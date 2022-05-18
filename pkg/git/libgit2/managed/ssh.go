/*
Copyright 2022 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
This was inspired and contains part of:
https://github.com/libgit2/git2go/blob/eae00773cce87d5282a8ac7c10b5c1961ee6f9cb/ssh.go

The MIT License

Copyright (c) 2013 The git2go contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package managed

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net"
	"net/url"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/net/proxy"

	"github.com/fluxcd/source-controller/pkg/git"
	git2go "github.com/libgit2/git2go/v33"
)

// registerManagedSSH registers a Go-native implementation of
// SSH transport that doesn't rely on any lower-level libraries
// such as libssh2.
func registerManagedSSH() error {
	for _, protocol := range []string{"ssh", "ssh+git", "git+ssh"} {
		_, err := git2go.NewRegisteredSmartTransport(protocol, false, sshSmartSubtransportFactory)
		if err != nil {
			return fmt.Errorf("failed to register transport for %q: %v", protocol, err)
		}
	}
	return nil
}

func sshSmartSubtransportFactory(remote *git2go.Remote, transport *git2go.Transport) (git2go.SmartSubtransport, error) {
	return &sshSmartSubtransport{
		transport: transport,
	}, nil
}

type sshSmartSubtransport struct {
	transport *git2go.Transport

	lastAction    git2go.SmartServiceAction
	conn          net.Conn
	client        *ssh.Client
	session       *ssh.Session
	stdin         io.WriteCloser
	stdout        io.Reader
	currentStream *sshSmartSubtransportStream
	addr          string
	connected     bool
}

func (t *sshSmartSubtransport) Action(urlString string, action git2go.SmartServiceAction) (git2go.SmartSubtransportStream, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	finalUrl := urlString
	opts, found := transportOptions(urlString)
	var authOpts *git.AuthOptions

	if found {
		if opts.TargetURL != "" {
			// override target URL only if options are found and a new targetURL
			// is provided.
			finalUrl = opts.TargetURL
		}

		authOpts = opts.AuthOpts
	}

	u, err := url.Parse(finalUrl)
	if err != nil {
		return nil, err
	}

	if len(u.Path) > PathMaxLength {
		return nil, fmt.Errorf("path exceeds the max length (%d)", PathMaxLength)
	}

	// decode URI's path
	uPath, err := url.PathUnescape(u.Path)
	if err != nil {
		return nil, err
	}

	// Escape \ and '.
	uPath = strings.Replace(uPath, `\`, `\\`, -1)
	uPath = strings.Replace(uPath, `'`, `\'`, -1)

	var cmd string
	switch action {
	case git2go.SmartServiceActionUploadpackLs, git2go.SmartServiceActionUploadpack:
		if t.currentStream != nil {
			if t.lastAction == git2go.SmartServiceActionUploadpackLs {
				return t.currentStream, nil
			}
		}
		cmd = fmt.Sprintf("git-upload-pack '%s'", uPath)

	case git2go.SmartServiceActionReceivepackLs, git2go.SmartServiceActionReceivepack:
		if t.currentStream != nil {
			if t.lastAction == git2go.SmartServiceActionReceivepackLs {
				return t.currentStream, nil
			}
		}
		cmd = fmt.Sprintf("git-receive-pack '%s'", uPath)

	default:
		return nil, fmt.Errorf("unexpected action: %v", action)
	}

	if t.connected {
		// Disregard errors from previous stream, futher details inside Close().
		_ = t.Close()
	}

	port := "22"
	if u.Port() != "" {
		port = u.Port()
	}
	t.addr = net.JoinHostPort(u.Hostname(), port)

	sshConfig, err := clientConfig(t.addr, authOpts)
	if err != nil {
		return nil, err
	}

	sshConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		marshaledKey := key.Marshal()
		// There is no point on hashing the key multiple times and
		// there is no need to support anything but sha256.
		// This entire logic could become git2go agnostic.
		cert := &git2go.Certificate{
			Kind: git2go.CertificateHostkey,
			Hostkey: git2go.HostkeyCertificate{
				Kind:         git2go.HostkeySHA256,
				HashSHA256:   sha256.Sum256(marshaledKey),
				Hostkey:      marshaledKey,
				SSHPublicKey: key,
			},
		}
		return knownHostsCallback(hostname, authOpts.KnownHosts)(cert, true, hostname)
	}

	err = t.createConn(t.addr, sshConfig)
	if err != nil {
		return nil, err
	}
	t.connected = true

	traceLog.Info("[ssh]: creating new ssh session")
	if t.session, err = t.client.NewSession(); err != nil {
		return nil, err
	}

	if t.stdin, err = t.session.StdinPipe(); err != nil {
		return nil, err
	}

	var w *io.PipeWriter
	var reader io.Reader
	t.stdout, w = io.Pipe()
	if reader, err = t.session.StdoutPipe(); err != nil {
		return nil, err
	}

	// If the session's stdout pipe is not serviced fast
	// enough it may cause the remote command to block.
	//
	// xref: https://github.com/golang/crypto/blob/eb4f295cb31f7fb5d52810411604a2638c9b19a2/ssh/session.go#L553-L558
	go func() error {
		defer w.Close()
		for {
			if !t.connected {
				return nil
			}

			_, err := io.Copy(w, reader)
			if err != nil {
				return err
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	traceLog.Info("[ssh]: run on remote", "cmd", cmd)
	if err := t.session.Start(cmd); err != nil {
		return nil, err
	}

	t.lastAction = action
	t.currentStream = &sshSmartSubtransportStream{
		owner: t,
	}

	return t.currentStream, nil
}

func (t *sshSmartSubtransport) createConn(addr string, sshConfig *ssh.ClientConfig) error {
	ctx, cancel := context.WithTimeout(context.TODO(), sshConnectionTimeOut)
	defer cancel()

	conn, err := proxy.Dial(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		return err
	}

	t.conn = conn
	t.client = ssh.NewClient(c, chans, reqs)

	return nil
}

// Close closes the smart subtransport.
//
// This is called internally ahead of a new action, and also
// upstream by the transport handler:
// https://github.com/libgit2/git2go/blob/0e8009f00a65034d196c67b1cdd82af6f12c34d3/transport.go#L409
//
// Avoid returning errors, but focus on releasing anything that
// may impair the transport to have successful actions on a new
// SmartSubTransport (i.e. unreleased resources, staled connections).
func (t *sshSmartSubtransport) Close() error {
	traceLog.Info("[ssh]: sshSmartSubtransport.Close()", "server", t.addr)
	t.currentStream = nil
	if t.client != nil && t.stdin != nil {
		_ = t.stdin.Close()
	}
	t.client = nil

	if t.session != nil {
		traceLog.Info("[ssh]: session.Close()", "server", t.addr)
		_ = t.session.Close()
	}
	t.session = nil

	return nil
}

func (t *sshSmartSubtransport) Free() {
	traceLog.Info("[ssh]: sshSmartSubtransport.Free()")
	if t.client != nil {
		_ = t.client.Close()
	}

	if t.conn != nil {
		_ = t.conn.Close()
	}
	t.connected = false
}

type sshSmartSubtransportStream struct {
	owner *sshSmartSubtransport
}

func (stream *sshSmartSubtransportStream) Read(buf []byte) (int, error) {
	return stream.owner.stdout.Read(buf)
}

func (stream *sshSmartSubtransportStream) Write(buf []byte) (int, error) {
	return stream.owner.stdin.Write(buf)
}

func (stream *sshSmartSubtransportStream) Free() {
	traceLog.Info("[ssh]: sshSmartSubtransportStream.Free()")
}

func clientConfig(remoteAddress string, cred *git.AuthOptions) (*ssh.ClientConfig, error) {
	if cred == nil {
		return nil, fmt.Errorf("cannot create ssh client config from a nil credential")
	}

	var key ssh.Signer
	var err error
	if cred.Password != "" {
		key, err = ssh.ParsePrivateKeyWithPassphrase(cred.Identity, []byte(cred.Password))
	} else {
		key, err = ssh.ParsePrivateKey(cred.Identity)
	}

	if err != nil {
		return nil, err
	}

	cfg := &ssh.ClientConfig{
		User:    cred.Username,
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(key)},
		Timeout: sshConnectionTimeOut,
	}
	if len(git.KexAlgos) > 0 {
		cfg.Config.KeyExchanges = git.KexAlgos
	}
	if len(git.HostKeyAlgos) > 0 {
		cfg.HostKeyAlgorithms = git.HostKeyAlgos
	}

	return cfg, nil
}

/// Below comes from libgit2.Transport, and should be moved into fluxcd/pkg/ssh

// knownHostCallback returns a CertificateCheckCallback that verifies
// the key of Git server against the given host and known_hosts for
// git.SSH Transports.
func knownHostsCallback(host string, knownHosts []byte) git2go.CertificateCheckCallback {
	return func(cert *git2go.Certificate, valid bool, hostname string) error {
		kh, err := parseKnownHosts(string(knownHosts))
		if err != nil {
			return fmt.Errorf("failed to parse known_hosts: %w", err)
		}

		// First, attempt to split the configured host and port to validate
		// the port-less hostname given to the callback.
		hostWithoutPort, _, err := net.SplitHostPort(host)
		if err != nil {
			// SplitHostPort returns an error if the host is missing
			// a port, assume the host has no port.
			hostWithoutPort = host
		}

		// Different versions of libgit handle this differently.
		// This fixes the case in which ports may be sent back.
		hostnameWithoutPort, _, err := net.SplitHostPort(hostname)
		if err != nil {
			hostnameWithoutPort = hostname
		}

		if hostnameWithoutPort != hostWithoutPort {
			return fmt.Errorf("host mismatch: %q %q", hostWithoutPort, hostnameWithoutPort)
		}

		// We are now certain that the configured host and the hostname
		// given to the callback match. Use the configured host (that
		// includes the port), and normalize it, so we can check if there
		// is an entry for the hostname _and_ port.
		h := knownhosts.Normalize(host)
		for _, k := range kh {
			if k.matches(h, cert.Hostkey) {
				return nil
			}
		}
		return fmt.Errorf("hostkey could not be verified")
	}
}

type knownKey struct {
	hosts []string
	key   ssh.PublicKey
}

func parseKnownHosts(s string) ([]knownKey, error) {
	var knownHosts []knownKey
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		_, hosts, pubKey, _, _, err := ssh.ParseKnownHosts(scanner.Bytes())
		if err != nil {
			// Lines that aren't host public key result in EOF, like a comment
			// line. Continue parsing the other lines.
			if err == io.EOF {
				continue
			}
			return []knownKey{}, err
		}

		knownHost := knownKey{
			hosts: hosts,
			key:   pubKey,
		}
		knownHosts = append(knownHosts, knownHost)
	}

	if err := scanner.Err(); err != nil {
		return []knownKey{}, err
	}

	return knownHosts, nil
}

func (k knownKey) matches(host string, hostkey git2go.HostkeyCertificate) bool {
	if !containsHost(k.hosts, host) {
		return false
	}

	var fingerprint []byte
	var hasher hash.Hash

	//DEPRECATE insecure algos MD5/SHA1
	switch {
	case hostkey.Kind&git2go.HostkeySHA256 > 0:
		fingerprint = hostkey.HashSHA256[:]
		hasher = sha256.New()
	case hostkey.Kind&git2go.HostkeySHA1 > 0:
		fingerprint = hostkey.HashSHA1[:]
		hasher = sha1.New()
	case hostkey.Kind&git2go.HostkeyMD5 > 0:
		fingerprint = hostkey.HashMD5[:]
		hasher = md5.New()
	default:
		return false
	}
	hasher.Write(k.key.Marshal())
	return bytes.Equal(hasher.Sum(nil), fingerprint)
}

func containsHost(hosts []string, host string) bool {
	for _, kh := range hosts {
		// hashed host must start with a pipe
		if kh[0] == '|' {
			match, _ := MatchHashedHost(kh, host)
			if match {
				return true
			}

		} else if kh == host { // unhashed host check
			return true
		}
	}
	return false
}

// MatchHashedHost tries to match a hashed known host (kh) to
// host.
//
// Note that host is not hashed, but it is rather hashed during
// the matching process using the same salt used when hashing
// the known host.
func MatchHashedHost(kh, host string) (bool, error) {
	if kh == "" || kh[0] != '|' {
		return false, fmt.Errorf("hashed known host must begin with '|': '%s'", kh)
	}

	components := strings.Split(kh, "|")
	if len(components) != 4 {
		return false, fmt.Errorf("invalid format for hashed known host: '%s'", kh)
	}

	if components[1] != "1" {
		return false, fmt.Errorf("unsupported hash type '%s'", components[1])
	}

	hkSalt, err := base64.StdEncoding.DecodeString(components[2])
	if err != nil {
		return false, fmt.Errorf("cannot decode hashed known host: '%w'", err)
	}

	hkHash, err := base64.StdEncoding.DecodeString(components[3])
	if err != nil {
		return false, fmt.Errorf("cannot decode hashed known host: '%w'", err)
	}

	mac := hmac.New(sha1.New, hkSalt)
	mac.Write([]byte(host))
	hostHash := mac.Sum(nil)

	return bytes.Equal(hostHash, hkHash), nil
}
