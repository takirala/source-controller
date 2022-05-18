/*
Copyright 2020 The Flux authors

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

package libgit2

import (
	"context"
	"time"

	git2go "github.com/libgit2/git2go/v33"

	"github.com/fluxcd/source-controller/pkg/git"
)

var (
	now = time.Now
)

// This no longer requires args and probably can be moved somewhere within managed

// RemoteCallbacks constructs RemoteCallbacks with credentialsCallback and
// certificateCallback, and the given options if the given opts is not nil.
func RemoteCallbacks(ctx context.Context, opts *git.AuthOptions) git2go.RemoteCallbacks {

	// This may not be fully removed as without some of the callbacks git2go
	// gets anxious and panics.
	return git2go.RemoteCallbacks{

		CredentialsCallback:      credentialsCallback(),
		CertificateCheckCallback: certificateCallback(),
	}
}

// credentialsCallback constructs CredentialsCallbacks with the given options
// for git.Transport, and returns the result.
func credentialsCallback() git2go.CredentialsCallback {
	return func(url string, username string, allowedTypes git2go.CredentialType) (*git2go.Credential, error) {

		// If credential is nil, panic will ensue. We fake it as managed transport does not
		// require it.
		return git2go.NewCredentialUserpassPlaintext("", "")
	}
}

// certificateCallback constructs CertificateCallback with the given options
// for git.Transport if the given opts is not nil, and returns the result.
func certificateCallback() git2go.CertificateCheckCallback {
	// returning a nil func can cause git2go to panic.

	return func(cert *git2go.Certificate, valid bool, hostname string) error {
		return nil
	}
}
