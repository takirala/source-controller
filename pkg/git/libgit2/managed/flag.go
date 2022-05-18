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

package managed

// Enabled defines whether the use of Managed Transport should be enabled.
// This is only affects git operations that uses libgit2 implementation.
//
// True is returned when the environment variable `EXPERIMENTAL_GIT_TRANSPORT`
// is detected with the value of `true` or `1`.
func Enabled() bool {
	// if v, ok := os.LookupEnv("EXPERIMENTAL_GIT_TRANSPORT"); ok {
	// 	return strings.ToLower(v) == "true" || v == "1"
	// }
	// return false

	// this are throw away changes to be overriden by
	// https://github.com/fluxcd/source-controller/pull/718
	return true
}
