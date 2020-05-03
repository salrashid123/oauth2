// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

type ExternalTokenConfig struct {
	Env     []string
	Command string
	Args    []string
	Format interface{}
}

//https://github.com/golang/oauth2/blob/master/internal/token.go#L33
type externalTokenResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type,omitempty"`
	ExpiresIn int    `json:"expires_in,omitempty"`
}

const ()

// ExternalTokenSource acquires tokens by running out-of process binaries or scripts.
//
// The external binary that this tokensource executes _must_ return a json formmatted response
// that includes the token (which maybe either an access or id_token).
// Specifically, the out of process script must return the following JSON:
//
//  For more information, see:  https://github.com/salrashid123/downscoped_token
//		type externalTokenResponse struct {
//			Token     string `json:"token"`
//			TokenType string `json:"token_type,omitempty"`
//			ExpiresIn int    `json:"expires_in,omitempty"`
//		}
//
//  Sample Usage
//
//
//		extTokenSource, err := sal.ExternalTokenSource(
//			&sal.ExternalTokenConfig{
//				Command: "/usr/bin/echo",
//				Env:     []string{"foo=bar"},
//				//Args:    []string{"$ENV_TOKEN"},
//				Args: []string{os.ExpandEnv("$ENV_TOKEN")},
//			},
//		)
//		extTokenSource, err := sal.ExternalTokenSource(
//			&sal.ExternalTokenConfig{
//				Command: "/usr/bin/cat",
//				Env:     []string{"foo=bar"},
//				Args:    []string{"file_token.json"},
//			},
//		)
//		extTokenSource, err := sal.ExternalTokenSource(
//			&sal.ExternalTokenConfig{
//				Command: "/usr/bin/curl",
//				Env:     []string{"foo=bar"},
//				Args:    []string{"-s", "https://server.dom/path/to/file_token.json"},
//			},
//		)
//
// References:
//   https://kubernetes.io/docs/reference/access-authn-authz/authentication/#configuration
//   https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html

func ExternalTokenSource(tokenConfig *ExternalTokenConfig) (oauth2.TokenSource, error) {

	if tokenConfig.Command == "" {
		return nil, fmt.Errorf("oauth2/google: Command cannot be nil")
	}

	return &externalTokenSource{
		refreshMutex:  &sync.Mutex{},
		externalToken: nil,
		env:           tokenConfig.Env,
		command:       tokenConfig.Command,
		args:          tokenConfig.Args,
		format:        tokenConfig.Format,
	}, nil
}

type externalTokenSource struct {
	refreshMutex  *sync.Mutex
	externalToken *oauth2.Token
	env           []string
	command       string
	args          []string
	format        interface{}
}

func (ts *externalTokenSource) Token() (*oauth2.Token, error) {

	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	if ts.externalToken.Valid() {
		return ts.externalToken, nil
	}

	cmd := exec.Command(ts.command, ts.args...)
	cmd.Env = append(os.Environ(), ts.env...)

	stdout := &bytes.Buffer{}
	cmd.Stdout = stdout
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("Unable to run command value to int %v", err)
	}

	resp := &externalTokenResponse{}
	err = json.Unmarshal(stdout.Bytes(), resp)
	if err != nil {
		return nil, err
	} else {
		return &oauth2.Token{
			AccessToken: resp.Token,
			TokenType:   resp.TokenType,
			Expiry:      time.Now().Add(time.Duration(resp.ExpiresIn)),
		}, nil
	}

}
