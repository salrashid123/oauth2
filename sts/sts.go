// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// https://www.rfc-editor.org/rfc/rfc8693.html#section-2.2.1
type rTSTokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type,omitempty"`
	ExpiresIn       int64  `json:"expires_in,omitempty"`
	Scope           string `json:"scope,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
}

type STSTokenConfig struct {
	TokenExchangeServiceURI string
	Resource                string
	Audience                string
	Scope                   string
	SubjectTokenSource      oauth2.TokenSource
	SubjectTokenType        string
	RequestedTokenType      string
	TLSConfig               tls.Config
}

const ()

/*
	STSTokenSource basically exchanges an arbitrary token (which maybe anything, any token, not necessarily google)
	for another token through an intermediary STS server.

	You can find more
*/
func STSTokenSource(tokenConfig *STSTokenConfig) (oauth2.TokenSource, error) {

	if tokenConfig.SubjectTokenSource == nil {
		return nil, fmt.Errorf("oauth2/google: Command cannot be nil")
	}

	return &stsTokenSource{
		refreshMutex:            &sync.Mutex{},
		stsToken:                nil,
		tokenExchangeServiceURI: tokenConfig.TokenExchangeServiceURI,
		audience:                tokenConfig.Audience,

		scope:              tokenConfig.Scope,
		subjectTokenSource: tokenConfig.SubjectTokenSource,

		subjectTokenType:   tokenConfig.SubjectTokenType,
		requestedTokenType: tokenConfig.RequestedTokenType,
		tlsConfig:          &tokenConfig.TLSConfig,
	}, nil
}

type stsTokenSource struct {
	refreshMutex            *sync.Mutex
	stsToken                *oauth2.Token
	tokenExchangeServiceURI string
	audience                string
	scope                   string

	subjectTokenSource oauth2.TokenSource
	subjectTokenType   string
	requestedTokenType string
	tlsConfig          *tls.Config
}

func (ts *stsTokenSource) Token() (*oauth2.Token, error) {

	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	if ts.stsToken.Valid() {
		return ts.stsToken, nil
	}

	sourceTok, err := ts.subjectTokenSource.Token()
	if err != nil {
		return &oauth2.Token{}, err
	}

	form := url.Values{}
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Add("audience", ts.audience)
	form.Add("subject_token_type", ts.subjectTokenType)
	form.Add("requested_token_type", ts.requestedTokenType)
	form.Add("scope", ts.scope)
	form.Add("subject_token", sourceTok.AccessToken)
	// fmt.Println(string(e))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: ts.tlsConfig,
		},
	}

	gcpSTSResp, err := client.PostForm(ts.tokenExchangeServiceURI, form)
	defer gcpSTSResp.Body.Close()
	if err != nil {
		return &oauth2.Token{}, fmt.Errorf("Error exchaning token for GCP STS %v", err)
	}
	if gcpSTSResp.StatusCode != http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(gcpSTSResp.Body)
		return &oauth2.Token{}, fmt.Errorf("Unable to exchange token %s,  %v", string(bodyBytes), err)
	}
	tresp := &rTSTokenResponse{}
	err = json.NewDecoder(gcpSTSResp.Body).Decode(tresp)
	if err != nil {
		return &oauth2.Token{}, fmt.Errorf("Error Decoding GCP STS TokenResponse %v", err)
	}

	ts.stsToken = &oauth2.Token{
		AccessToken: tresp.AccessToken,
		Expiry:      time.Now().Add(time.Duration(tresp.ExpiresIn)),
	}

	return &oauth2.Token{
		AccessToken: ts.stsToken.AccessToken,
		TokenType:   "Bearer",
		Expiry:      ts.stsToken.Expiry,
	}, nil

}
