// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
)

type osTSTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type osTSHeaders struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}
type osTSOptions struct {
	Headers []osTSHeaders `json:"headers"`
	Method  string        `json:"method,omitempty"`
	URL     string        `json:"url,omitempty"`
}

type OIDCFederatedTokenConfig struct {
	SourceToken          string
	Scope                string
	TargetResource       string
	TargetServiceAccount string
	UseIAMToken          bool
}

type oidciamGenerateAccessTokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}

const (
	GCP_OIDC_STS_ENDPOINT         = "https://sts.googleapis.com/v1beta/token"
	GCP_OIDC_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
)

// OIDCSourceTokenSource exchanges AWS credentials for GCP credentials
//
// Use this TokenSource to access GCP resources while using Arbitrary OIDC provider's token

func OIDCFederatedTokenSource(tokenConfig *OIDCFederatedTokenConfig) (oauth2.TokenSource, error) {

	if &tokenConfig.SourceToken == nil {
		return nil, fmt.Errorf("oauth2/google: Source OIDC Token cannot be nil")
	}

	if tokenConfig.Scope == "" {
		tokenConfig.Scope = GCP_OIDC_CLOUD_PLATFORM_SCOPE
	}
	return &oidcFederatedTokenSource{
		refreshMutex:         &sync.Mutex{},
		rootSource:           tokenConfig.SourceToken,
		scope:                tokenConfig.Scope,
		targetResource:       tokenConfig.TargetResource,
		targetServiceAccount: tokenConfig.TargetServiceAccount,
		useIAMToken:          tokenConfig.UseIAMToken,
	}, nil
}

type oidcFederatedTokenSource struct {
	refreshMutex         *sync.Mutex
	scope                string
	targetResource       string
	rootSource           string
	targetTokenSource    *oauth2.Token
	targetServiceAccount string
	useIAMToken          bool
}

func (ts *oidcFederatedTokenSource) Token() (*oauth2.Token, error) {
	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	if ts.targetTokenSource.Valid() {
		return ts.targetTokenSource, nil
	} else {
		c, _, err := new(jwt.Parser).ParseUnverified(ts.rootSource, jwt.MapClaims{})
		if err != nil {
			return nil, fmt.Errorf("input RootSource not JWT %v", err)
		}
		claims, ok := c.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("Could not parse JWT to standard claims %v", err)
		}
		err = claims.Valid()
		if err != nil {
			return nil, fmt.Errorf("Error Refreshing root JWT:  %v", err)
		}
	}

	form := url.Values{}
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Add("audience", ts.targetResource)
	form.Add("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
	form.Add("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Add("scope", ts.scope)
	form.Add("subject_token", ts.rootSource)

	gcpSTSResp, err := http.PostForm(GCP_OIDC_STS_ENDPOINT, form)
	defer gcpSTSResp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Error exchaning token for GCP STS %v", err)
	}

	if gcpSTSResp.StatusCode != http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(gcpSTSResp.Body)
		return nil, fmt.Errorf("Unable to exchange token %s,  %v", string(bodyBytes), err)
	}
	tresp := &osTSTokenResponse{}
	err = json.NewDecoder(gcpSTSResp.Body).Decode(tresp)
	if err != nil {
		return nil, fmt.Errorf("Error Decoding GCP STS TokenResponse %v", err)
	}

	ts.targetTokenSource = &oauth2.Token{
		AccessToken: tresp.AccessToken,
		TokenType:   tresp.TokenType,
		Expiry:      time.Now().Add(time.Duration(tresp.ExpiresIn)),
	}

	if !ts.useIAMToken {
		return ts.targetTokenSource, nil
	}

	iamEndpoint := fmt.Sprintf("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken", ts.targetServiceAccount)

	var jsonStr = []byte(fmt.Sprintf(`{"scope": ["%s"] }`, ts.scope))
	req, err := http.NewRequest(http.MethodPost, iamEndpoint, bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, fmt.Errorf("Error invoking IAM Credentials API %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.targetTokenSource.AccessToken))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	ttresp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error invoking IAM Credentials API %v", err)
	}
	defer ttresp.Body.Close()

	if ttresp.StatusCode != http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(ttresp.Body)
		return nil, fmt.Errorf("Error invoking IAM Credentials API: [%s] \n %v", string(bodyBytes), err)
	}

	target := &oidciamGenerateAccessTokenResponse{}

	json.NewDecoder(ttresp.Body).Decode(target)

	expireAt, err := time.Parse(time.RFC3339, target.ExpireTime)
	if err != nil {
		return nil, fmt.Errorf("oauth2/google: Error parsing ExpireTime from iamcredentials: %v", err)
	}

	return &oauth2.Token{
		AccessToken: target.AccessToken,
		TokenType:   "Bearer",
		Expiry:      expireAt,
	}, nil

}
