// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"
	"google.golang.org/api/iamcredentials/v1"
)

// ImpersonatedTokenConfig prameters to start Credential impersonation exchange.
type ImpersonatedTokenConfig struct {
	RootTokenSource oauth2.TokenSource
	TargetPrincipal string
	Lifetime        time.Duration
	Delegates       []string
	TargetScopes    []string
	Subject         string
}

// ImpersonatedTokenSource returns a TokenSource issued to a user or
// service account to impersonate another. The source project using
// ImpersonatedTokenSource must enable the "IAMCredentials" API.  Also, the
// target service account must grant the orginating principal the
// "Service Account Token Creator" IAM role:
// https://cloud.google.com/iam/docs/service-accounts#the_service_account_token_creator_role
//
//  rootSource (TokenSource): The root TokenSource
//     used as to acquire the target identity TokenSource.
//     rootSource *must* include scopes that contains
//     "https://www.googleapis.com/auth/iam"
//     or
//     "https://www.googleapis.com/auth/cloud.platform"
//  targetPrincipal (string): The service account to impersonate.
//  targetScopes ([]string): Scopes to request during the
//     authorization grant.
//  delegates ([]string): The chained list of delegates required
//     to grant the final access_token. If set, the sequence of
//     identities must have "Service Account Token Creator" capability
//     granted to the preceeding identity. For example, if set to
//     [serviceAccountB, serviceAccountC], the source_credential
//     must have the Token Creator role on serviceAccountB.
//     serviceAccountB must have the Token Creator on serviceAccountC.
//     Finally, C must have Token Creator on target_principal.
//     If left unset, source_credential must have that role on
//     target_principal.
//  lifetime (time.Duration): Number of seconds the impersonated credential should
//     be valid for (up to 3600).
//  subject (string): Subject fieild used for Gsuites Domain Wide Delegation.
//     Specify this field ONLY if you wish to use Google GSuites Admin SDK and utilize
//     domain wide delegation with impersonated credentials.
//     https://developers.google.com/admin-sdk/directory/v1/guides/delegation
//
// Note that this is not a standard OAuth flow, but rather uses Google Cloud
// IAMCredentials API to exchange one oauth token for an impersonated account
// see: https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/generateAccessToken
func ImpersonatedTokenSource(tokenConfig *ImpersonatedTokenConfig) (oauth2.TokenSource, error) {

	if tokenConfig.RootTokenSource == nil {
		return nil, fmt.Errorf("oauth2/google: rootSource cannot be nil")
	}

	return &impersonatedTokenSource{
		refreshMutex:      &sync.Mutex{}, // guards impersonatedToken; held while fetching or updating it.
		impersonatedToken: nil,           // Token representing the impersonated identity. Initially nil.

		rootSource:      tokenConfig.RootTokenSource,
		targetPrincipal: tokenConfig.TargetPrincipal,
		lifetime:        tokenConfig.Lifetime,
		delegates:       tokenConfig.Delegates,
		targetScopes:    tokenConfig.TargetScopes,
		subject:         tokenConfig.Subject,
	}, nil
}

type impersonatedTokenSource struct {
	refreshMutex      *sync.Mutex   // guards impersonatedToken; held while fetching or updating it.
	impersonatedToken *oauth2.Token // Token representing the impersonated identity.

	rootSource      oauth2.TokenSource
	targetPrincipal string
	lifetime        time.Duration
	delegates       []string
	targetScopes    []string
	subject         string
}

func (ts *impersonatedTokenSource) Token() (*oauth2.Token, error) {

	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	if ts.impersonatedToken.Valid() {
		return ts.impersonatedToken, nil
	}
	client := oauth2.NewClient(context.TODO(), ts.rootSource)

	service, err := iamcredentials.New(client)
	if err != nil {
		return nil, fmt.Errorf("oauth2/google: Error creating IAMCredentials: %v", err)
	}
	name := fmt.Sprintf("projects/-/serviceAccounts/%s", ts.targetPrincipal)

	var accessToken string
	var expireAt time.Time
	if ts.subject == "" {
		tokenRequest := &iamcredentials.GenerateAccessTokenRequest{
			Lifetime:  fmt.Sprintf("%ds", int(ts.lifetime.Seconds())),
			Delegates: ts.delegates,
			Scope:     ts.targetScopes,
		}
		at, err := service.Projects.ServiceAccounts.GenerateAccessToken(name, tokenRequest).Do()
		if err != nil {
			return nil, fmt.Errorf("oauth2/google: Error calling iamcredentials.GenerateAccessToken: %v", err)
		}
		accessToken = at.AccessToken
		expireAt, err = time.Parse(time.RFC3339, at.ExpireTime)
		if err != nil {
			return nil, fmt.Errorf("oauth2/google: Error parsing ExpireTime from iamcredentials: %v", err)
		}
	} else {
		// Domain-Wide Delgation token
		// ref: https://github.com/googleapis/google-api-go-client/issues/379#issuecomment-514806450
		// ref: https://gist.github.com/julianvmodesto/ed73201703dac8a047ec35a24dce4524
		var iat = time.Now()
		var exp = iat.Add(time.Hour)
		var claims = &jws.ClaimSet{
			Iss:   ts.targetPrincipal,
			Scope: strings.Join(ts.targetScopes, " "),
			Sub:   ts.subject,
			Aud:   google.JWTTokenURL,
			Iat:   iat.Unix(),
			Exp:   exp.Unix(),
		}
		b, err := json.Marshal(claims)
		if err != nil {
			return nil, err
		}
		var signJwtRequest = &iamcredentials.SignJwtRequest{
			Delegates: []string{name},
			Payload:   string(b),
		}
		jwt, err := service.Projects.ServiceAccounts.SignJwt(name, signJwtRequest).Do()
		if err != nil {
			return nil, fmt.Errorf("error retrieving short-lived iamcredentials token: %v", err)
		}
		ctx := context.Background()
		var hc = oauth2.NewClient(ctx, nil)
		var v = url.Values{}
		v.Set("grant_type", "assertion")
		v.Set("assertion_type", "http://oauth.net/grant_type/jwt/1.0/bearer")
		v.Set("assertion", jwt.SignedJwt)
		resp, err := hc.PostForm(google.JWTTokenURL, v)
		if err != nil {
			return nil, fmt.Errorf("oauth2: cannot exchange jwt for access token: %v", err)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("oauth2: cannot exchange jwt for access token: %v", err)
		}
		if c := resp.StatusCode; c != http.StatusOK {
			return nil, &oauth2.RetrieveError{
				Response: resp,
				Body:     body,
			}
		}
		var tokenRes struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			IDToken     string `json:"id_token"`
			ExpiresIn   int64  `json:"expires_in"`
		}

		if err := json.Unmarshal(body, &tokenRes); err != nil {
			return nil, fmt.Errorf("oauth2: cannot exchange jwt for access token: %v", err)
		}

		accessToken = tokenRes.AccessToken
		now := time.Now()
		now.Add(time.Second * time.Duration(tokenRes.ExpiresIn))
		expireAt = now
		if err != nil {
			return nil, fmt.Errorf("oauth2/google: Error parsing ExpireTime from iamcredentials: %v", err)
		}

	}

	ts.impersonatedToken = &oauth2.Token{
		AccessToken: accessToken,
		Expiry:      expireAt,
	}

	return ts.impersonatedToken, nil
}
