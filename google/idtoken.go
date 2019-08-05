// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"
	"google.golang.org/api/iamcredentials/v1"
)

const (
	googleRootCertURL      = "https://www.googleapis.com/oauth2/v3/certs"
	metadataIdentityDocURL = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
)

var (
	verifier *oidc.IDTokenVerifier
)

// IdTokenConfig ...
type IdTokenConfig struct {
	Credentials *google.Credentials
	Audiences   []string
}

// IdTokenSource ..
func IdTokenSource(tokenConfig IdTokenConfig) (oauth2.TokenSource, error) {

	if tokenConfig.Credentials == nil || tokenConfig.Audiences == nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: IdTokenConfig.Credentials and cannot be nil")
	}

	return &idTokenSource{
		refreshMutex: &sync.Mutex{}, // guards impersonatedToken; held while fetching or updating it.
		credentials:  *tokenConfig.Credentials,
		audiences:    tokenConfig.Audiences,
	}, nil
}

type idTokenSource struct {
	refreshMutex *sync.Mutex   // guards impersonatedToken; held while fetching or updating it.
	idToken      *oauth2.Token // Token representing the impersonated identity.
	credentials  google.Credentials
	audiences    []string
}

// VerifyGoogleIDToken ...
func VerifyGoogleIDToken(ctx context.Context, token string, aud string) (*oidc.IDToken, error) {

	if verifier == nil {
		keySet := oidc.NewRemoteKeySet(ctx, googleRootCertURL)

		var config = &oidc.Config{
			ClientID: aud,
		}
		verifier = oidc.NewVerifier("https://accounts.google.com", keySet, config)
	}

	idt, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}
	return idt, nil
}

func (ts *idTokenSource) Token() (*oauth2.Token, error) {

	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	if ts.idToken.Valid() {
		return ts.idToken, nil
	}

	if len(ts.audiences) == 0 {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: Audience cannot be empty")
	}

	var idToken string

	switch ts.credentials.TokenSource.(type) {
	case *impersonatedTokenSource:
		its := ts.credentials.TokenSource.(*impersonatedTokenSource)
		client := oauth2.NewClient(context.TODO(), its.rootSource)
		service, err := iamcredentials.New(client)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: Error creating IAMCredentials: %v", err)
		}
		name := fmt.Sprintf("projects/-/serviceAccounts/%s", its.targetPrincipal)
		tokenRequest := &iamcredentials.GenerateIdTokenRequest{
			Audience:  ts.audiences[0],
			Delegates: its.delegates,
		}
		at, err := service.Projects.ServiceAccounts.GenerateIdToken(name, tokenRequest).Do()
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google:: Error calling iamcredentials.GenerateIdToken: %v", err)
		}
		idToken = at.Token

	default:
		tok, err := ts.credentials.TokenSource.Token()
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google:: Unable to derive token from Credentials: %v", err)
		}
		if ts.credentials.JSON != nil {
			fmt.Printf("Usign ServiceAccountJSON credential type")
			conf, err := google.JWTConfigFromJSON(ts.credentials.JSON, "")
			if err != nil {
				return nil, err
			}

			header := &jws.Header{
				Algorithm: "RS256",
				Typ:       "JWT",
				KeyID:     conf.PrivateKeyID,
			}

			privateClaims := map[string]interface{}{"target_audience": ts.audiences[0]}
			iat := time.Now()
			exp := iat.Add(time.Hour)

			payload := &jws.ClaimSet{
				Iss:           conf.Email,
				Iat:           iat.Unix(),
				Exp:           exp.Unix(),
				Aud:           "https://www.googleapis.com/oauth2/v4/token",
				PrivateClaims: privateClaims,
			}

			key := conf.PrivateKey
			block, _ := pem.Decode(key)
			if block != nil {
				key = block.Bytes
			}
			parsedKey, err := x509.ParsePKCS8PrivateKey(key)
			if err != nil {
				parsedKey, err = x509.ParsePKCS1PrivateKey(key)
				if err != nil {
					return nil, err
				}
			}
			parsed, ok := parsedKey.(*rsa.PrivateKey)
			if !ok {
				log.Fatal("private key is invalid")
			}

			token, err := jws.Encode(header, payload, parsed)
			if err != nil {
				return nil, err
			}

			d := url.Values{}
			d.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
			d.Add("assertion", token)

			client := &http.Client{}
			req, err := http.NewRequest("POST", "https://www.googleapis.com/oauth2/v4/token", strings.NewReader(d.Encode()))
			if err != nil {
				return nil, err
			}
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}

			var y map[string]interface{}
			err = json.Unmarshal([]byte(body), &y)
			if err != nil {
				return nil, err
			}

			idToken = y["id_token"].(string)
		} else if tok.RefreshToken == "" {
			client := &http.Client{}
			req, err := http.NewRequest("GET", metadataIdentityDocURL+"?audience="+ts.audiences[0], nil)
			req.Header.Add("Metadata-Flavor", "Google")
			resp, err := client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("salrashid123/x/oauth2/google:: Unable to get Id  Token from Metadata server: %v", err)
			}
			defer resp.Body.Close()

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("salrashid123/x/oauth2/google::  Unable to parse Id  Token from Metadata server:: %v", err)
			}
			idToken = string(bodyBytes)
		} else {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: Unsupported Credential Type supplied: got %v", reflect.TypeOf(ts.credentials.TokenSource))
		}
	}

	idt, err := VerifyGoogleIDToken(context.Background(), idToken, ts.audiences[0])
	if err != nil {
		log.Fatalf("salrashid123/x/oauth2/google: Unable to verify OIDC token %v", err)
	}

	expireAt := idt.Expiry
	if err != nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: Error parsing ExpireTime from iamcredentials: %v", err)
	}

	ts.idToken = &oauth2.Token{
		AccessToken: idToken,
		Expiry:      expireAt,
	}

	return ts.idToken, nil
}
