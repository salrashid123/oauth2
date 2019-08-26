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
	"google.golang.org/grpc/credentials"
)

const (
	googleRootCertURL      = "https://www.googleapis.com/oauth2/v3/certs"
	metadataIdentityDocURL = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
)

var (
	verifier *oidc.IDTokenVerifier
)

// IdTokeConfig parameters to initialize IdTokenSource
//    Audience and Credential fields are both required.
type IdTokenConfig struct {
	Credentials *google.Credentials
	Audiences   []string
}

// IdTokenSource returns a TokenSource which returns a GoogleOIDC token
//
//  tokenConfig (IdTokenConfig): The root Credential object which will
//      be used to generate the IDToken.
// https://medium.com/google-cloud/authenticating-using-google-openid-connect-tokens-e7675051213b
func IdTokenSource(tokenConfig IdTokenConfig) (oauth2.TokenSource, error) {

	if tokenConfig.Credentials == nil || tokenConfig.Audiences == nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: IdTokenConfig.Credentials and Audience and cannot be nil")
	}

	return &idTokenSource{
		refreshMutex: &sync.Mutex{}, // guards impersonatedToken; held while fetching or updating it.
		credentials:  *tokenConfig.Credentials,
		audiences:    tokenConfig.Audiences,
	}, nil
}

type idTokenSource struct {
	refreshMutex *sync.Mutex   // guards idToken; held while fetching or updating it.
	idToken      *oauth2.Token // Token representing source identity.
	credentials  google.Credentials
	audiences    []string
}

// VerifyGoogleIDToken verifies the IdToken for expiration, signature against Google's certificates
//    and the audience it should be issued to
//    returns false if unverified
//    TODO: return struct to allow inspection of the actual claims, not just true/false of the
//          signature+expiration+audience
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
		return nil, fmt.Errorf("salrashid123/oauth2/google: Audience cannot be empty")
	}

	_, err := url.ParseRequestURI(ts.audiences[0])
	if err != nil {
		return nil, fmt.Errorf("salrashid123/oauth2/google: Audience must be valid URL")
	}

	var idToken string

	// first check if the provided token is impersonated
	switch ts.credentials.TokenSource.(type) {
	case *impersonatedTokenSource:
		its := ts.credentials.TokenSource.(*impersonatedTokenSource)
		client := oauth2.NewClient(context.TODO(), its.rootSource)
		service, err := iamcredentials.New(client)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/oauth2/google: Error creating IAMCredentials: %v", err)
		}
		name := fmt.Sprintf("projects/-/serviceAccounts/%s", its.targetPrincipal)
		tokenRequest := &iamcredentials.GenerateIdTokenRequest{
			Audience:  ts.audiences[0],
			Delegates: its.delegates,
		}
		at, err := service.Projects.ServiceAccounts.GenerateIdToken(name, tokenRequest).Do()
		if err != nil {
			return nil, fmt.Errorf("salrashid123/oauth2/google:: Error calling iamcredentials.GenerateIdToken: %v", err)
		}
		idToken = at.Token

	// TODO: once merged to googe/oauth2, use *oauth2.reuseTokenSource (can't use it now since its not exported outside)
	//  https://github.com/golang/oauth2/blob/master/oauth2.go#L288
	default:
		// if not, the its either UserCredentials, ComputeCredentials or ServiceAccount, either way, it should have
		// and existing Token()
		tok, err := ts.credentials.TokenSource.Token()
		if err != nil {
			return nil, fmt.Errorf("salrashid123/oauth2/google:: Unable to derive token from Credentials: %v", err)
		}
		// Attempt to parse the JSON file as a service account creds; otherwise, its a usercredential file from gcloud CLI
		if ts.credentials.JSON != nil {
			conf, err := google.JWTConfigFromJSON(ts.credentials.JSON, "")
			if err != nil {
				return nil, fmt.Errorf("salrashid123/oauth2/google:: JSON Credential cannot be parsed.  Initialize ServiceAccount Credentials instead: %v", err)
			}

			// now construct the JWT to exchange
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

			// sign it with the private key inside the JSON file
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

			// do the exchange
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

			// extract the id_token from the response
			var y map[string]interface{}
			err = json.Unmarshal([]byte(body), &y)
			if err != nil {
				return nil, err
			}

			idToken = y["id_token"].(string)

		} else if tok.RefreshToken == "" {
			// if the token isn't a json cert or usercreds file, it should be a ReuseTokenSource from MetadataServer
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
			// bail, this shoudn't happe
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: Unsupported Credential Type supplied: got %v", reflect.TypeOf(ts.credentials.TokenSource))
		}
	}

	// I'm only verifying the token here so that i can extract out the expiration date.
	// TODO: just extract and parse, don't be lazy, sal
	idt, err := VerifyGoogleIDToken(context.Background(), idToken, ts.audiences[0])
	if err != nil {
		log.Fatalf("salrashid123/oauth2/google: Unable to verify OIDC token %v", err)
	}

	expireAt := idt.Expiry
	if err != nil {
		return nil, fmt.Errorf("salrashid123/oauth2/google: Error parsing ExpireTime from iamcredentials: %v", err)
	}

	ts.idToken = &oauth2.Token{
		AccessToken: idToken,
		Expiry:      expireAt,
	}

	return ts.idToken, nil
}

// TokenSource here is used to initlaize gRPC Credentials
// START Section for PerRPCCredentials
type TokenSource struct {
	oauth2.TokenSource
}

// NewIDTokenRPCCredential returns a crdential object for use with gRPC clients
func NewIDTokenRPCCredential(ctx context.Context, tokenSource oauth2.TokenSource) (credentials.PerRPCCredentials, error) {
	return TokenSource{tokenSource}, nil
}

// GetRequestMetadata gets the request metadata as a map from a TokenSource.
func (ts TokenSource) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	token, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"authorization": token.Type() + " " + token.AccessToken,
	}, nil
}

// RequireTransportSecurity indicates whether the credentials requires transport security.
func (ts TokenSource) RequireTransportSecurity() bool {
	return true
}

// END Section for PerRPCCredentials
