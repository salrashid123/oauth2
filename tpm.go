// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/go-tpm/tpm2"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
	"golang.org/x/oauth2"
)

const (
	GCP_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
)

// TpmTokenConfig parameters to start Credential based off of TPM RSA Private Key.
type TpmTokenConfig struct {
	TPMDevice        io.ReadWriteCloser // ReadCloser to the TPM
	Email            string             // ServiceAccount Email
	Handle           tpm2.TPMHandle     // TPM ObjectHandle
	AuthSession      tpmjwt.Session     // TPM Session handle for Password or PCR auth
	KeyId            string             // The service accounts key_id value
	Scopes           []string           // list of scopes to use
	UseOauthToken    bool               // enables oauth2 token (default: false)
	IdentityToken    bool               // get id_token instead of access_token (default false)
	Audience         string             // audience (required if IdToken is true)
	EncryptionHandle tpm2.TPMHandle     // (optional) handle to use for transit encryption
}

type tpmTokenSource struct {
	refreshMutex *sync.Mutex
	oauth2.TokenSource
	email            string
	tpmdevice        io.ReadWriteCloser
	handle           tpm2.TPMHandle
	authSession      tpmjwt.Session
	keyId            string
	scopes           []string
	useOauthToken    bool
	myToken          *oauth2.Token
	identityToken    bool
	audience         string
	encryptionHandle tpm2.TPMHandle // (optional) handle to use for transit encryption
}

type rtokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type ClaimWithSubject struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

// TpmTokenSource returns a TokenSource for a ServiceAccount where
// the privateKey is sealed within a Trusted Platform Module (TPM)
// The TokenSource uses the TPM to sign a JWT representing an AccessTokenCredential.
//
// This TpmTokenSource will only work on platforms where the PrivateKey for the Service
// Account is already loaded on the TPM previously and available via Persistent Handle or PEM Key file
func TpmTokenSource(tokenConfig *TpmTokenConfig) (oauth2.TokenSource, error) {

	if tokenConfig.Handle == 0 || tokenConfig.TPMDevice == nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: KeyHandle and TPMDevice must be specified")
	}

	if tokenConfig.Email == "" {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: TPMTokenConfig.Email and cannot be nil")
	}

	if len(tokenConfig.Scopes) == 0 {
		tokenConfig.Scopes = []string{GCP_CLOUD_PLATFORM_SCOPE}
	}

	return &tpmTokenSource{
		refreshMutex:     &sync.Mutex{},
		email:            tokenConfig.Email,
		tpmdevice:        tokenConfig.TPMDevice,
		authSession:      tokenConfig.AuthSession,
		keyId:            tokenConfig.KeyId,
		scopes:           tokenConfig.Scopes,
		handle:           tokenConfig.Handle,
		useOauthToken:    tokenConfig.UseOauthToken,
		identityToken:    tokenConfig.IdentityToken,
		audience:         tokenConfig.Audience,
		encryptionHandle: tokenConfig.EncryptionHandle,
	}, nil

}

func (ts *tpmTokenSource) Token() (*oauth2.Token, error) {
	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()
	if ts.myToken.Valid() {
		return ts.myToken, nil
	}

	ctx := context.Background()

	config := &tpmjwt.TPMConfig{
		TPMDevice:        ts.tpmdevice,
		Handle:           ts.handle,
		AuthSession:      ts.authSession,
		KeyID:            ts.keyId,
		EncryptionHandle: ts.encryptionHandle,
	}

	if ts.identityToken {
		if ts.audience == "" {
			return nil, fmt.Errorf(" audience must be set if identityToken is used")
		}
		iat := time.Now()
		exp := iat.Add(time.Second * 10) // we just need a small amount of time to get a token

		type idTokenJWT struct {
			jwt.RegisteredClaims
			TargetAudience string `json:"target_audience"`
		}

		claims := &idTokenJWT{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    ts.email,
				IssuedAt:  jwt.NewNumericDate(iat),
				ExpiresAt: jwt.NewNumericDate(exp),
				Audience:  []string{"https://oauth2.googleapis.com/token"},
			},
			TargetAudience: ts.audience,
		}

		tpmjwt.SigningMethodTPMRS256.Override()
		jwt.MarshalSingleStringAsArray = false
		token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

		ctx := context.Background()
		config := &tpmjwt.TPMConfig{
			TPMDevice:        ts.tpmdevice,
			Handle:           ts.handle,
			AuthSession:      ts.authSession,
			EncryptionHandle: ts.encryptionHandle,
		}
		keyctx, err := tpmjwt.NewTPMContext(ctx, config)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/tpm Unable to initialize tpmJWT: %v", err)
		}

		tokenString, err := token.SignedString(keyctx)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/tpm Error signing %v", err)
		}
		client := &http.Client{}

		data := url.Values{}
		data.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
		data.Add("assertion", tokenString)

		hreq, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", bytes.NewBufferString(data.Encode()))
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/tpm Error: Unable to generate token Request, %v", err)
		}
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
		resp, err := client.Do(hreq)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/tpm  unable to POST token request, %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			f, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("salrashid123/x/oauth2/tpm Error Reading response body, %v", err)
			}
			return nil, fmt.Errorf("salrashid123/x/oauth2/tpm Error: Token Request error:, %s", f)
		}
		defer resp.Body.Close()

		type idTokenResponse struct {
			IdToken string `json:"id_token"`
		}

		var ret idTokenResponse
		err = json.NewDecoder(resp.Body).Decode(&ret)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/tpm Error: decoding token:, %s", err)
		}
		defaultExp := iat.Add(3600 * time.Second)
		ts.myToken = &oauth2.Token{AccessToken: ret.IdToken, TokenType: "Bearer", Expiry: defaultExp}

		return nil, nil
	}

	if !ts.useOauthToken {

		keyctx, err := tpmjwt.NewTPMContext(ctx, config)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/tpm: Unable to initialize tpmjwt: %v", err)
		}
		tpmjwt.SigningMethodTPMRS256.Override()
		jwt.MarshalSingleStringAsArray = false

		iat := time.Now()
		exp := iat.Add(time.Hour)
		msg := ""

		claims := &ClaimWithSubject{
			Scope: strings.Join(ts.scopes, " "),
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(iat),
				ExpiresAt: jwt.NewNumericDate(exp),
				Issuer:    ts.email,
				Subject:   ts.email,
			},
		}

		token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

		if ts.keyId != "" {
			token.Header["kid"] = ts.keyId
		}

		tokenString, err := token.SignedString(keyctx)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/tpm: unable to POST token request, %v", err)
		}
		msg = tokenString

		ts.myToken = &oauth2.Token{AccessToken: msg, TokenType: "Bearer", Expiry: exp}
	} else {
		iat := time.Now()
		exp := iat.Add(10 * time.Second)

		claims := &ClaimWithSubject{
			Scope: strings.Join(ts.scopes, " "),
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(iat),
				ExpiresAt: jwt.NewNumericDate(exp),
				Issuer:    ts.email,
				Audience:  []string{"https://oauth2.googleapis.com/token"},
			},
		}

		tpmjwt.SigningMethodTPMRS256.Override()
		jwt.MarshalSingleStringAsArray = false
		token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

		if ts.keyId != "" {
			token.Header["kid"] = ts.keyId
		}

		keyctx, err := tpmjwt.NewTPMContext(ctx, config)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/tpm: Unable to initialize tpmjwt: %v", err)
		}

		tokenString, err := token.SignedString(keyctx)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/tpn: unable to POST token request, %v", err)
		}

		client := &http.Client{}

		data := url.Values{}
		data.Set("grant_type", "assertion")
		data.Add("assertion_type", "http://oauth.net/grant_type/jwt/1.0/bearer")
		data.Add("assertion", tokenString)

		hreq, err := http.NewRequest(http.MethodPost, "https://accounts.google.com/o/oauth2/token", bytes.NewBufferString(data.Encode()))
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: Unable to generate token Request, %v", err)
		}
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
		resp, err := client.Do(hreq)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/tpm: unable to POST token request, %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			f, err := io.ReadAll(resp.Body)
			defer resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("salrashid123/x/oauth2/tpm: unable to POST token request %v", err)
			}
			return nil, fmt.Errorf("salrashid123/x/oauth2/tpm: Token Request error:, %s", string(f))
		}

		f, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/tpm: unable to parse tokenresponse, %v", err)
		}
		resp.Body.Close()
		var m rtokenJSON
		err = json.Unmarshal(f, &m)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/tpm: Unable to unmarshal response, %v", err)
		}
		defaultExp := iat.Add(3600 * time.Second)
		ts.myToken = &oauth2.Token{AccessToken: m.AccessToken, TokenType: "Bearer", Expiry: defaultExp}
	}

	return ts.myToken, nil
}
