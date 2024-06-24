// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

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
	TPMDevice        io.ReadWriteCloser
	Email, Audience  string
	NamedHandle      tpm2.NamedHandle // load a key from handle
	AuthSession      tpmjwt.Session
	KeyId            string
	Scopes           []string
	UseOauthToken    bool
	EncryptionHandle tpm2.TPMHandle   // (optional) handle to use for transit encryption
	EncryptionPub    *tpm2.TPMTPublic // (optional) public key to use for transit encryption

}

type tpmTokenSource struct {
	refreshMutex *sync.Mutex
	oauth2.TokenSource
	email, audience  string
	tpmdevice        io.ReadWriteCloser
	namedHandle      tpm2.NamedHandle
	authSession      tpmjwt.Session
	keyId            string
	scopes           []string
	useOauthToken    bool
	myToken          *oauth2.Token
	encryptionHandle tpm2.TPMHandle   // (optional) handle to use for transit encryption
	encryptionPub    *tpm2.TPMTPublic // (optional) public key to use for transit encryption

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
// Account is already loaded on the TPM previously and available via Persistent Handle.
//
//			TPMDevice (io.ReadWriteCloser): The device Handle for the TPM managed by the caller Use either TPMDevice or TPMPath
//			Email (string): The service account to get the token for.
//			Audience (string): The audience representing the service the token is valid for.
//			    The audience must match the name of the Service the token is intended for.  See
//			    documentation links above.
//			    (eg. https://pubsub.googleapis.com/google.pubsub.v1.Publisher)
//			Scopes ([]string): The GCP Scopes for the GCP token. (default: cloud-platform)
//			NamedHandle (*tpm2.NameHandle): The key handle to use
//	     Session: (go-tpm-jwt.Session): PCR or Password authorized session to use (github.com/salrashid123/golang-jwt-tpm)
//			KeyId (string): (optional) The private KeyID for the service account key saved to the TPM.
//			    This field is optional but recomended if  UseOauthTOken is false
//			    Find the keyId associated with the service account by running:
//			    `gcloud iam service-accounts keys list --iam-account=<email>``
//			UseOauthToken (bool): Use oauth2 access_token (true) or JWTAccessToken (false)
//		     see: https://developers.google.com/identity/protocols/oauth2/service-account#jwt-auth
//		     eg: audience="https://pubsub.googleapis.com/google.pubsub.v1.Publisher"
func TpmTokenSource(tokenConfig *TpmTokenConfig) (oauth2.TokenSource, error) {

	if &tokenConfig.NamedHandle == nil || tokenConfig.TPMDevice == nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: KeyHandle and TPMDevice must be specified")
	}

	if tokenConfig.Email == "" {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: TPMTokenConfig.Email and cannot be nil")
	}

	if tokenConfig.Audience == "" && tokenConfig.UseOauthToken == false {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: Audience must be specified if UseOauthToken is false")
	}

	if len(tokenConfig.Scopes) == 0 {
		tokenConfig.Scopes = []string{GCP_CLOUD_PLATFORM_SCOPE}
	}

	return &tpmTokenSource{
		refreshMutex:     &sync.Mutex{},
		email:            tokenConfig.Email,
		audience:         tokenConfig.Audience,
		tpmdevice:        tokenConfig.TPMDevice,
		authSession:      tokenConfig.AuthSession,
		keyId:            tokenConfig.KeyId,
		scopes:           tokenConfig.Scopes,
		useOauthToken:    tokenConfig.UseOauthToken,
		namedHandle:      tokenConfig.NamedHandle,
		encryptionHandle: tokenConfig.EncryptionHandle,
		encryptionPub:    tokenConfig.EncryptionPub,
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
		NamedHandle:      ts.namedHandle,
		AuthSession:      ts.authSession,
		KeyID:            ts.keyId,
		EncryptionHandle: ts.encryptionHandle,
		EncryptionPub:    ts.encryptionPub,
	}

	keyctx, err := tpmjwt.NewTPMContext(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: Unable to initialize tpmjwt: %v", err)
	}
	tpmjwt.SigningMethodTPMRS256.Override()
	jwt.MarshalSingleStringAsArray = false

	iat := time.Now()
	exp := iat.Add(time.Hour)
	msg := ""

	if ts.useOauthToken {

		claims := &ClaimWithSubject{
			Scope: strings.Join(ts.scopes, " "),
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(iat),
				ExpiresAt: jwt.NewNumericDate(exp),
				Issuer:    ts.email,
				Audience:  []string{"https://oauth2.googleapis.com/token"},
			},
		}

		token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

		if ts.keyId != "" {
			token.Header["kid"] = ts.keyId
		}

		tokenString, err := token.SignedString(keyctx)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: unable to POST token request, %v", err)
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
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: unable to POST token request, %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			f, err := io.ReadAll(resp.Body)
			defer resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("salrashid123/x/oauth2/google: unable to POST token request %v", err)
			}
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: Token Request error:, %s", string(f))
		}

		f, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: unable to parse tokenresponse, %v", err)
		}
		resp.Body.Close()
		var m rtokenJSON
		err = json.Unmarshal(f, &m)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: Unable to unmarshal response, %v", err)
		}
		msg = m.AccessToken

	} else {

		claims := &jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(iat),
			ExpiresAt: jwt.NewNumericDate(exp),
			Issuer:    ts.email,
			Subject:   ts.email,
			Audience:  []string{ts.audience},
		}

		token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

		if ts.keyId != "" {
			token.Header["kid"] = ts.keyId
		}

		tokenString, err := token.SignedString(keyctx)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: unable to POST token request, %v", err)
		}
		msg = tokenString
	}
	ts.myToken = &oauth2.Token{AccessToken: msg, TokenType: "Bearer", Expiry: exp}
	return ts.myToken, nil
}
