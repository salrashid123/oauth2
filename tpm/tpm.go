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
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
	"golang.org/x/oauth2"
)

const (
	GCP_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
)

// TpmTokenConfig parameters to start Credential based off of TPM RSA Private Key.
type TpmTokenConfig struct {
	TPMDevice       io.ReadWriteCloser
	TPMPath         string
	Email, Audience string
	Key             *client.Key // load a key from handle
	KeyId           string
	Scopes          []string
	UseOauthToken   bool
}

type tpmTokenSource struct {
	refreshMutex    *sync.Mutex
	email, audience string
	tpmdevice       io.ReadWriteCloser
	tpmpath         string
	key             *client.Key
	keyId           string
	scopes          []string
	useOauthToken   bool
	myToken         *oauth2.Token
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
//		TPMDevice (io.ReadWriteCloser): The device Handle for the TPM managed by the caller Use either TPMDevice or TPMPath
//		TPMPath (string): The device Handle for the TPM (eg. "/dev/tpm0" managed by the library. Use either TPMDevice or TPMPath
//		Email (string): The service account to get the token for.
//		Audience (string): The audience representing the service the token is valid for.
//		    The audience must match the name of the Service the token is intended for.  See
//		    documentation links above.
//		    (eg. https://pubsub.googleapis.com/google.pubsub.v1.Publisher)
//		Scopes ([]string): The GCP Scopes for the GCP token. (default: cloud-platform)
//		Key (go-tpm-tools.client.Key): The client.Key from go-tpm-tools to use for the oauth handle.  Required field
//		KeyId (string): (optional) The private KeyID for the service account key saved to the TPM.
//		    This field is optional but recomended if  UseOauthTOken is false
//		    Find the keyId associated with the service account by running:
//		    `gcloud iam service-accounts keys list --iam-account=<email>``
//		UseOauthToken (bool): Use oauth2 access_token (true) or JWTAccessToken (false)
//	     see: https://developers.google.com/identity/protocols/oauth2/service-account#jwt-auth
//	     eg: audience="https://pubsub.googleapis.com/google.pubsub.v1.Publisher"
func TpmTokenSource(tokenConfig *TpmTokenConfig) (oauth2.TokenSource, error) {

	if tokenConfig.Key == nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: Key must be specified")
	}

	if tokenConfig.Email == "" {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: TPMTokenConfig.Email and cannot be nil")
	}

	if tokenConfig.TPMDevice != nil && tokenConfig.TPMPath != "" {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: one of TPMTokenConfig.TPMDevice,  TPMTokenConfig.TPMPath must be set")
	}

	if tokenConfig.Audience == "" && tokenConfig.UseOauthToken == false {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: Audience must be specified if UseOauthToken is false")
	}

	if len(tokenConfig.Scopes) == 0 {
		tokenConfig.Scopes = []string{GCP_CLOUD_PLATFORM_SCOPE}
	}

	return &tpmTokenSource{
		refreshMutex:  &sync.Mutex{},
		email:         tokenConfig.Email,
		audience:      tokenConfig.Audience,
		tpmdevice:     tokenConfig.TPMDevice,
		tpmpath:       tokenConfig.TPMPath,
		key:           tokenConfig.Key,
		keyId:         tokenConfig.KeyId,
		scopes:        tokenConfig.Scopes,
		useOauthToken: tokenConfig.UseOauthToken,
	}, nil

}

func (ts *tpmTokenSource) Token() (*oauth2.Token, error) {
	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()
	if ts.myToken.Valid() {
		return ts.myToken, nil
	}

	ctx := context.Background()

	var rwc io.ReadWriteCloser

	if ts.tpmdevice != nil {
		rwc = ts.tpmdevice
	} else {
		var err error
		rwc, err = tpm2.OpenTPM(ts.tpmpath)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: Unable to open tpm: %v", err)
		}
		defer rwc.Close()
	}

	config := &tpmjwt.TPMConfig{
		TPMDevice: rwc,
		Key:       ts.key,
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
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: Unable to generate token Request, %v", err)
		}
		resp, err := client.Do(hreq)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: unable to POST token request, %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: Token Request error:, %v", err)
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
