// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"context"
	"fmt"
	"io"
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
	Email            string
	Handle           tpm2.TPMHandle // load a key from handle
	AuthSession      tpmjwt.Session
	KeyId            string
	Scopes           []string
	EncryptionHandle tpm2.TPMHandle // (optional) handle to use for transit encryption
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
	myToken          *oauth2.Token
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
func TpmTokenSource(tokenConfig *TpmTokenConfig) (oauth2.TokenSource, error) {

	if &tokenConfig.Handle == nil || tokenConfig.TPMDevice == nil {
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

	keyctx, err := tpmjwt.NewTPMContext(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: Unable to initialize tpmjwt: %v", err)
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
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: unable to POST token request, %v", err)
	}
	msg = tokenString

	ts.myToken = &oauth2.Token{AccessToken: msg, TokenType: "Bearer", Expiry: exp}
	return ts.myToken, nil
}
