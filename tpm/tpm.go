// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"
)

// TpmTokenConfig parameters to start Credential based off of TPM RSA Private Key.
type TpmTokenConfig struct {
	Tpm, Email, Audience string
	TpmHandle            uint32
	KeyId                string
	UseOauthToken        bool
}

type tpmTokenSource struct {
	refreshMutex         *sync.Mutex
	tpm, email, audience string

	tpmHandle     uint32
	keyId         string
	useOauthToken bool
}

type rtokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// TpmTokenSource returns a TokenSource for a ServiceAccount where
// the privateKey is sealed within a Trusted Platform Module (TPM)
// The TokenSource uses the TPM to sign a JWT representing an AccessTokenCredential.
//
// This TpmTokenSource will only work on platforms where the PrivateKey for the Service
// Account is already loaded on the TPM previously and available via Persistent Handle.
//
//	Tpm (string): The device Handle for the TPM (eg. "/dev/tpm0")
//	Email (string): The service account to get the token for.
//	Audience (string): The audience representing the service the token is valid for.
//	    The audience must match the name of the Service the token is intended for.  See
//	    documentation links above.
//	    (eg. https://pubsub.googleapis.com/google.pubsub.v1.Publisher)
//	TpmHandle (uint32): The persistent Handle representing the sealed keypair.
//	    This must be set prior to using this library.  Required field
//	KeyId (string): (optional) The private KeyID for the service account key saved to the TPM.
//	    This field is optional but recomended if  UseOauthTOken is false
//	    Find the keyId associated with the service account by running:
//	    `gcloud iam service-accounts keys list --iam-account=<email>``
//	UseOauthToken (bool): Use oauth2 access_token (true) or JWTAccessToken (false)
func TpmTokenSource(tokenConfig *TpmTokenConfig) (oauth2.TokenSource, error) {

	if tokenConfig.TpmHandle != 0 {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: either TPMTokenConfig.TpmHandle must be specified")
	}

	if tokenConfig.Tpm == "" || tokenConfig.Email == "" {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: TPMTokenConfig.Tpm, TPMTokenConfig.TpmHandle, TPMTokenConfig.Email and cannot be nil")
	}

	if tokenConfig.Audience == "" && tokenConfig.UseOauthToken == false {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: Audience must be specified if UseOauthToken is false")
	}

	return &tpmTokenSource{
		refreshMutex:  &sync.Mutex{},
		email:         tokenConfig.Email,
		audience:      tokenConfig.Audience,
		tpm:           tokenConfig.Tpm,
		tpmHandle:     tokenConfig.TpmHandle,
		keyId:         tokenConfig.KeyId,
		useOauthToken: tokenConfig.UseOauthToken,
	}, nil

}

func (ts *tpmTokenSource) Token() (*oauth2.Token, error) {
	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	rwc, err := tpm2.OpenTPM(ts.tpm)
	if err != nil {
		return nil, fmt.Errorf("google: Unable to Open TPM: %v", err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Errorf("google: Unable to close TPM: %v", err)
		}
	}()

	kh := tpmutil.Handle(ts.tpmHandle)

	defer tpm2.FlushContext(rwc, kh)
	iat := time.Now()
	exp := iat.Add(time.Hour)
	msg := ""

	if ts.useOauthToken {
		hdr, err := json.Marshal(&jws.Header{
			Algorithm: "RS256",
			Typ:       "JWT",
		})
		if err != nil {
			return nil, fmt.Errorf("google: Unable to marshal  JWT Header: %v", err)
		}
		cs, err := json.Marshal(&jws.ClaimSet{
			Iss:   ts.email,
			Scope: "https://www.googleapis.com/auth/cloud-platform",
			Aud:   "https://accounts.google.com/o/oauth2/token",
			Iat:   iat.Unix(),
			Exp:   exp.Unix(),
		})
		if err != nil {
			return nil, fmt.Errorf("google: Unable to marshal  JWT ClaimSet: %v", err)
		}

		j := base64.URLEncoding.EncodeToString([]byte(hdr)) + "." + base64.URLEncoding.EncodeToString([]byte(cs))
		aKdataToSign := []byte(j)
		aKdigest, aKvalidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, aKdataToSign, tpm2.HandleOwner)
		if err != nil {
			return nil, fmt.Errorf("google: Unable to Sign wit TPM: %v", err)
		}

		sig, err := tpm2.Sign(rwc, kh, "", aKdigest, aKvalidation, &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		})
		if err != nil {
			return nil, fmt.Errorf("google: Unable to Sign wit TPM: %v", err)
		}

		r := j + "." + base64.URLEncoding.EncodeToString([]byte(sig.RSA.Signature))

		client := &http.Client{}

		data := url.Values{}
		data.Set("grant_type", "assertion")
		data.Add("assertion_type", "http://oauth.net/grant_type/jwt/1.0/bearer")
		data.Add("assertion", r)

		hreq, err := http.NewRequest("POST", "https://accounts.google.com/o/oauth2/token", bytes.NewBufferString(data.Encode()))
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: Unable to generate token Requestt, %v", err)
		}
		resp, err := client.Do(hreq)
		if err != nil {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: unable to POST token request, %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("salrashid123/x/oauth2/google: Token Request error:, %v", err)
		}

		f, err := ioutil.ReadAll(resp.Body)
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
		hdr, err := json.Marshal(&jws.Header{
			Algorithm: "RS256",
			Typ:       "JWT",
			KeyID:     string(ts.keyId),
		})
		if err != nil {
			return nil, fmt.Errorf("google: Unable to marshal TPM JWT Header: %v", err)
		}
		cs, err := json.Marshal(&jws.ClaimSet{
			Iss: ts.email,
			Sub: ts.email,
			Aud: ts.audience,
			Iat: iat.Unix(),
			Exp: exp.Unix(),
		})
		if err != nil {
			return nil, fmt.Errorf("google: Unable to marshal TPM JWT ClaimSet: %v", err)
		}

		j := base64.URLEncoding.EncodeToString([]byte(hdr)) + "." + base64.URLEncoding.EncodeToString([]byte(cs))

		aKdataToSign := []byte(j)
		aKdigest, aKvalidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, aKdataToSign, tpm2.HandleOwner)
		if err != nil {
			return nil, fmt.Errorf("google: Unable to Sign wit TPM: %v", err)
		}
		sig, err := tpm2.Sign(rwc, kh, "", aKdigest, aKvalidation, &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		})
		if err != nil {
			return nil, fmt.Errorf("google: Unable to Sign wit TPM: %v", err)
		}

		msg = j + "." + base64.URLEncoding.EncodeToString([]byte(sig.RSA.Signature))
	}
	return &oauth2.Token{AccessToken: msg, TokenType: "Bearer", Expiry: exp}, nil
}
