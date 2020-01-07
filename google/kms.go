// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"encoding/base64"
	"encoding/json"
	"sync"

	"context"
	"crypto/sha256"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

const (
	CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
)

// KmsTokenConfig parameters to start Credential based off of a KMS-based Private Key.
type KmsTokenConfig struct {
	Email         string
	Audience      string
	ProjectId     string
	LocationId    string
	KeyRing       string
	Key           string
	KeyID         string
	KeyVersion    string
	UseOauthToken bool
}

type kmsTokenSource struct {
	refreshMutex  *sync.Mutex
	projectId     string
	audience      string
	locationId    string
	keyRing       string
	key           string
	keyId         string
	keyVersion    string
	email         string
	useOauthToken bool
}

type tokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// KmsTokenSource returns a TokenSource for a ServiceAccount where
// the privateKey is sealed within Google Cloud KMS
// The TokenSource uses the KMS to sign a JWT representing an JWTAccessTokenCredential or
// a regular oauh2 access_token.
// for more information on JWTAccesTokens, see
// https://developers.google.com/identity/protocols/OAuth2ServiceAccount#jwt-auth
//
// This TokenSource will only work if the KMS's key is linked with a Google Cloud Service
// Account.  To do that, first generate a public/private keypair either directly on
// KMS (preferred) or using your own CA.  Then import the the privateKey into KMS
// If you generate the key outside KMS, you must import the public part into GCP and associate it:
// https://cloud.google.com/iam/docs/creating-managing-service-account-keys#uploading
//
//  Email (string): The service account to get the token for.
//  Audience (string): The audience representing the service the token is valid for.
//      The audience must match the name of the Service the token is intended for.  See
//      documentation links above.  This field is optional if UseOauthToken
//      is true.
//      (eg. https://pubsub.googleapis.com/google.pubsub.v1.Publisher)
//  KeyID (string): The keyID for the ServiceAccount key.  This field is optional but recomended if
//      UseOauthTOken is false
//      Find the keyId associated with the service account by running:
//      `gcloud iam service-accounts keys list --iam-account=<email>``
//  KeyRing (string): The keyRing where the key is saved on KMS
//  LocationId (string): The location for the keyring
//  Key (string): Name of the key
//  ProjectId (string): ProjectID of the KMS keyring.
//  UseOauthToken (bool): Use oauth2 access_token (true) or JWTAccessToken (false)
//
func KmsTokenSource(tokenConfig *KmsTokenConfig) (oauth2.TokenSource, error) {

	if tokenConfig.Email == "" || tokenConfig.KeyRing == "" || tokenConfig.LocationId == "" || tokenConfig.Key == "" {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: KMSTokenConfig keyID, Audience, Locaiton, Email, Key and keyring cannot be nil")
	}

	if tokenConfig.Audience == "" && tokenConfig.UseOauthToken == false {
		return nil, fmt.Errorf("salrashid123/x/oauth2/google: Audience  must be specified if UseOauthToken is false")
	}

	return &kmsTokenSource{
		refreshMutex:  &sync.Mutex{},
		email:         tokenConfig.Email,
		audience:      tokenConfig.Audience,
		keyId:         tokenConfig.KeyID,
		key:           tokenConfig.Key,
		projectId:     tokenConfig.ProjectId,
		locationId:    tokenConfig.LocationId,
		keyRing:       tokenConfig.KeyRing,
		keyVersion:    tokenConfig.KeyVersion,
		useOauthToken: tokenConfig.UseOauthToken,
	}, nil

}

func (ts *kmsTokenSource) Token() (*oauth2.Token, error) {
	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

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
			Scope: CLOUD_PLATFORM_SCOPE,
			Aud:   "https://accounts.google.com/o/oauth2/token",
			Iat:   iat.Unix(),
			Exp:   exp.Unix(),
		})
		if err != nil {
			return nil, fmt.Errorf("google: Unable to marshal  JWT ClaimSet: %v", err)
		}

		j := base64.URLEncoding.EncodeToString([]byte(hdr)) + "." + base64.URLEncoding.EncodeToString([]byte(cs))
		ctx := context.Background()
		parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", ts.projectId, ts.locationId, ts.keyRing, ts.key, ts.keyVersion)

		kmsClient, err := cloudkms.NewKeyManagementClient(ctx)

		digest := sha256.New()
		digest.Write([]byte(j))
		req := &kmspb.AsymmetricSignRequest{
			Name: parentName,
			Digest: &kmspb.Digest{
				Digest: &kmspb.Digest_Sha256{
					Sha256: digest.Sum(nil),
				},
			},
		}
		dresp, err := kmsClient.AsymmetricSign(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("google: Unable to AsymetricSign: %v", err)
		}
		r := j + "." + base64.URLEncoding.EncodeToString(dresp.Signature)

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
		var m tokenJSON
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
			return nil, fmt.Errorf("google: Unable to marshal KMS JWT Header: %v", err)
		}
		cs, err := json.Marshal(&jws.ClaimSet{
			Iss: ts.email,
			Sub: ts.email,
			Aud: ts.audience,
			Iat: iat.Unix(),
			Exp: exp.Unix(),
		})
		if err != nil {
			return nil, fmt.Errorf("google: Unable to marshal KMS JWT ClaimSet: %v", err)
		}

		j := base64.URLEncoding.EncodeToString([]byte(hdr)) + "." + base64.URLEncoding.EncodeToString([]byte(cs))
		ctx := context.Background()
		parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", ts.projectId, ts.locationId, ts.keyRing, ts.key, ts.keyVersion)

		kmsClient, err := cloudkms.NewKeyManagementClient(ctx)

		digest := sha256.New()
		digest.Write([]byte(j))
		req := &kmspb.AsymmetricSignRequest{
			Name: parentName,
			Digest: &kmspb.Digest{
				Digest: &kmspb.Digest_Sha256{
					Sha256: digest.Sum(nil),
				},
			},
		}
		dresp, err := kmsClient.AsymmetricSign(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("google: Unable to AsymetricSign: %v", err)
		}
		msg = j + "." + base64.URLEncoding.EncodeToString(dresp.Signature)

	}
	return &oauth2.Token{AccessToken: msg, TokenType: "Bearer", Expiry: exp}, nil
}
