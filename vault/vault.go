// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"golang.org/x/oauth2"
)

const (
	refreshWindow = 60
)

type VaultTokenConfig struct {
	VaultToken  string
	VaultPath   string
	VaultCAcert string
	VaultAddr   string
}

// VaultTokenSource returns a Google Cloud TokenSource derived from a HashiCorp Vault TOKEN
//
// Use this TokenSource to derive a Google Cloud Credential from a HashiCorp Vault Token.
// You must configure a Vault policy the VAULT_TOKEN that returns a GCP access_token:
// https://www.vaultproject.io/docs/secrets/gcp/index.html#access-tokens
//
//	VaultToken (string): The VAULT_TOKEN capable of deriving a GCP access_token.
//	VaultPath (string): Vault gcp secrets policy endpoint. (eg "gcp/token/my-token-roleset")
//	VaultCAcert (string): The root CA Certificate for the Vault Server's endpoint
//	VaultAddr (string): Hostname/Address URI for the vault server (https://your_vault.server:8200/)
func VaultTokenSource(tokenConfig *VaultTokenConfig) (oauth2.TokenSource, error) {

	if tokenConfig.VaultToken == "" || tokenConfig.VaultPath == "" || tokenConfig.VaultAddr == "" {
		return nil, fmt.Errorf("oauth2/google: VaultToken, VaultPath, VaultAddr cannot be nil")
	}
	return &vaultTokenSource{
		refreshMutex: &sync.Mutex{}, // guards token; held while fetching or updating it.
		googleToken:  nil,           // Token representing the google identity. Initially nil.

		vaultToken:  tokenConfig.VaultToken,
		vaultPath:   tokenConfig.VaultPath,
		vaultCAcert: tokenConfig.VaultCAcert,
		vaultAddr:   tokenConfig.VaultAddr,
	}, nil
}

type vaultTokenSource struct {
	refreshMutex *sync.Mutex // guards vaultTokenSource; held while fetching or updating it.
	googleToken  *oauth2.Token
	vaultToken   string
	vaultPath    string
	vaultCAcert  string
	vaultAddr    string

	vaultTokenSecret *api.Secret
}

func (ts *vaultTokenSource) Token() (*oauth2.Token, error) {

	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	if ts.googleToken.Valid() {
		return ts.googleToken, nil
	}

	var caCertPool *x509.CertPool
	caCertPool = x509.NewCertPool()
	if ts.vaultCAcert != "" {
		caCert, err := os.ReadFile(ts.vaultCAcert)
		if err != nil {
			return nil, fmt.Errorf("Unable to read root CA certificate for Vault Server: %v", err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	config := &api.Config{
		Address: ts.vaultAddr,
		HttpClient: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		}},
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("Unable to initialize vault client: %v", err)
	}

	client.SetToken(ts.vaultToken)

	vaultTokenSecret, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return nil, fmt.Errorf("VaultToken: cannot lookup token details: %v", err)
	}

	timeLeft, err := vaultTokenSecret.TokenTTL()
	if err != nil {
		return nil, fmt.Errorf("VaultToken: unable to lookup token details: %v", err)
	}
	isRenewable, err := vaultTokenSecret.TokenIsRenewable()
	if err != nil {
		return nil, fmt.Errorf("VaultToken: unable to lookup TokenIsRenewable: %v", err)
	}

	if timeLeft.Seconds() < refreshWindow && !isRenewable {
		return nil, fmt.Errorf("VaultToken expired not renewable: %v", err)
	}

	if timeLeft.Seconds() < refreshWindow {
		vaultTokenSecret, err = client.Auth().Token().RenewSelf(0)
		if err != nil {
			return nil, fmt.Errorf("VaultToken unable to renew vault token: %v", err)
		}
	}
	secret, err := client.Logical().Read(ts.vaultPath)
	if err != nil {
		return nil, fmt.Errorf("VaultToken:  Unable to read resource at path [%s] error: %v", ts.vaultPath, err)
	}

	d := secret.Data

	accessToken := d["token"].(string)
	expireAtSeconds := d["expires_at_seconds"].(json.Number)

	i, err := strconv.ParseInt(string(expireAtSeconds), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("VaultToken:  Unable to parse enpiredTime: %v", err)
	}
	expireAt := time.Unix(i, 0)
	ts.googleToken = &oauth2.Token{
		AccessToken: accessToken,
		Expiry:      expireAt,
	}

	return ts.googleToken, nil
}
