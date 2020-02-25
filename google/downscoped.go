// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

type AccessBoundaryRule struct {
	AvailableResource    string   `json:"availableResource"`
	AvailablePermissions []string `json:"availablePermissions"`
}

type DownScopedTokenConfig struct {
	RootTokenSource     oauth2.TokenSource
	AccessBoundaryRules []AccessBoundaryRule `json:"accessBoundaryRules"`
}

type DownScopedTokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

const (
	TOKEN_INFO_ENDPOINT       = "https://www.googleapis.com/oauth2/v3/tokeninfo"
	IDENTITY_BINDING_ENDPOINT = "https://securetoken.googleapis.com/v1beta1/identitybindingtoken"
)

// DownScopedTokenSource returns a reduced capability Google Cloud TokenSource derived a
// higher privileged TokenSource.
//
// Use this TokenSource to limit the resources a credential can access on GCP.  For example,
// if a given TokenSource can access GCS buckets A and B, a DownScopedTokenSource derived from
// the root would represent the _same_ user but IAM permissions are restricted to bucket A.
//
//  For more information, see:  https://github.com/salrashid123/downscoped_token
//
//  RootTokenSource (string): The root token to derive the restricted one from
//  DownScopedTokenConfig ([]AccessBoundaryRule): List of AccessBoundaryRule structures defining the
//     what restriction policies to apply on a resource.  In the following, the token that is returned
//     will only be valid to as an objectViewer on bucketA
//     {
// 	    "accessBoundaryRules" : [
// 	      {
// 		    "availableResource" : "//storage.googleapis.com/projects/_/buckets/bucketA",
// 		    "availablePermissions": ["inRole:roles/storage.objectViewer"]
// 	      }
// 	    ]
//     }
//
func DownScopedTokenSource(tokenConfig *DownScopedTokenConfig) (oauth2.TokenSource, error) {

	if tokenConfig.RootTokenSource == nil {
		return nil, fmt.Errorf("oauth2/google: rootSource cannot be nil")
	}

	return &downScopedTokenSource{
		refreshMutex:        &sync.Mutex{}, // guards restrictedToken; held while fetching or updating it.
		downScopedToken:     nil,           // Token representing the restricted ten. Initially nil.
		rootSource:          tokenConfig.RootTokenSource,
		accessBoundaryRules: tokenConfig.AccessBoundaryRules,
	}, nil
}

type downScopedTokenSource struct {
	refreshMutex        *sync.Mutex // guards restrictedToken; held while fetching or updating it.
	downScopedToken     *oauth2.Token
	accessBoundaryRules []AccessBoundaryRule
	rootSource          oauth2.TokenSource
}

func (ts *downScopedTokenSource) Token() (*oauth2.Token, error) {

	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	if ts.downScopedToken.Valid() {
		return ts.downScopedToken, nil
	}

	tok, err := ts.rootSource.Token()
	if err != nil {
		return nil, fmt.Errorf("oauth2/google: unable to refresh root token %v", err)
	}

	br, err := json.Marshal(
		struct {
			AccessBoundaryRules []AccessBoundaryRule `json:"accessBoundaryRules"`
		}{
			AccessBoundaryRules: ts.accessBoundaryRules,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Unable to marshall AccessBoundary Payload %v", err)
	}

	form := url.Values{}
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Add("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Add("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Add("subject_token", tok.AccessToken)
	form.Add("access_boundary", url.QueryEscape(string(br)))

	resp, err := http.PostForm(IDENTITY_BINDING_ENDPOINT, form)
	defer resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Unable to generate POST Request %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("Unable to exchange token %v", string(bodyBytes))
	}
	tresp := DownScopedTokenResponse{}
	json.NewDecoder(resp.Body).Decode(&tresp)

	// an exchanged token that is derived from a service account (2LO) has an expired_in value
	// a token derived from a users token (3LO) does not.
	// The following code uses the time remaining on rootToken for a user as the value for the
	// derived token's lifetime
	var expiresIn int
	if tresp.ExpiresIn > 0 {
		expiresIn = tresp.ExpiresIn
	} else {

		hclient := &http.Client{}
		req, err := http.NewRequest("GET", TOKEN_INFO_ENDPOINT, nil)
		if err != nil {
			return nil, fmt.Errorf("Unable to deterimine expire_time %v", err)
		}
		q := req.URL.Query()
		q.Add("access_token", tok.AccessToken)
		req.URL.RawQuery = q.Encode()
		resp, err := hclient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("Unable to lookup token expire_time %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Error while looking up token_info token %v", err)
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("Unable to parse expire_time response  %v", err)
		}

		var result map[string]interface{}
		err = json.Unmarshal(bodyBytes, &result)
		if err != nil {
			return nil, fmt.Errorf("Unable to parse response json for expire_time %v", err)
		}
		exp := string(result["expires_in"].(string))
		expiresIn, err = strconv.Atoi(exp)
		if err != nil {
			return nil, fmt.Errorf("Unable to convert expires_in value to int %v", err)
		}
	}

	ts.downScopedToken = &oauth2.Token{
		AccessToken: tresp.AccessToken,
		TokenType:   tresp.TokenType,
		Expiry:      time.Now().Add(time.Duration(expiresIn)),
	}

	return ts.downScopedToken, nil
}
