// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	awscred "github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"golang.org/x/oauth2"
)

type sTSTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type sTSHeaders struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}
type sTSOptions struct {
	Headers []sTSHeaders `json:"headers"`
	Method  string       `json:"method,omitempty"`
	URL     string       `json:"url,omitempty"`
}

type AwsTokenConfig struct {
	AwsCredential        awscred.Credentials
	Scope                string
	TargetResource       string
	Region               string
	TargetServiceAccount string
	UseIAMToken          bool
}

type iamGenerateAccessTokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}

const (
	GCP_STS_ENDPOINT         = "https://sts.googleapis.com/v1beta/token"
	AWS_STS_ENDPOINT         = "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
	GCP_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
)

// AWSTokenSource exchanges AWS credentials for GCP credentials
//
// Use this TokenSource to access GCP resources while using AWS Credentials configured with
//  either AssumeRole or directly as an AWS User.
//
//  For more information, see:  https://github.com/salrashid123/gcpcompat-aws
//
//  AwsCredential (aws.Credential): The root AWS Credential to use.  Maybe either a direct user
//     user credential or one derived through AssumeRole
//  Scope (string): The GCP Scope value for the GCP token. (default: cloud-platform)
//  TargetResource (string): Full GCP URI of the workload identity pool.  eg
//     "//iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/providers/aws-provider-1",
//  Region (string): The AWS Region for the STS Service (eg us-east-1))
//  TargetServiceAccount: (string): GCP ServiceAccount name that will get impersonated.   Used
//     only if UseFederatedToken=false
//  UseIAMToken:  (bool) Enables direct exchange of Federated Token for an IAMCredential token
//     token for a service account token.  Set this value to false (i.,e use FederatedToken) only applies
//     to a limited set of GCP services (at the moment, IAMCredentials, GCS).

func AWSTokenSource(tokenConfig *AwsTokenConfig) (oauth2.TokenSource, error) {

	if &tokenConfig.AwsCredential == nil {
		return nil, fmt.Errorf("oauth2/google: AwsCredential cannot be nil")
	}

	if tokenConfig.Scope == "" {
		tokenConfig.Scope = GCP_CLOUD_PLATFORM_SCOPE
	}
	return &awsTokenSource{
		refreshMutex:         &sync.Mutex{},
		rootSource:           &tokenConfig.AwsCredential,
		scope:                tokenConfig.Scope,
		targetResource:       tokenConfig.TargetResource,
		region:               tokenConfig.Region,
		targetServiceAccount: tokenConfig.TargetServiceAccount,
		useIAMToken:          tokenConfig.UseIAMToken,
	}, nil
}

type awsTokenSource struct {
	refreshMutex         *sync.Mutex
	scope                string
	targetResource       string
	rootSource           *awscred.Credentials
	targetTokenSource    *oauth2.Token
	region               string
	targetServiceAccount string
	useIAMToken          bool
}

func (ts *awsTokenSource) Token() (*oauth2.Token, error) {
	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	if ts.targetTokenSource.Valid() {
		return ts.targetTokenSource, nil
	} else if ts.rootSource.IsExpired() {
		_, err := ts.rootSource.Get()
		if err != nil {
			return nil, fmt.Errorf(" Could not refresh AWS Credentials %v", err)
		}
	}

	body := strings.NewReader("")

	signer := v4.NewSigner(ts.rootSource)
	req, err := http.NewRequest(http.MethodPost, AWS_STS_ENDPOINT, body)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate AWS STS POST request %v", err)
	}

	req.Header.Add("x-goog-cloud-target-resource", ts.targetResource)

	cv, err := ts.rootSource.Get()
	if err != nil {
		return nil, fmt.Errorf("Unable to generate AWS STS POST request %v", err)
	}

	if cv.SessionToken != "" {
		req.Header.Add("x-amz-security-token", cv.SessionToken)
	}

	_, err = signer.Sign(req, body, "sts", ts.region, time.Now())
	if err != nil {
		return nil, fmt.Errorf("Unable to generate AWS Signature %v", err)
	}

	// log.Printf("Signed Authorization header: %s\n", req.Header.Get("Authorization"))
	// log.Printf("Signed x-amz-date header: %s\n", req.Header.Get("x-amz-date"))
	// log.Printf("Signed x-amz-security-token: %s\n", req.Header.Get("x-amz-security-token"))
	// log.Printf("Signed host header: %s\n", req.Host)
	// log.Printf("Signed x-goog-cloud-target-resource header: %s\n", req.Header.Get("x-goog-cloud-target-resource"))
	// log.Printf("Signed request method: %s\n", req.Method)

	var subjectToken = &sTSOptions{}

	if cv.SessionToken != "" {
		subjectToken = &sTSOptions{
			Headers: []sTSHeaders{
				{Key: "host", Value: req.Host},
				{Key: "x-amz-date", Value: req.Header.Get("x-amz-date")},
				{Key: "x-amz-security-token", Value: url.QueryEscape(req.Header.Get("x-amz-security-token"))},
				{Key: "x-goog-cloud-target-resource", Value: req.Header.Get("x-goog-cloud-target-resource")},
				{Key: "Authorization", Value: req.Header.Get("Authorization")},
			},
			Method: http.MethodPost,
			URL:    AWS_STS_ENDPOINT,
		}
	} else {
		subjectToken = &sTSOptions{
			Headers: []sTSHeaders{
				{Key: "host", Value: req.Host},
				{Key: "x-amz-date", Value: req.Header.Get("x-amz-date")},
				{Key: "x-goog-cloud-target-resource", Value: req.Header.Get("x-goog-cloud-target-resource")},
				{Key: "Authorization", Value: req.Header.Get("Authorization")},
			},
			Method: http.MethodPost,
			URL:    AWS_STS_ENDPOINT,
		}
	}

	e, err := json.Marshal(subjectToken)
	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("Unable to Unmarshall SubjectToken %v", err)
	}

	form := url.Values{}
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Add("audience", ts.targetResource)
	form.Add("subject_token_type", "urn:ietf:params:aws:token-type:aws4_request")
	form.Add("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Add("scope", ts.scope)
	form.Add("subject_token", string(e))

	gcpSTSResp, err := http.PostForm(GCP_STS_ENDPOINT, form)
	defer gcpSTSResp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Error exchaning token for GCP STS %v", err)
	}

	if gcpSTSResp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(gcpSTSResp.Body)
		if err != nil {
			return nil, fmt.Errorf("Error reading sts response body %v", err)
		}
		return nil, fmt.Errorf("Unable to exchange token %s,  %v", string(bodyBytes), err)
	}
	tresp := &sTSTokenResponse{}
	err = json.NewDecoder(gcpSTSResp.Body).Decode(tresp)
	if err != nil {
		return nil, fmt.Errorf("Error Decoding GCP STS TokenResponse %v", err)
	}

	ts.targetTokenSource = &oauth2.Token{
		AccessToken: tresp.AccessToken,
		TokenType:   tresp.TokenType,
		Expiry:      time.Now().Add(time.Duration(tresp.ExpiresIn)),
	}

	if !ts.useIAMToken {
		return ts.targetTokenSource, nil
	}

	iamEndpoint := fmt.Sprintf("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken", ts.targetServiceAccount)

	var jsonStr = []byte(fmt.Sprintf(`{"scope": ["%s"] }`, ts.scope))
	req, err = http.NewRequest(http.MethodPost, iamEndpoint, bytes.NewBuffer(jsonStr))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.targetTokenSource.AccessToken))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	ttresp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error invoking IAM Credentials API %v", err)
	}
	defer ttresp.Body.Close()

	if ttresp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(ttresp.Body)
		if err != nil {
			return nil, fmt.Errorf("Error reading IAM Credentials response body %v", err)
		}
		return nil, fmt.Errorf("Error invoking IAM Credentials API: [%s] \n %v", string(bodyBytes), err)
	}

	target := &iamGenerateAccessTokenResponse{}

	json.NewDecoder(ttresp.Body).Decode(target)

	expireAt, err := time.Parse(time.RFC3339, target.ExpireTime)
	if err != nil {
		return nil, fmt.Errorf("oauth2/google: Error parsing ExpireTime from iamcredentials: %v", err)
	}

	return &oauth2.Token{
		AccessToken: target.AccessToken,
		TokenType:   "Bearer",
		Expiry:      expireAt,
	}, nil

}
