// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
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
	CredentialsProvider  *aws.CredentialsProvider
	Scopes               []string
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
	GCP_STS_ENDPOINT         = "https://sts.googleapis.com/v1/token"
	AWS_STS_ENDPOINT         = "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
	GCP_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

	defaultVersion = "2011-06-15"
)

// AWSTokenSource exchanges AWS credentials for GCP credentials
//
// Use this TokenSource to access GCP resources while using AWS Credentials configured with
//  either AssumeRole or directly as an AWS User.
//
//  For more information, see:  https://github.com/salrashid123/gcpcompat-aws
//
//  CredentialsProvider (aws.CredentialsProvider): The root AWS Credential source to use
//  Scopes ([]string): The GCP Scopes for the GCP token. (default: cloud-platform)
//  TargetResource (string): Full GCP URI of the workload identity pool.  eg
//     "//iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/providers/aws-provider-1",
//  Region (string): The AWS Region for the STS Service (eg us-east-1))
//  TargetServiceAccount: (string): GCP ServiceAccount name that will get impersonated.   Used
//     only if UseFederatedToken=false
//  UseIAMToken:  (bool) Enables direct exchange of Federated Token for an IAMCredential token
//     token for a service account token.  Set this value to false (i.,e use FederatedToken) only applies
//     to a limited set of GCP services (at the moment, IAMCredentials, GCS).

func AWSTokenSource(tokenConfig *AwsTokenConfig) (oauth2.TokenSource, error) {

	if &tokenConfig.CredentialsProvider == nil {
		return nil, fmt.Errorf("oauth2/google: AwsCredential cannot be nil")
	}

	if len(tokenConfig.Scopes) == 0 {
		tokenConfig.Scopes = []string{GCP_CLOUD_PLATFORM_SCOPE}
	}
	return &awsTokenSource{
		refreshMutex:         &sync.Mutex{},
		rootSource:           *tokenConfig.CredentialsProvider,
		scopes:               tokenConfig.Scopes,
		targetResource:       tokenConfig.TargetResource,
		region:               tokenConfig.Region,
		targetServiceAccount: tokenConfig.TargetServiceAccount,
		useIAMToken:          tokenConfig.UseIAMToken,
	}, nil
}

type awsTokenSource struct {
	refreshMutex         *sync.Mutex
	scopes               []string
	targetResource       string
	rootSource           aws.CredentialsProvider
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
	}

	rr, err := ts.rootSource.Retrieve(context.Background())
	if err != nil {
		return nil, err
	}

	body := strings.NewReader("")

	signer := v4.NewSigner()
	req, err := http.NewRequest(http.MethodPost, AWS_STS_ENDPOINT, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("x-goog-cloud-target-resource", ts.targetResource)
	postForm := url.Values{}
	hasher := sha256.New()
	_, err = hasher.Write([]byte(postForm.Encode()))
	if err != nil {
		return nil, err
	}
	postPayloadHash := hex.EncodeToString(hasher.Sum(nil))
	ctx := context.Background()

	err = signer.SignHTTP(ctx, rr, req, postPayloadHash, "sts", ts.region, time.Now())
	if err != nil {
		return nil, err
	}

	var subjectToken = &sTSOptions{}

	if rr.SessionToken != "" {
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
		return nil, fmt.Errorf("unable to Unmarshall SubjectToken %v", err)
	}

	gform := url.Values{}
	gform.Add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	gform.Add("audience", ts.targetResource)
	gform.Add("subject_token_type", "urn:ietf:params:aws:token-type:aws4_request")
	gform.Add("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	gform.Add("scope", strings.Join(ts.scopes, " "))
	gform.Add("subject_token", string(e))

	gcpSTSResp, err := http.PostForm(GCP_STS_ENDPOINT, gform)
	defer gcpSTSResp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error exchaning token for GCP STS %v", err)
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
		return nil, err
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

	var jsonStr = []byte(fmt.Sprintf(`{"scope": ["%s"] }`, strings.Join(ts.scopes, " ")))
	req, err = http.NewRequest(http.MethodPost, iamEndpoint, bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.targetTokenSource.AccessToken))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	ttresp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error invoking IAM Credentials API %v", err)
	}
	defer ttresp.Body.Close()

	if ttresp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(ttresp.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading IAM Credentials response body %v", err)
		}
		return nil, fmt.Errorf("error invoking IAM Credentials API: [%s] \n %v", string(bodyBytes), err)
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
