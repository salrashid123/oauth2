// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package google

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

type MyTokenConfig struct {
	TokenValues             []string
	RotationIntervalSeconds int
}

const ()

var (
	lastRefresh time.Time
	pos         = 0
)

/*
	MyTokenSource is just a testtokensource
*/
func NewMyTokenSource(tokenConfig *MyTokenConfig) (oauth2.TokenSource, error) {

	if len(tokenConfig.TokenValues) == 0 {
		return nil, fmt.Errorf("oauth2/google: initToken cannot be nil")
	}
	lastRefresh = time.Now()
	return &myTokenSource{
		refreshMutex:            &sync.Mutex{},
		tokenValues:             tokenConfig.TokenValues,
		rotationIntervalSeconds: tokenConfig.RotationIntervalSeconds,
	}, nil
}

type myTokenSource struct {
	refreshMutex            *sync.Mutex
	tokenValues             []string
	rotationIntervalSeconds int
	myToken                 *oauth2.Token
}

func (ts *myTokenSource) Token() (*oauth2.Token, error) {

	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	if ts.myToken.Valid() {
		fmt.Printf("myToken still Valid, returning [%s]\n", ts.myToken.AccessToken)
		return ts.myToken, nil
	}
	fmt.Printf("myToken not valid refreshing \n")

	tok := ""
	if lastRefresh.Before(time.Now()) {
		if pos > len(ts.tokenValues) {
			pos = 0
		}
		tok = ts.tokenValues[pos]
		pos++
	}

	ts.myToken = &oauth2.Token{
		AccessToken: tok,
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Duration(ts.rotationIntervalSeconds) * time.Second),
	}
	fmt.Printf("myToken, returning new [%s]\n", ts.myToken.AccessToken)
	return ts.myToken, nil

}
