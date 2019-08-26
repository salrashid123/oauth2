
# Google OIDC tokens in golang

Sample Reference that implements Google OIDC tokens in golang to support Google Cloud services.

Use this library to easily acquire Google OpenID Connect tokens for use against Cloud Run, Cloud Functions, IAP, endpoints and other services.

You can bootstrap this client using a source [oauth2/google/Credential](https://godoc.org/golang.org/x/oauth2/google#Credentials) object

For more information, see
- [Authenticating using Google OpenID Connect Tokens](https://medium.com/google-cloud/authenticating-using-google-openid-connect-tokens-e7675051213b)
- [ImpersonatedCredentials](https://github.com/googleapis/google-api-go-client/issues/378)

> NOTE: This is NOT supported by Google


## Usage

You can bootstrap this library in a number of ways depending on where you are running this code.  You must acquire a [Credential](https://godoc.org/golang.org/x/oauth2/google#Credentials) object and pass that into `IdTokenCredentials`

You *CANNOT* use end user credentials such as those derived from your user account with oauth2 webflow.  You can use ServiceAccount, ComputeEngine or Impersonated Credentials as shown below

- Import classes

```golang
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	sal "github.com/salrashid123/oauth2/google"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	targetAudience = "https://your_target_audience.run.app"
	url            = "https://your_endpoint.run.app"   // usually the same as targetAudience
)

func main() {
  ...
}
```

You can pick the credential type that suits you:

#### Default Credentials with ServiceAccount

First export env vars pointing to svc_account

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/pathy/svc.json
```

```golang
scopes := "https://www.googleapis.com/auth/userinfo.email"  // scopes here dont' really matter...
creds, err := google.FindDefaultCredentials(ctx, scopes)
if err != nil {
	log.Fatal(err)
}
```

#### ComputeEngine/GKE

```golang
scopes := "https://www.googleapis.com/auth/userinfo.email"
creds, err := google.FindDefaultCredentials(ctx, scopes)
if err != nil {
	log.Fatal(err)
}
```

#### ServiceAccount

Read the certificate file and initialize a credential:

```golang
scopes := "https://www.googleapis.com/auth/userinfo.email"  // again, scopes don't really matter
data, err := ioutil.ReadFile(jsonCert)
if err != nil {
	log.Fatal(err)
}
creds, err := google.CredentialsFromJSON(ctx, data, scopes)
if err != nil {
	log.Fatal(err)
}
```

#### ImpersonatedCredentials

ImpersonatedCredential is experimental (you'll only find it in this repo for now)

```golang
targetPrincipal := "impersonated-account@fabled-ray-104117.iam.gserviceaccount.com"
lifetime := 30 * time.Second
delegates := []string{}
targetScopes := []string{"https://www.googleapis.com/auth/devstorage.read_only",
	"https://www.googleapis.com/auth/cloud-platform"}
rootTokenSource, err := google.DefaultTokenSource(ctx,
	"https://www.googleapis.com/auth/iam")
if err != nil {
	log.Fatal(err)
}
tokenSource, err := sal.ImpersonatedTokenSource(
	sal.ImpersonatedTokenConfig{
		RootTokenSource: rootTokenSource,
		TargetPrincipal: targetPrincipal,
		Lifetime:        lifetime,
		Delegates:       delegates,
		TargetScopes:    targetScopes,
	},
)
if err != nil {
	log.Fatal(err)
}

// Since we just have a tokensource here, we need to add that into a Credential for later use
creds := &google.Credentials{
	TokenSource: tokenSource,
}
```

## Use IDToken in HTTP Client

Now that you have a Credential, you can extract the token or just use it in an authorized client

```golang
idTokenSource, err := sal.IdTokenSource(
	sal.IdTokenConfig{
		Credentials: creds,
		Audiences:   []string{targetAudience},
	},
)
client := &http.Client{
	Transport: &oauth2.Transport{
		Source: idTokenSource,
	},
}

resp, err := client.Get(url)
if err != nil {
	log.Fatal(err)
}
log.Printf("Response: %v", resp.Status)
```

## Token Verification

You can verify a rawToken against google public certifiates and audience

```golang
log.Printf("IdToken: %v", tok.AccessToken)
idt, err := sal.VerifyGoogleIDToken(ctx, tok.AccessToken, targetAudience)
if err != nil {
	log.Fatal(err)
}
fmt.Printf("Token Verified with Audience: %v\n", idt.Audience)
```

## gRPC WithPerRPCCredentials

To use IDTokens with gRPC channels, you can either

A) Acquire credentials and use `NewIDTokenRPCCredential()` (preferable)
   ```golang
   rpcCreds, err := sal.NewIDTokenRPCCredential(ctx, idTokenSource)
   ```
OR

B) apply the `Token()` to [oauth.NewOauthAccess()](https://godoc.org/google.golang.org/grpc/credentials/oauth#NewOauthAccess)
and that directly into [grpc.WithPerRPCCredentials()](https://godoc.org/google.golang.org/grpc#WithPerRPCCredentials)

```golang
import (
	"google.golang.org/grpc/credentials/oauth"
	sal "github.com/salrashid123/oauth2/google"
	...
)
   ...

    scopes := "https://www.googleapis.com/auth/userinfo.email"
    creds, err := google.FindDefaultCredentials(ctx, scopes)
    if err != nil {
        log.Fatal(err)
    }
    idTokenSource, err := sal.IdTokenSource(
        sal.IdTokenConfig{
            Credentials: creds,
            Audiences:   []string{targetAudience},
        },
	)
	
	// if you are using a token directly:	
	/*
	tok, err := idTokenSource.Token()
	if err != nil {
		log.Fatal(err)
	}
	rpcCreds := oauth.NewOauthAccess(tok)
	*/

	rpcCreds, err := sal.NewIDTokenRPCCredential(ctx, idTokenSource)
	if err != nil {
		log.Fatal(err)
	}

    ce, err := credentials.NewClientTLSFromFile("server_crt.pem", "")
    if err != nil {
        log.Fatal(err)
    }

    conn, err := grpc.Dial(address, grpc.WithTransportCredentials(ce), grpc.WithPerRPCCredentials(rpcCreds))
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    c := pb.NewEchoServerClient(conn)
```
---


## Appendix

Follwing snippet is the full combined flow

```golang
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	sal "github.com/salrashid123/oauth2/google"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	targetAudience = "https://your_cloudrunapp.a.run.app"
	url            = "https://your_cloudrunapp.a.run.app"
	jsonCert       = "/path/to/svc.json"
)

func main() {

	ctx := context.Background()

	// For DefaultCredentials
	// export GOOGLE_APPLICATION_CREDENTIALS=/path/to/svc.json

	// For ComputeEngineCredentials

	scopes := "https://www.googleapis.com/auth/userinfo.email"
	creds, err := google.FindDefaultCredentials(ctx, scopes)
	if err != nil {
		log.Fatal(err)
	}

	// For Impersonated Credentials
	/*
		targetPrincipal := "impersonated-account@project.iam.gserviceaccount.com"
		lifetime := 30 * time.Second
		delegates := []string{}
		targetScopes := []string{"https://www.googleapis.com/auth/devstorage.read_only",
			"https://www.googleapis.com/auth/cloud-platform"}
		rootTokenSource, err := google.DefaultTokenSource(ctx,
			"https://www.googleapis.com/auth/iam")
		if err != nil {
			log.Fatal(err)
		}
		tokenSource, err := sal.ImpersonatedTokenSource(
			sal.ImpersonatedTokenConfig{
				RootTokenSource: rootTokenSource,
				TargetPrincipal: targetPrincipal,
				Lifetime:        lifetime,
				Delegates:       delegates,
				TargetScopes:    targetScopes,
			},
		)
		if err != nil {
			log.Fatal(err)
		}

		creds := &google.Credentials{
			TokenSource: tokenSource,
		}
	*/

	// For ServiceAccountCredentials

	/*
		scopes := "https://www.googleapis.com/auth/userinfo.email"
		data, err := ioutil.ReadFile(jsonCert)
		if err != nil {
			log.Fatal(err)
		}
		creds, err := google.CredentialsFromJSON(ctx, data, scopes)
		if err != nil {
			log.Fatal(err)
		}
	*/

	idTokenSource, err := sal.IdTokenSource(
		sal.IdTokenConfig{
			Credentials: creds,
			Audiences:   []string{targetAudience},
		},
	)
	client := &http.Client{
		Transport: &oauth2.Transport{
			Source: idTokenSource,
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response: %v", resp.Status)

	tok, err := idTokenSource.Token()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("IdToken: %v", tok.AccessToken)
	idt, err := sal.VerifyGoogleIDToken(ctx, tok.AccessToken, targetAudience)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Token Verified with Audience: %v\n", idt.Audience)

}
```