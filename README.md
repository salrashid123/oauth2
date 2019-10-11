
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

## TpmTokenSource

>> **WARNING:**  `TpmTokenSource` is highly experimental.  This repo is NOT supported by Google


`google/oauth2/TpmTokenSource` is a variation of [google/oauth2/JWTAccessTokenSourceFromJSON](https://godoc.org/golang.org/x/oauth2/google#JWTAccessTokenSourceFromJSON) where the private key used to sign the JWT is embedded within a [Trusted Platform Module](https://en.wikipedia.org/wiki/Trusted_Platform_Module) (`TPM`).

The private key in raw form _not_ exposed to the filesystem or any process other than through the TPM interface.  This token source uses the TPM interface to `sign` the JWT which is then used to access a Google Cloud API.  


### Usage


1. Create a VM with a `TPM`.  

	For example, create an Google Cloud [Shielded VM](https://cloud.google.com/security/shielded-cloud/shielded-vm).


2. Install `tpm2_tools`.

	This step is only necessary to seal the keys to the TPM.  You can also use [go-tpm](https://github.com/google/go-tpm).

	The installation steps to setup `tpm2_tools` on an Ubuntu ShieldedVM can be found [here](https://gist.github.com/salrashid123/9390fdccbe19eb8aba0f76afadf64e68).

3. Extract the public/private RSA keys.

	Create a Service Account and extract the public private keypairs.  Note the `keyID` and `email` address for this key (its needed later)

	For a `.p12` file, use `openssl`:

	```bash
	openssl pkcs12 -in svc_account.p12  -nocerts -nodes -passin pass:notasecret | openssl rsa -out privkey.pem
	openssl rsa -in privkey.pem -outform PEM -pubout -out public.pem
	```

4. Embed PrivateKey and acquire Persistent Handle

	Transfer the PEM keypairs to the ShieldedVM (you can use any means you like)

	Create a primary object, parent and load the `private.pem` file into the TPM.
	```
	# tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx

	# tpm2_import -C primary.ctx -G rsa -i private.pem -u key.pub -r key.priv

	# tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	```

	At this point, the embedded key is a `transient object` reference via file context.  To make it permanent at handle `0x81010002`:

	```
	# tpm2_evictcontrol -C o -c key.ctx 0x81010002
	persistent-handle: 0x81010002
	action: persisted
	```

	> Note, there are several ways to securely transfer public/private keys between TPM-enabled systems (eg, your laptop where you downloaded the key and a Shielded VM).  That procedure is demonstrated here: [Duplicating Objects](https://github.com/tpm2-software/tpm2-tools/wiki/Duplicating-Objects)


5. Use `TpmTokenSource`

	After the key is embedded, you can *DELETE* any reference to `private.pem` (the now exists protected by the TPM and any access policy you may want to setup).

	The TPM based `TokenSource` can now be used to access a GCP resource.

	```golang
	package main

	import (
		"log"
		"net/http"
		"golang.org/x/oauth2"
		sal "github.com/salrashid123/oauth2/google"
	)

	func main() {

		tpmTokenSource, err := sal.TpmTokenSource(
			sal.TpmTokenConfig{
				Tpm:       "/dev/tpm0",
				Email:     "svcA@your_project.iam.gserviceaccount.com",
				TpmHandle: 0x81010002,
				Audience:  "https://pubsub.googleapis.com/google.pubsub.v1.Publisher",
				KeyId:     "your_service_account_key_id",
			},
		)

		tok, err := tpmTokenSource.Token()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Token: %v", tok.AccessToken)
		client := &http.Client{
			Transport: &oauth2.Transport{
				Source: tpmTokenSource,
			},
		}

		url := "https://pubsub.googleapis.com/v1/projects/your_project/topics"
		resp, err := client.Get(url)
		if err != nil {
			glog.Fatal(err)
		}
		log.Printf("Response: %v", resp.Status)
	}
	```

* TODO, to fix:
* `/dev/tpm0` concurrency from multiple clients.
* Provide example PCR values and policy access.

