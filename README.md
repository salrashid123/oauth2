
# The other Google Cloud Credential TokenSources in golang 

Implementations of various [TokenSource](https://godoc.org/golang.org/x/oauth2#TokenSource) types for use with Google Cloud.  Specifically this repo includes code that allows a developer to acquire and use the following credentials directly and use them with the Google Cloud Client golang library:

* **OIDC**:  a Google OpenID Connect token (OIDC) usable for Google Cloud Run, Cloud Functions, Identiy Aware Proxy. (_deprecated; see below_)
* **Impersonated**: `access_token` that is impersonating another ServiceAccount. (_deprecated; see below_)
* **AWS**: `access_token` for a Federated identity or GCP service account that is derived from AWSCredentials
* **OIDC-Federated**: `access_token` for an arbitrary OIDC identity that is exchanged for a GCP Credential
* **TPM**:  `access_token` for a serviceAccount where the private key is saved inside a Trusted Platform Module (TPM)
* **KMS**: `access_token` for a serviceAccount where the private key is saved inside Google Cloud KMS
* **Vault**: `access_token` derived from a [HashiCorp Vault](https://www.vaultproject.io/) TOKEN using [Google Cloud Secrets Engine](https://www.vaultproject.io/docs/secrets/gcp/index.html)
* **Downscoped**: `access_token` that is derived from a provided parent `access_token` where the derived token has redued IAM permissions.
* **External**: `access_token` or `id_token` derived from running an arbitrary external script or binary.
* **STS**: `access_token` or `id_token` derived from interacting with an STS endpoint per [https://www.rfc-editor.org/rfc/rfc8693.html](https://www.rfc-editor.org/rfc/rfc8693.html)
* **DummyTokenSource**: `access_token` or `id_token` This is just a test tokensource that will return a token from a list of provided values. Use this as a test harness

>> **Update 11/1/20** Refactored modules!!!!

Before:
```golang
import (
	sal "github.com/salrashid123/oauth2"
)
```

After

```golang
import (
	aws "github.com/salrashid123/oauth2/aws"
	downscoped "github.com/salrashid123/oauth2/downscoped"
	external "github.com/salrashid123/oauth2/external"
	idtoken "github.com/salrashid123/oauth2/idtoken"
	impersonate "github.com/salrashid123/oauth2/impersonate"
	oidcfederated "github.com/salrashid123/oauth2/oidcfederated"
	kms "github.com/salrashid123/oauth2/kms"
	sts "github.com/salrashid123/oauth2/sts"	
	tpm "github.com/salrashid123/oauth2/tpm"
	vault "github.com/salrashid123/oauth2/vault"
	
)

```

* **Using Impersonated IdTokens or Impersonated Downscoped Credentials**: Combining and chaining credential types

For OIDC, use this library to easily acquire Google OpenID Connect tokens for use against `Cloud Run`, `Cloud Functions`, `IAP`, `Endpoints` and other services.

For Impersonated Credentials, you will use a source [oauth2/google/Credential](https://godoc.org/golang.org/x/oauth2/google#Credentials) object which as IAM permissions to assume another ServiceAccount and then finally perform operations as that account.

For AWS based Credentials, you will exchange an AWS Credential for a Google Credential.

For Federated OIDC based Credentials, you will exchange an arbitrary OIDC provicers Credential for a Google Credential.

For TPM based Credentials, you will need to embed the ServiceAccount within a Trusted Platform Module.

For KMS based Credentials, you can either embed the ServiceAccounts Private key within KMS or generate a Signing Key on KMS and then associate a service account with it.

For Vault based Credentials, you need to first configure the a Vault policy that provides an  `access_token` for Google.

For External or process based Credentials, you must have an external binary or script that the credential type can can execute.  The external process __must__ return JSON with an `access_token`

For more information, see

**OIDC**
* [Authenticating using Google OpenID Connect Tokens](https://medium.com/google-cloud/authenticating-using-google-openid-connect-tokens-e7675051213b)
  > deprecated

**Impersonated**
* [ImpersonatedCredentials](https://github.com/googleapis/google-api-go-client/issues/378)
  > deprecated

**AWS**
* [Accessing resources from AWS](https://cloud.google.com/iam/docs/access-resources-aws)

**Federate OIDC**
* [Accessing resources from OIDC Providers](https://cloud.google.com/iam/docs/access-resources-oidc)

**TPM**
* [TPM2-TSS-Engine hello world and Google Cloud Authentication](https://github.com/salrashid123/tpm2_evp_sign_decrypt)
* [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)
* [Trusted Platform Module (TPM) and Google Cloud KMS based mTLS auth to HashiCorp Vault](https://github.com/salrashid123/vault_mtls_tpm)

**KMS**
* [mTLS with Google Cloud KMS](https://github.com/salrashid123/kms_golang_signer)

**Vault**
* [Vault auth and secrets on GCP](https://github.com/salrashid123/vault_gcp)
* [Vault Kubernetes Auth with Minikube](https://github.com/salrashid123/minikube_vault)

**DownScoped**

And as a complete sideshow: [YubiKey TokenSource](https://github.com/salrashid123/yubikey)

Other than providing `TokenSources` for GCP, most of the "key-based" sources can also be used to sign or decrypt data or even establish TLS connections:
* [crypto.Signer, crypto.Decrypter for TPM, KMS](https://github.com/salrashid123/signer)

**STS**
* [https://www.rfc-editor.org/rfc/rfc8693.html](https://www.rfc-editor.org/rfc/rfc8693.html)
* [STS Server](https://github.com/salrashid123/sts_server)

> NOTE: This is NOT supported by Google


**External**

This credential type allows for a flexible source for a GCP TokenSource.  You get to define how you acquire an access or id_token and incorporate that logic inside the binary that gets executed.  This credential type is inspired by:
* [Kubernetes ExecConfig](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#configuration)
* [AWS Process Credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html)

## Usage IDToken

>> **UPDATE 5/10/20**  use `google.golang.org/api/idtoken` instead of this library

```golang
package main

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"

	"google.golang.org/api/idtoken"
)

const ()


func main() {

	aud := "https://myapp-6w42z6vi3q-uc.a.run.app"
	url := "https://httpbin.org/get"
	jsonCert := "/path/to/svc.json"

	ctx := context.Background()

	ts, err := idtoken.NewTokenSource(ctx, aud, idtoken.WithCredentialsFile(jsonCert))
	if err != nil {
		log.Fatalf("unable to create TokenSource: %v", err)
	}
	tok, err := ts.Token()
	if err != nil {
		log.Fatalf("unable to retrieve Token: %v", err)
	}
	log.Printf("IDToken: %s", tok.AccessToken)
	validTok, err := idtoken.Validate(ctx, tok.AccessToken, aud)
	if err != nil {
		log.Fatalf("token validation failed: %v", err)
	}
	if validTok.Audience != aud {
		log.Fatalf("got %q, want %q", validTok.Audience, aud)
	}

	client, err := idtoken.NewClient(ctx, aud, idtoken.WithCredentialsFile(jsonCert))

	if err != nil {
		log.Fatalf("Could not generate NewClient: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatalf("Error Creating HTTP Request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error making authenticated call: %v", err)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error Reading response body: %v", err)
	}
	bodyString := string(bodyBytes)
	log.Printf("Authenticated Response: %v", bodyString)

}
```

for gRPC:
```golang
	idTokenSource, err := idtoken.NewTokenSource(ctx, *targetAudience, idtoken.WithCredentialsFile(*serviceAccount))
	if err != nil {
		log.Fatalf("unable to create TokenSource: %v", err)
	}
	tok, err := idTokenSource.Token()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("IdToken %s", tok)

	var conn *grpc.ClientConn

	conn, err = grpc.Dial(*address,

		grpc.WithPerRPCCredentials(grpcTokenSource{
			TokenSource: oauth.TokenSource{
				idTokenSource,
			},
		}),
	)
```

Use 

Anyway, I'm leaving the following in for reference:

```golang
import (
	sal "github.com/salrashid123/oauth2/idtoken"
)

idTokenSource, err := sal.IdTokenSource(
	&sal.IdTokenConfig{
		Credentials: creds,
		Audiences:   []string{targetAudience},
	},
)
```

## Usage ImpersonatedCredentials

>> ** UPDATE 9/29/20 ** : googlel.golang.org/api/options supports impersonated credentials directly against GCP APIs so there isn't a reason to use the `ImpersonatedCredentials` provided by this repo


- [https://pkg.go.dev/google.golang.org/api/option#ImpersonateCredentials](https://pkg.go.dev/google.golang.org/api/option#ImpersonateCredentials)


To acquire a raw `access_token` use:

```golang
package main

import (
    "context"
    "log"

    "google.golang.org/api/option"
    "google.golang.org/api/transport"
)

func main() {

    ctx := context.Background()
    creds, err := transport.Creds(ctx,
        option.WithScopes("https://www.googleapis.com/auth/cloud-platform"),
        //option.WithCredentialsFile("/path/to/svc.json"),
        option.ImpersonateCredentials("impersonated-account@fabled-ray-104117.iam.gserviceaccount.com"))
    if err != nil {
        log.Fatalf("%v", err)
    }
    ts := creds.TokenSource

    tok, err := ts.Token()
    if err != nil {
        log.Fatalf("%v", err)
    }
    log.Printf("access_token %v", tok.AccessToken)

}
```

---

The section below for `ImpersonatedCredentials` is deprecated!!!  use the bit above please

ImpersonatedCredential is experimental (you'll only find it in this repo for now).  `Impersonated Credentials` allows one service account or user to impersonate another service account.  This API already exits in `google-auth-python` and `google-auth-java`


- Please see 
  - [issue#378](https://github.com/googleapis/google-api-go-client/issues/378)
  - [gcloud --impersonate-service-account](https://cloud.google.com/sdk/gcloud/reference/#--impersonate-service-account)
  - [google-auth-python](https://google-auth.readthedocs.io/en/latest/reference/google.auth.impersonated_credentials.html)
  - [google-auth-java](https://github.com/googleapis/google-auth-library-java/blob/master/oauth2_http/java/com/google/auth/oauth2/ImpersonatedCredentials.java)
  - [Terraform “Assume Role” and service Account impersonation on Google Cloud](https://medium.com/google-cloud/terraform-assume-role-and-service-account-impersonation-on-google-cloud-ffc553863e72)

To use this credential type, you must allow the source credential the `iam/ServiceAccountTokenCreator` role on the target service account.  From there, you bootstrap the source, then the target and finally use the target in a google cloud api.

There are two modes to using impersonated credentials which based on what apis you intent to invoke:

1. Google Cloud APIS. 
2. Gsuites AdminSDK APIs

You will most likely use this library for GCP apis but if you intend to call Gsuites, the token will eed to utilize [Domain-wide Delegation](https://developers.google.com/admin-sdk/directory/v1/guides/delegation).

### Impersonated with GCP APIs

To use this mode, do not specify the `Subject` field in `ImpersonatedTokenSource` struct.  The resulting tokensource can be used directly in a google cloud client library

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
	&sal.ImpersonatedTokenConfig{
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

### Impersonated Credentials with Domain Wide Delegation

Specify the `Subject` field to enable Domain-Wide Delegation

```golang
package main

import (
	sal "github.com/salrashid123/oauth2/impersonate"
	admin "google.golang.org/api/admin/directory/v1"
)

var (
	serviceAccountFile = "/path/to/svc.json"
	domain  = "yurdomain.com"
	cx      = "yourGsuitesCustomerID"
	subject = "admin@yourdomain.com"
)

func main() {
	ctx := context.Background()
	data, err := ioutil.ReadFile(serviceAccountFile)
	creds, err := google.CredentialsFromJSON(ctx, data, "https://www.googleapis.com/auth/cloud-platform")
	rootTokenSource := creds.TokenSource
	// rootTokenSource, err := google.DefaultTokenSource(ctx,"https://www.googleapis.com/auth/iam")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	targetPrincipal := "domainadminsvc@project.iam.gserviceaccount.com"
	lifetime := 30 * time.Second
	delegates := []string{}
	targetScopes := []string{admin.AdminDirectoryUserScope, admin.AdminDirectoryGroupScope}

	tokenSource, err := sal.ImpersonatedTokenSource(
		&sal.ImpersonatedTokenConfig{
			RootTokenSource: rootTokenSource,
			TargetPrincipal: targetPrincipal,
			Lifetime:        lifetime,
			Delegates:       delegates,
			TargetScopes:    targetScopes,
			Subject:         subject, // Spdcify the subjec for domain-wide-delegation
		},
	)
	adminClient := oauth2.NewClient(ctx, tokenSource)
	adminService, err := admin.New(adminClient)

	usersReport, err := adminService.Users.List().Customer(cx).MaxResults(10).OrderBy("email").Do()
	if err != nil {
		log.Fatal(err)
	}
  ...
  ...
}
```
---

## Usage AWS

This credential type exchanges an AWS Credential for a GCP credential.  The specific flow implemented here is documented at [Accessing resources from AWS](https://cloud.google.com/iam/docs/access-resources-aws) and utilizes
[GCP STS Service](https://cloud.google.com/iam/docs/reference/sts/rest).  The STS Service allows exchanges for AWS,Azure and arbitrary OIDC providers but this credential TokenSource focuses specifically on AWS origins.

- For a more detailed walkthrough of this credential type, see [Exchange AWS Credentials for GCP Credentials using GCP STS Service](https://github.com/salrashid123/gcpcompat-aws)

- For GCP->AWS credential exchange, see [AWSCompat](https://github.com/salrashid123/awscompat)


Sample usage

```golang
package main

import (
	"context"
	"io"
	"log"
	"os"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	sal "github.com/salrashid123/oauth2/aws"
	"google.golang.org/api/option"
)

const (
	gcpBucketName  = "mineral-minutia-820-cab1"
	gcpObjectName  = "foo.txt"
	awsRegion      = "us-east-1"
	awsRoleArn     = "arn:aws:iam::291738886548:role/gcpsts"
	awsSessionName = "mysession"
)

var ()

func main() {

	AWS_ACCESS_KEY_ID := "readacted"
	AWS_SECRET_ACCESS_KEY := "reacted"

	// first just get any credentials
	creds := credentials.NewStaticCredentials(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, "")

	session, err := session.NewSession(&aws.Config{
		Credentials: creds,
	})
	if err != nil {
		log.Fatal(err)
	}

	conf := &aws.Config{
		Region:      aws.String(awsRegion),
		Credentials: creds,
	}
	// print out its identity
	stsService := sts.New(session, conf)
	input := &sts.GetCallerIdentityInput{}
	result, err := stsService.GetCallerIdentity(input)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Original Caller Identity :" + result.GoString())

	// now assume role and bootstrap the new tokens into another credential
	params := &sts.AssumeRoleInput{
		RoleArn:         aws.String(awsRoleArn),
		RoleSessionName: aws.String(awsSessionName),
	}
	resp, err := stsService.AssumeRole(params)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Assumed user Arn: %s", *resp.AssumedRoleUser.Arn)
	log.Printf("Assumed AssumedRoleId: %s", *resp.AssumedRoleUser.AssumedRoleId)
	creds = credentials.NewStaticCredentials(*resp.Credentials.AccessKeyId, *resp.Credentials.SecretAccessKey, *resp.Credentials.SessionToken)

	//creds = credentials.NewStaticCredentials(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, "")

	// use that to print out the new identity specs and exchange for a GCP token
	conf = &aws.Config{
		Region:      aws.String(awsRegion),
		Credentials: creds,
	}
	stsService = sts.New(session, conf)
	input = &sts.GetCallerIdentityInput{}
	result, err = stsService.GetCallerIdentity(input)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("New Caller Identity :" + result.GoString())

	awsTokenSource, err := sal.AWSTokenSource(
		&sal.AwsTokenConfig{
			AwsCredential:        *creds,
			Scope:                "https://www.googleapis.com/auth/cloud-platform",
			TargetResource:       "//iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/aws-pool-1/providers/aws-provider-1",
			Region:               "us-east-1",
			TargetServiceAccount: "aws-federated@mineral-minutia-820.iam.gserviceaccount.com",
		},
	)

	tok, err := awsTokenSource.Token()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("AWS Derived GCP access_token: %s\n", tok.AccessToken)

	// use the AWSTokenSource to call GCS
	ctx := context.Background()
	storageClient, err := storage.NewClient(ctx, option.WithTokenSource(awsTokenSource))
	if err != nil {
		log.Fatalf("Could not create storage Client: %v", err)
	}

	bkt := storageClient.Bucket(gcpBucketName)
	obj := bkt.Object(gcpObjectName)
	r, err := obj.NewReader(ctx)
	if err != nil {
		panic(err)
	}
	defer r.Close()
	if _, err := io.Copy(os.Stdout, r); err != nil {
		panic(err)
	}

}

```
---




## Usage Federated OIDC

This credential type exchanges an arbitrary OIDC Credential for a GCP credential.  The specific flow implemented here is documented at [Accessing resources from an OIDC identity provider](https://cloud.google.com/iam/docs/access-resources-oidcs) and utilizes
[GCP STS Service](https://cloud.google.com/iam/docs/reference/sts/rest).  The STS Service allows exchanges for AWS,Azure and arbitrary OIDC providers but this credential TokenSource focuses specifically on AWS origins.

- For a more detailed walkthrough of this credential type, see [Exchange AWS Credentials for GCP Credentials using GCP STS Service](https://github.com/salrashid123/gcpcompat-oidc)


Sample usage

```golang
package main

import (
	"context"
	"io"
	"log"
	"os"

	"cloud.google.com/go/storage"
	sal "github.com/salrashid123/oauth2/oidcfederated"
	"google.golang.org/api/option"
)

var ()

func main() {

	sourceToken := "eyJhbGci--redacted"
	scope := "https://www.googleapis.com/auth/cloud-platform"
	targetResource := "//iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/oidc-pool-1/providers/oidc-provider-1"
	targetServiceAccount := "oidc-federated@mineral-minutia-820.iam.gserviceaccount.com"
	gcpBucketName := "mineral-minutia-820-cab1"
	gcpObjectName := "foo.txt"

	oTokenSource, err := sal.OIDCFederatedTokenSource(
		&sal.OIDCFederatedTokenConfig{
			SourceTokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: sourceToken,
			}),
			Scope:                scope,
			TargetResource:       targetResource,
			TargetServiceAccount: targetServiceAccount,
			UseIAMToken:          true,
		},
	)

	tok, err := oTokenSource.Token()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("OIDC Derived GCP access_token: %s\n", tok.AccessToken)

	ctx := context.Background()
	storageClient, err := storage.NewClient(ctx, option.WithTokenSource(oTokenSource))
	if err != nil {
		log.Fatalf("Could not create storage Client: %v", err)
	}

	bkt := storageClient.Bucket(gcpBucketName)
	obj := bkt.Object(gcpObjectName)
	r, err := obj.NewReader(ctx)
	if err != nil {
		panic(err)
	}
	defer r.Close()
	if _, err := io.Copy(os.Stdout, r); err != nil {
		panic(err)
	}
```

### Chained Credential usage. 

Note, you can also chain tokensources together where one relies on another for refresh:

In this,  we acquire the oidc federating token from some other source (eg, the exec provider)

```bash
export ENV_TOKEN="eyJHbGc..."
go run main.go
```

where main.go:

```golang

import (
	salext "github.com/salrashid123/oauth2/external"
	sal "github.com/salrashid123/oauth2/oidcfederated"
)


	extTokenSource, err := salext.ExternalTokenSource(
		&salext.ExternalTokenConfig{
			Command: "/usr/bin/echo",
			Env:     []string{},
			Args:    []string{os.ExpandEnv("$ENV_TOKEN")},

			Parser: func(b []byte) (salext.ExternalTokenResponse, error) {
				ret := &salext.ExternalTokenResponse{
					Token:     string(b),
					ExpiresIn: 3600,
					TokenType: "Bearer",
				}
				return *ret, nil
			},
		},
	)

	scope := "https://www.googleapis.com/auth/cloud-platform"
	targetResource := "//iam.googleapis.com/projects/1071284184436/locations/global/workloadIdentityPools/oidc-pool-1/providers/oidc-provider-1"
	targetServiceAccount := "oidc-federated@mineral-minutia-820.iam.gserviceaccount.com"
	gcpBucketName := "mineral-minutia-820-cab1"
	gcpObjectName := "foo.txt"

	oTokenSource, err := sal.OIDCFederatedTokenSource(
		&sal.OIDCFederatedTokenConfig{
			SourceTokenSource: extTokenSource,
			Scope:                scope,
			TargetResource:       targetResource,
			TargetServiceAccount: targetServiceAccount,
			UseIAMToken:          true,
		},
	)

	storageClient, err := storage.NewClient(ctx, option.WithTokenSource(oTokenSource))
```

## Usage TpmTokenSource

>> **WARNING:**  `TpmTokenSource` is highly experimental.  This repo is NOT supported by Google

There are two types of tokens this TokenSource fulfills:

- `JWTAccessToken`
- `Oauth2 access_tokens`.


JWTAccessToken is a custom variation of the standard oauth2 access token that is works with just a certain subset of GCP apis.  What JWTAccessTokens do is locally sign a JWT and send that directly to GCP instead of the the normal oauth2 flows where the local signed token is exchanged for yet another `access_token`.  The flow where the the exchange for a local signed JWT for an access_token is the normal oauth2 flow.  If you use any of the services described [here](https://github.com/googleapis/googleapis/tree/master/google) (eg, PubSub), use JWTAccessToken.  If you use any other serivce (eg GCS), use oauth2.   JWTAccessTokens are enabled by default.  To enable oauth2access tokens, set `UseOauthToken: true`.

For more information, see: [Faster ServiceAccount authentication for Google Cloud Platform APIs](https://medium.com/google-cloud/faster-serviceaccount-authentication-for-google-cloud-platform-apis-f1355abc14b2).

This token source is a variation of `google/oauth2/JWTAccessTokenSourceFromJSON` where the private key used to sign the JWT is embedded within a [Trusted Platform Module](https://en.wikipedia.org/wiki/Trusted_Platform_Module) (`TPM`).

The private key in raw form _not_ exposed to the filesystem or any process other than through the TPM interface.  This token source uses the TPM interface to `sign` the JWT which is then used to access a Google Cloud API.  


### Usage


1. Create a VM with a `TPM`.  

	For example, create an Google Cloud [Shielded VM](https://cloud.google.com/security/shielded-cloud/shielded-vm).

You can either 

* 1) download a Google ServiceAccount's `.p12` file  and embed the private part to the TPM 
or
* 2) Generate a Key _ON THE TPM_ and then import the public part to GCP.

Option 2 has some distinct advantages:  the private key would have never left the TPM at all...it was generated on the TPM....However, you have to be careful to import the public key and associate that public key with the service account.  What that means is you need to employ controls to assure that the public key you will import infact is the one that is associated with the TPM.

Anyway, either do (A) or (B) below.

#### A) Import Service Account .p12 to TPM:

1) Download Service account .p12 file

2) Extract public/private keypair
```
    openssl pkcs12 -in svc_account.p12  -nocerts -nodes -passin pass:notasecret | openssl rsa -out private.pem
    openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

3) Embed the key into a TPM.
   There are several ways to do this:  either install and use `tpm2_tools` or use `go-tpm`.  

   Using `go-tpm` is easier and I've setup a small app to import a service account key:

    a) Run the following utility function which does the same steps as `tpm2_tools` but uses [go-tpm](https://github.com/google/go-tpm).
     - [https://github.com/salrashid123/tpm2/blob/master/utils/import_gcp_sa.go](https://github.com/salrashid123/tpm2/blob/master/utils/import_gcp_sa.go)
  
    b) If you choose to use `tpm2_tools`,  first [install TPM2-Tools](https://github.com/tpm2-software/tpm2-tools/blob/master/INSTALL.md)

    Then setup a primary object on the TPM and import `private.pem` we created earlier

```bash
	tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
	tpm2_import -C primary.ctx -G rsa -i private.pem -u key.pub -r key.prv
	tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
```

    At this point, the embedded key is a `transient object` reference via file context.  To make it permanent at handle `0x81010002`:

```
	# tpm2_evictcontrol -C o -c key.ctx 0x81010002
		persistent-handle: 0x81010002
		action: persisted
```

You may need to stop the tpm broker by running `service tpm2-abrmd stop`

  - there are several ways to securely transfer public/private keys between TPM-enabled systems (eg, your laptop where you downloaded the key and a Shielded VM).  That procedure is demonstrated here: [Duplicating Objects](https://github.com/tpm2-software/tpm2-tools/wiki/Duplicating-Objects)

##### Using go-tpm-tools Key

  Instead of persisting a key to the TPM, you can also use a key file that was persisted using `go-tpm-tools`.  In this mode, you would first use go-tpm-tools to persist a file that represents a  [(*tpm2tools.Key).Handle()](https://godoc.org/github.com/google/go-tpm-tools/tpm2tools#Key) as shown below


  ```golang
  	/// "======= Saving Key Handle========")
	keyHandle := key.Handle()
	keyBytes, err := tpm2.ContextSave(rwc, keyHandle)
	err = ioutil.WriteFile(keyHandleOutputFile, keyBytes, 0644)
  ```
  Once you persist that file, simply specify that handle's filename while initializing the library:

  ```golang
	//  KeyHandleFile (string):  The file that holds the handle to the RSA Key to use.
	//      This file must be generated by go-tpm-tools  a saved context of type `(*tpm2tools.Key).Handle()`
  ```

---

#### B) Generate key on TPM and export public X509 certificate to GCP

1) Generate Key on TPM and make it persistent

The following uses `tpm2_tools` but is pretty straightfoward to do the same steps using `go-tpm` (see the [import_gcp_sa.go](https://github.com/salrashid123/tpm2/blob/master/utils/import_gcp_sa.go) for a sample)

```bash
tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx
tpm2_create -G rsa -u key.pub -r key.priv -C primary.ctx
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_evictcontrol -C o -c 0x81010002
tpm2_evictcontrol -C o -c key.ctx 0x81010002
tpm2_readpublic -c key.ctx -f PEM -o key.pem
```

2) use the TPM based private key to create an `x509` certificate

Google Cloud uses the `x509` format of a key to import.  So far all we've created ins a private RSA key on the TPM.  We need to use it to sing for an x509 cert.  I've written the folling [certgen.go](https://raw.githubusercontent.com/salrashid123/signer/master/certgen/certgen.go) utility to do that.

Remember to modify certgen.go and configure/enable the TPM Credential mode

```golang
	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: "/dev/tpm0",
		TpmHandle: 0x81010002,
	})
```

Once you run certgen.go the output should be just `cert.pem` which is infact just the x509 certificate we will use to import
```
 go run certgen.go 
2019/11/28 00:49:55 Creating public x509
2019/11/28 00:49:55 wrote cert.pem
```

3) Import `x509` cert to GCP for a given service account (note ` YOUR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com` must exist prior to this step)

The following steps are outlined [here](https://cloud.google.com/iam/docs/creating-managing-service-account-keys#uploading).

```
gcloud alpha iam service-accounts keys upload cert.pem  --iam-account YOUR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com
```

Verify...you should see a new certificate.  Note down the `KEY_ID`

```
$ gcloud iam service-accounts keys list --iam-account=YOUR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com
KEY_ID                                    CREATED_AT            EXPIRES_AT
a03f0c4c61864b7fe20db909a3174c6b844f8909  2019-11-27T23:20:16Z  2020-12-31T23:20:16Z
9bd21535c9985ad922c1cf6bb3dbceef0f7375d6  2019-11-28T00:49:55Z  2020-11-27T00:49:55Z <<<<<<< note, this is the pubic cert for the TPM  based key!!
7077c0c9164252fcfb73d8ccbd68f8c97e0ffee6  2019-11-27T23:15:32Z  2021-12-01T05:43:27Z
```

---

#### Post Step A) or B)

4. Use `TpmTokenSource`

	After the key is embedded, you can *DELETE* any reference to `private.pem` (the now exists protected by the TPM and any access policy you may want to setup).

	The TPM based `TokenSource` can now be used to access a GCP resource using either a plain HTTPClient or _native_ GCP library (`google-cloud-pubsub`)!!

	```golang
	package main

	import (
		"context"
		"fmt"
		"log"
		"net/http"

		"cloud.google.com/go/storage"

		"cloud.google.com/go/pubsub"
		sal "github.com/salrashid123/oauth2/tpm"
		"golang.org/x/oauth2"
		"google.golang.org/api/iterator"
		"google.golang.org/api/option"
	)

	var (
		projectId           = "your_project"
		bucketName          = "your_bucket"
		serviceAccountEmail = "your_service_account@your_project.iam.gserviceaccount.com"
		keyId               = "your_key_id"
	)

	func main() {
		ts, err := sal.TpmTokenSource(
			&sal.TpmTokenConfig{
				Tpm:           "/dev/tpm0",
				Email:         serviceAccountEmail,
				TpmHandle:     0x81010002,
				//KeyHandleFile: "/path/tp/keyfile.bin,
				Audience:      "https://pubsub.googleapis.com/google.pubsub.v1.Publisher",
				KeyId:         keyId,
				UseOauthToken: false,
			},
		)

		// tok, err := kmsTokenSource.Token()
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// //log.Printf("Token: %v", tok.AccessToken)

		tok, err := ts.Token()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Token: %v", tok.AccessToken)
		client := &http.Client{
			Transport: &oauth2.Transport{
				Source: ts,
			},
		}

		ctx := context.Background()

		url := fmt.Sprintf("https://pubsub.googleapis.com/v1/projects/%s/topics", projectId)
		resp, err := client.Get(url)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Response: %v", resp.Status)

		// Using google-cloud library

		pubsubClient, err := pubsub.NewClient(ctx, projectId, option.WithTokenSource(ts))
		if err != nil {
			log.Fatalf("Could not create pubsub Client: %v", err)
		}

		it := pubsubClient.Topics(ctx)
		for {
			topic, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				log.Fatalf("Unable to iterate topics %v", err)
			}
			log.Printf("Topic: %s", topic.ID())
		}

		// GCS does not support JWTAccessTokens, the following will only work if UseOauthToken is set to True
		storageClient, err := storage.NewClient(ctx, option.WithTokenSource(ts))
		if err != nil {
			log.Fatal(err)
		}
		sit := storageClient.Buckets(ctx, projectId)
		for {
			battrs, err := sit.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				log.Fatal(err)
			}
			log.Printf(battrs.Name)
		}

	}

	```

* TODO, to fix:
* `/dev/tpm0` concurrency from multiple clients.
* Provide example PCR values and policy access.

---

## Usage KmsTokenSource

>> **WARNING:**  `KmsTokenSource` is  experimental.  This repo is NOT supported by Google

Frankly, I'm not sure the feasibility or usecases for this tokenSource but what this allows you to do is use KMS as the keystorage system for a serviceAccount.  The obvious question is that to gain access to the KMS key you must already be authenticated...


There are two types of tokens this TokenSource fulfills:

- `JWTAccessToken`
- `Oauth2 access_tokens`.

JWTAccessToken is a custom variation of the standard oauth2 access token that is works with just a certain subset of GCP apis.  What JWTAccessTokens do is locally sign a JWT and send that directly to GCP instead of the the normal oauth2 flows where the local signed token is exchanged for yet another `access_token`.  The flow where the the exchange for a local signed JWT for an access_token is the normal oauth2 flow.  If you use any of the services described [here](https://github.com/googleapis/googleapis/tree/master/google) (eg, PubSub), use JWTAccessToken.  If you use any other serivce (eg GCS), use oauth2.  JWTAccessTokens are enabled by default.  To enable oauth2access tokens, set `UseOauthToken: true`.

For more inforamtion, see: [Faster ServiceAccount authentication for Google Cloud Platform APIs](https://medium.com/google-cloud/faster-serviceaccount-authentication-for-google-cloud-platform-apis-f1355abc14b2).


Suppose your credential does not directly grant you access to a resource but rather you must impersonate service account to do so (possibly with also some  [IAM Conditional](https://cloud.google.com/iam/docs/conditions-overview) as well).  You can that bit of impersonation via the impersonation credentials described in this repo but the other way is to acquire access to a service account key somehow.  One way to do that last part is to gain access through KMS API call.

Anyway, there are two ways to embed a ServiceAccount's keys into KMS:

1. Download a serviceAccount Key and the import private key into KMS
2. Generate a a keypair on KMS, download the public certificate and associate the public key with a ServiceAccount.

There are advantages and disadvantages to each ...both of which hinge on on the controls you have in your system/processes.   For (1), you need to make sure the private key ise securely transported.   For (2), make sure the public key is securely transported...


either do (A) or (B) below:

### A. Generate Service Account key on KMS directly

On Google cloud console, go to the KMS screen for a given project, create a new key with the specifications:

* `Asymmetric Sign`
* `2048 bit RSA key PKCS#1 v1.5 padding - SHA256 Digest`
* `"Generate a key for me"`


### B. Generate public/private key and import into KMS

First generate a keypair on your local filesystem.  You can use `openssl` or any CA you own (make sure the key is enabled for digitalSignatures)

For openssl based key, you can generate a CA and keypair as shown [here](https://github.com/salrashid123/gcegrpc/tree/master/certs).

You must also generate an `x509` certificate since we will need that to import into KMS. Once youv'e generated a keypair, follow the [procedure to upload the external key](https://cloud.google.com/iam/docs/creating-managing-service-account-keys#uploading) into KMS.


### Specify IAM permission on the keys to Sign

However you've defined and uploaded the key to KMS, the client credential that is bootstrapped to use this TokenSource must have IAM permissions on that key to use it as `Cloud KMS CryptoKey Signer`. 


Finally, specify the KMS setting as the `KmsTokenConfig` while bootstrapping the credential


```golang
	kmsTokenSource, err := salkms.KmsTokenSource(
		&salkms.KmsTokenConfig{
			Email: "your_service_account@your_project.iam.gserviceaccount.com",

			ProjectId:  "your_project",
			LocationId: "us-central1",
			KeyRing:    "yourkeyring",
			Key:        "yourkey",
			KeyVersion: "1",

			Audience: "https://pubsub.googleapis.com/google.pubsub.v1.Publisher",
			KeyID:    "yourkeyid",
			UseAccessToken: false,
		},
	)
```

## Usage VaultTokenSource

`VaultTokenSource` provides a google cloud credential and tokenSource derived from a `VAULT_TOKEN`.

Vault must be configure first to return a valid `access_token` with appropriate permissions on the resource being accessed on GCP.

For more information, see [Vault access_token for GCP](https://www.vaultproject.io/docs/secrets/gcp/index.html#access-tokens) and specific implementation [here](https://github.com/salrashid123/vault_gcp#accesstoken)

As an example setup, consider a Vault HCL config for Google Secrets capable of listing pubsub topics in a project

- `pubsub.hcl`
```hcl
resource "//cloudresourcemanager.googleapis.com/projects/$PROJECT_ID" {
        roles = ["roles/pubsub.viewer"]
}
```

Then apply a roleset that allows access as `my-token-roleset`:

```bash
vault write gcp/roleset/my-token-roleset   \
   project="$PROJECT_ID"   \
   secret_type="access_token" \
   token_scopes="https://www.googleapis.com/auth/cloud-platform"  \
   bindings=@pubsub.hcl
```

Generate a token for this given policy:

```bash
$ vault token create -policy=my-policy 
Key                  Value
---                  -----
token                s.TsDU8YfeaVbpT9rLiZS7LcVJ
token_accessor       HMkju91OWvR3u9tKJ8jrsYfo
token_duration       768h
token_renewable      true
token_policies       ["default" "my-policy"]
identity_policies    []
policies             ["default" "my-policy"]
```

Verify the new token can return the access_token:

```bash
export VAULT_TOKEN=s.TsDU8YfeaVbpT9rLiZS7LcVJ

vault read gcp/token/my-token-roleset
Key                   Value
---                   -----
expires_at_seconds    1575132122
token                 ya29.c.Kl6zB1_redacted
token_ttl             59m59s
```

```bash
curl  -H "X-Vault-Token: s.TsDU8YfeaVbpT9rLiZS7LcVJ"  --cacert CA_crt.pem   https://vault.domain.com:8200/v1/gcp/token/my-token-roleset
```

Finally, in a golang client, you can initialize it by specifying the `VAULT_TOKEN`, path the the certificate the vault server uses and the address:

```golang
	tokenSource, err := sal.VaultTokenSource(
		&sal.VaultTokenConfig{
			VaultToken:  "s.TsDU8YfeaVbpT9rLiZS7LcVJ",
			VaultPath:   "gcp/token/my-token-roleset",
			VaultCAcert: "CA_crt.pem",
			VaultAddr:   "https://vault.domain.com:8200",
		},
	)
```

## Usage DownScoped

Downscoped credentials allows for exchanging a parent Credential's `access_token` for another `access_token` that has permissions on a limited set of resoruces the parent token originally had.

For example, if the root Credential that represents Alice has access to GCS buckets A, B, C, you can exchange the Alice's credential for another  credential that still identifies Alice but can only be used against Bucket A.

>> Downscoped tokens currently only works for certain GCP resources like GCS resources

For more information, see [https://github.com/salrashid123/downscoped_token](https://github.com/salrashid123/downscoped_token)

The following shows how to exchange a root credential for a downscoped credential that can only be used as `roles/storage.objectViewer` against GCS bucket `bucketName`.   Downscoped tokens are normally used in a tokenbroker/exchange service where you can mint a new restricted token to hand to a client.  The sample below shows how to generate a downscoped token, extract the raw `access_token`, and then inject the raw token in another `TokenSource` (instead of just using the DownScopedToken as the tokensource directly in the storageClient.).

Note the `AvailabilityCondition`:  this parameter lets you define fine-grained controls such as specific resources like GCS objects the downscoped token has permissions over.

```golang
package main

import (
	"context"
	"log"

	"cloud.google.com/go/storage"
	sal "github.com/salrashid123/oauth2/downscoped"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	projectID  = "your_project"
	bucketName = "your_bucket"
)

func main() {

	ctx := context.Background()

	rootTokenSource, err := google.DefaultTokenSource(ctx,
		"https://www.googleapis.com/auth/iam")
	if err != nil {
		log.Fatal(err)
	}

	downScopedTokenSource, err := sal.DownScopedTokenSource(
		&sal.DownScopedTokenConfig{
			RootTokenSource: rootTokenSource,
			DownscopedOptions: sal.DownscopedOptions{
				AccessBoundary: sal.AccessBoundary{
					AccessBoundaryRules: []sal.AccessBoundaryRule{
						sal.AccessBoundaryRule{
							AvailableResource: "//storage.googleapis.com/projects/_/buckets/" + bucketName,
							AvailablePermissions: []string{
								"inRole:roles/storage.objectViewer",
							},
							AvailabilityCondition: sal.AvailabilityCondition{
								Title:      "obj-prefixes",
								Expression: "resource.name.startsWith(\"projects/_/buckets/your_bucket/objects/foo.txt\")",
							},
						},
					},
				},
			},
		},
	)

	// You can use the downscopeToken in the storage client below...but realistically,
	// you would generate a rootToken, downscope it and then provide the new token to another client
	// to use...similar to the bit below where the token itself is used to setup a StaticTokenSource
	tok, err := downScopedTokenSource.Token()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Downscoped Token: %s", tok.AccessToken)

	sts := oauth2.StaticTokenSource(tok)

	storageClient, err := storage.NewClient(ctx, option.WithTokenSource(sts))
	if err != nil {
		log.Fatalf("Could not create storage Client: %v", err)
	}

	bkt := storageClient.Bucket(bucketName)
	obj := bkt.Object("foo.txt")
	r, err := obj.NewReader(ctx)
	if err != nil {
		panic(err)
	}
	defer r.Close()
	if _, err := io.Copy(os.Stdout, r); err != nil {
		panic(err)
	}

}
```

## Usage External

External Credentials leaves the action of acquiring an `access_token` or `id_token` up to an external binary or script that gets called.  By **default**, binary MUST return json with the token and optionally its type "Bearer" and the number of seconds the token will expire in.  

This credential type will simply call that as a subprocess and unmarshall the response json and extract the `Token`.  How the binary gets the token once invoked is left undefined (its upto you).

For example, you can use this in a number of ways by sourcing from environment variables, files or even remote api calls...they will all work as long as the response inclues the JSON struct:

```golang
type externalTokenResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type,omitempty"`
	ExpiresIn int    `json:"expires_in,omitempty"`
}
```

If the external script or binary honors this request, the usage is like

```golang
    // env-var usage
	extTokenSource, err := sal.ExternalTokenSource(
		&sal.ExternalTokenConfig{
			Command: "/usr/bin/echo",
			Env:     []string{"foo=bar"},
			Args: []string{os.ExpandEnv("$ENV_TOKEN")},
		},
	)

    // file
	extTokenSource, err := sal.ExternalTokenSource(
		&sal.ExternalTokenConfig{
			Command: "/usr/bin/cat",
			Env:     []string{"foo=bar"},
			Args:    []string{"file_token.json"},
		},
	)

    // external
	extTokenSource, err := sal.ExternalTokenSource(
		&sal.ExternalTokenConfig{
			Command: "/usr/bin/curl",
			Env:     []string{"foo=bar"},
			Args:    []string{"-s", "https://gist.githubusercontent.com/salrashid123/8a8778aaa5743458b819245def9f8192/raw/bba367db1d18cbd6a99dca3c877d669498e5f742/exec.json"},
		},
	)

	// with parser
	extTokenSource, err := sal.ExternalTokenSource(
		&sal.ExternalTokenConfig{
			Command: "gcloud",
			Env:     []string{"foo=bar"},
			Args:    []string{"auth", "print-access-token"},
			Parser: func(b []byte) (sal.ExternalTokenResponse, error) {
				ret := &sal.ExternalTokenResponse{
					Token:     string(b),
					ExpiresIn: 3600,
					TokenType: "Bearer",
				}
				return *ret, nil
			},
		},
	)	
	// or.. kerberos, certificate, saml, etc

	if err != nil {
		log.Fatal(err)
	}

	// then..
	tok, err := extTokenSource.Token()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("External Token: %s\n", tok.AccessToken)
	fmt.Printf("Token Valid: %t\n", tok.Valid())
```

You can also apply a custom parser such that arbitrary responses can also be used.  For example, if the subprocess command returns a plain text string with just the access token (eg `gcloud auth print-access-token`), you can "just use" that token directly by specifying a Parser to handle the response.  In the example below, gcloud command returns a plain text string and not a JSON so a Parser will need to read the value as a string `Token:     string(b),` and set some default values

```golang
	extTokenSource, err := sal.ExternalTokenSource(
		&sal.ExternalTokenConfig{
			Command: "gcloud",
			Env:     []string{"foo=bar"},
			Args:    []string{"auth", "print-access-token"},
			Parser: func(b []byte) (sal.ExternalTokenResponse, error) {
				ret := &sal.ExternalTokenResponse{
					Token:     string(b),
					ExpiresIn: 3600,
					TokenType: "Bearer",
				}
				return *ret, nil
			},
		},
	)
```

The distinct advantage of using this encapsulated within a `TokenSource` is that the refresh and management all happens within the context of the caller.  That is, you could use the 'file based' token source by reading it in directly, then manually making a TokenSource and then using that TokenSource within a GCP library like Cloud Storage.  However, when that static token expires, it is irrecoverable and the GCS client will fail even if a "new file with a new token" is available.  In contrast, if it is included within a TokenSource like this, the refresh is managed internally and the calling api library (eg, GCS) would not throw any exceptions.


## Usage STS

To use this tokensource, you need to have any token you can echange with an STS server.  You'll also need an STS server.

For a sample server, see:

- [https://tools.ietf.org/html/rfc8693](https://tools.ietf.org/html/rfc8693)
- [https://github.com/salrashid123/sts_server](https://github.com/salrashid123/sts_server)

To use this, you need to bootstrap a TokenSource...In the example below, the root token is `rootTS` that includes
some arbitrary value.  That token is sent to n STS server at `https://stsserver-6w42z6vi3q-uc.a.run.app/token` which
validate the rootToken secret, then returns back yet another Token that is wrapped into a new TokenSource.  The
new tokensrouce can be used in an arbitrary client...not necessarily for a Google service

```golang
	// caCert, err := ioutil.ReadFile("google_root_ca.pem")
	// caCertPool := x509.NewCertPool()
	// caCertPool.AppendCertsFromPEM(caCert)

	// tlsConfig := &tls.Config{
	// 	ServerName: "server.domain.com",
	// 	RootCAs:    caCertPool,
	// }
	client := &http.Client{}

	rootTS, err := dummytokensource.NewDummyTokenSource(&testts.DummyTokenConfig{
		TokenValues:             []string{"iamtheeggman", "iamthewalrus"},
		RotationIntervalSeconds: 10,
	})
	stsTokenSource, _ := sal.STSTokenSource(
		&sal.STSTokenConfig{
			TokenExchangeServiceURI: "https://stsserver-6w42z6vi3q-uc.a.run.app/token",
			Resource:                "localhost",
			Audience:                "localhost",
			Scope:                   "https://www.googleapis.com/auth/cloud-platform",
			SubjectTokenSource:      rootTS,
			SubjectTokenType:        "urn:ietf:params:oauth:token-type:access_token",
			RequestedTokenType:      "urn:ietf:params:oauth:token-type:access_token",
			// TLSConfig:          *tlsConfig,
		},
	)

	client = oauth2.NewClient(context.TODO(), stsTokenSource)
	resp, err := client.Get("http://localhost:8080/")
	if err != nil {
		log.Printf("Error creating client %v", err)
		return
	}
```

## Usage DummyTokenSource

To use this tokensource, just specify the list of tokens to return and the interval to rotate/expire the current one.

```golang
import (
		testts "github.com/salrashid123/oauth2/dummy"
)

	myts, err := testts.NewDummyTokenSource(&testts.DummyTokenConfig{
		TokenValues:             []string{"iamtheeggman", "iamthewalrus"},
		RotationIntervalSeconds: 10,
	})
```

## Using Impersonated IdTokens or Impersonated Downscoped Credentials

You can also mix and match several credential types together in a chain by applying one credential as a source to another.

For example, to chain

* [doens not work anymore :(  Impersonated Credentials --> ID Token, see [impersonated->idtoken](https://gist.github.com/salrashid123/fd3236d7405748120089d2c93f71faac)
* Impersonated Credentials --> Downscope, see [impersonated->downscoped](https://gist.github.com/salrashid123/c894e3029be76243761709cf834c7ed1)


### Usage YubiKeyTokenSource

The `YubikeyTokenSource` can be found in a different repo [https://github.com/salrashid123/yubikey](https://github.com/salrashid123/yubikey)