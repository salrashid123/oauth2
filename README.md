
# Google OpenID Connect (OIDC), Impersonated, KMS and TPM-based Credential TokenSource in golang

Implementations of various [TokenSource](https://godoc.org/golang.org/x/oauth2#TokenSource) types for use with Google Cloud.  Specifically this repo includes code that allows a developer to acquire and use the following credentials directly and use them with the Google Cloud Client golang library:

* a Google OpenID Connect token
* an `access_token` that is impersonating another ServiceAccount.
* an `access_token` for a serviceAccount where the private key is saved inside a Trusted Platform Module (TPM)
* an `access_token` for a serviceAccount where the private key is saved inside Google Cloud KMS

For OIDC, use this library to easily acquire Google OpenID Connect tokens for use against `Cloud Run`, `Cloud Functions`, `IAP`, `Endpoints` and other services.

For Impersonated Credentials, you will use a source [oauth2/google/Credential](https://godoc.org/golang.org/x/oauth2/google#Credentials) object which as IAM permissions to assume another ServiceAccount and then finally perform operations as that account.

For TPM based Credentials, you will need to embed the ServiceAccount within a Trusted Platform Module.

For KMS based Credentials, you can either embed the ServiceAccounts Private key within KMS or generate a Signing Key on KMS and then associate a service account with it.

For more information, see

**OIDC**
* [Authenticating using Google OpenID Connect Tokens](https://medium.com/google-cloud/authenticating-using-google-openid-connect-tokens-e7675051213b)

**Impersonated**

* [ImpersonatedCredentials](https://github.com/googleapis/google-api-go-client/issues/378)
* [crypto.Signer, crypto.Decrypter for TPM, KMS](https://github.com/salrashid123/signer)

**TPM**
* [TPM2-TSS-Engine hello world and Google Cloud Authentication](https://github.com/salrashid123/tpm2_evp_sign_decrypt)
* [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)
* [Trusted Platform Module (TPM) and Google Cloud KMS based mTLS auth to HashiCorp Vault](https://github.com/salrashid123/vault_mtls_tpm)

**KMS**
* [mTLS with Google Cloud KMS](https://github.com/salrashid123/kms_golang_signer)


And as a complete sideshow: [YubiKey TokenSource](https://github.com/salrashid123/yubikey)

> NOTE: This is NOT supported by Google


## Usage IDToken

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
### Use IDToken in HTTP Client

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

### Token Verification

You can verify a rawToken against google public certifiates and audience

```golang
log.Printf("IdToken: %v", tok.AccessToken)
idt, err := sal.VerifyGoogleIDToken(ctx, tok.AccessToken, targetAudience)
if err != nil {
	log.Fatal(err)
}
fmt.Printf("Token Verified with Audience: %v\n", idt.Audience)
```

### gRPC WithPerRPCCredentials

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

## Usage ImpersonatedCredentials

ImpersonatedCredential is experimental (you'll only find it in this repo for now).  `Impersonated Credentials` allows one service account or user to impersonate another service account.  This API already exits in `google-auth-python` and `google-auth-java`


- Please see 
  - [issue#378](https://github.com/googleapis/google-api-go-client/issues/378)
  - [gcloud --impersonate-service-account](https://cloud.google.com/sdk/gcloud/reference/#--impersonate-service-account)
  - [google-auth-python](https://google-auth.readthedocs.io/en/latest/reference/google.auth.impersonated_credentials.html)
  - [google-auth-java](https://github.com/googleapis/google-auth-library-java/blob/master/oauth2_http/java/com/google/auth/oauth2/ImpersonatedCredentials.java)
  - [Terraform “Assume Role” and service Account impersonation on Google Cloud](https://medium.com/google-cloud/terraform-assume-role-and-service-account-impersonation-on-google-cloud-ffc553863e72)

To use this credential type, you must allow the source credential the `iam/ServiceAccountTokenCreator` role on the target service account.  From there, you bootstrap the source, then the target and finally use the target in a google cloud api.

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


---

## Usage TpmTokenSource

>> **WARNING:**  `TpmTokenSource` is highly experimental.  This repo is NOT supported by Google


`google/oauth2/TpmTokenSource` is a variation of `google/oauth2/JWTAccessTokenSourceFromJSON` where the private key used to sign the JWT is embedded within a [Trusted Platform Module](https://en.wikipedia.org/wiki/Trusted_Platform_Module) (`TPM`).

The private key in raw form _not_ exposed to the filesystem or any process other than through the TPM interface.  This token source uses the TPM interface to `sign` the JWT which is then used to access a Google Cloud API.  


### Usage


1. Create a VM with a `TPM`.  

	For example, create an Google Cloud [Shielded VM](https://cloud.google.com/security/shielded-cloud/shielded-vm).


--> You can either 

* 1) download a Google ServiceAcount's `.p12` file  and embed the private part to the TPM 
or
* 2) Generate a Key _ON THE TPM_ and then import the public part to GCP.

Option 2 has some distinct advantages:  the private key would have never left the TPM at all...it was generated on the TPM....However, you have to be careful to import the public key and associate that public key with the service account.  What that means is you need to employ controls to assure that the public key you will import infact is the one that is associated with the TPM.

Anyway, either do (A) or (B) below (A is easier)

#### A) Import Service Account .p12 to TPM:

1) Download Service account .p12 file

2) Extract public/private keypair
```
    openssl pkcs12 -in svc_account.p12  -nocerts -nodes -passin pass:notasecret | openssl rsa -out private.pem
    openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

3) Embed the key into a TPM 
    install TPM2-Tools
    [https://github.com/tpm2-software/tpm2-tools/blob/master/INSTALL.md](https://github.com/tpm2-software/tpm2-tools/blob/master/INSTALL.md)

```
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

Some Notes:

- there are several ways to securely transfer public/private keys between TPM-enabled systems (eg, your laptop where you downloaded the key and a Shielded VM).  That procedure is demonstrated here: [Duplicating Objects](https://github.com/tpm2-software/tpm2-tools/wiki/Duplicating-Objects)


- You can also use `go-tpm` to make the key persistent if you dont' want to use `tpm2_tools`:
  Run the following utility function which does the same steps as `tpm2_tools` sequence above but instead using [go-tpm](https://github.com/google/go-tpm).
	- [https://github.com/salrashid123/tpm2/blob/master/utils/import_gcp_sa.go](https://github.com/salrashid123/tpm2/blob/master/utils/import_gcp_sa.go)


#### B) Generate key on TPM and export public X509 certificate to GCP

1) Generate Key on TPM and make it persistent
```
tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx
tpm2_create -G rsa -u key.pub -r key.priv -C primary.ctx
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_evictcontrol -C o -c 0x81010002
tpm2_evictcontrol -C o -c key.ctx 0x81010002
tpm2_readpublic -c key.ctx -f PEM -o key.pem
```

2) use the TPM based private key to create an `x509` certificate

You can use [certgen.go](https://raw.githubusercontent.com/salrashid123/signer/master/certgen/certgen.go) here.  Remember to use 

```golang
	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: "/dev/tpm0",
		TpmHandle: 0x81010002,
	})
```

the output should be just `cert.pem` which is infact just the x509 certificate we will use to import
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

#### Post Step A) or B)

4. Use `TpmTokenSource`

	After the key is embedded, you can *DELETE* any reference to `private.pem` (the now exists protected by the TPM and any access policy you may want to setup).

	The TPM based `TokenSource` can now be used to access a GCP resource using either a plain HTTPClient or _native_ GCP library (`google-cloud-pubsub`)!!

	```golang
	package main

	import (
		"log"
		"net/http"
		"cloud.google.com/go/pubsub"		
		"golang.org/x/oauth2"
		sal "github.com/salrashid123/oauth2/google"

		"google.golang.org/api/iterator"
		"google.golang.org/api/option"	
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


		// Using google-cloud library

		ctx := context.Background()
		pubsubClient, err := pubsub.NewClient(ctx, proj, option.WithTokenSource(tpmTokenSource))
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
	}
	```

* TODO, to fix:
* `/dev/tpm0` concurrency from multiple clients.
* Provide example PCR values and policy access.

---

## Usage KmsTokenSource

>> **WARNING:**  `KmsTokenSource` is  experimental.  This repo is NOT supported by Google

Frankly, I'm not sure the feasibility or usecases for this tokenSource but what this allows you to do is use KMS as the keystorage system for a serviceAccount.  The obvious question is that to gain access to the KMS key you must already be authenticated...

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
		salkms.KmsTokenConfig{
			Email: "your_service_account@your_project.iam.gserviceaccount.com",

			ProjectId:  "your_project",
			LocationId: "us-central1",
			KeyRing:    "yourkeyring",
			Key:        "yourkey",
			KeyVersion: "1",

			Audience: "https://pubsub.googleapis.com/google.pubsub.v1.Publisher",
			KeyID:    "yourkeyid",
		},
	)
```

### Usage YubiKeyTokenSource

The `YubikeyTokenSource` can be found in a different repo [https://github.com/salrashid123/yubikey](https://github.com/salrashid123/yubikey)