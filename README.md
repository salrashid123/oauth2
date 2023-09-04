
# The other Google Cloud Credential TokenSources in golang 

Implementations of various [TokenSource](https://godoc.org/golang.org/x/oauth2#TokenSource) types for use with Google Cloud.  Specifically this repo includes code that allows a developer to acquire and use the following credentials directly and use them with the Google Cloud Client golang library:

* **AWS**: `access_token` for a Federated identity or GCP service account that is derived from AWSCredentials
* **OIDC-Federated**: `access_token` for an arbitrary OIDC identity that is exchanged for a GCP Credential
* **TPM**:  `access_token` for a serviceAccount where the private key is saved inside a Trusted Platform Module (TPM)
* **KMS**: `access_token` for a serviceAccount where the private key is saved inside Google Cloud KMS
* **Vault**: `access_token` derived from a [HashiCorp Vault](https://www.vaultproject.io/) TOKEN using [Google Cloud Secrets Engine](https://www.vaultproject.io/docs/secrets/gcp/index.html)
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
	oidcfederated "github.com/salrashid123/oauth2/oidcfederated"
	kms "github.com/salrashid123/oauth2/kms"
	tpm "github.com/salrashid123/oauth2/tpm"
	vault "github.com/salrashid123/oauth2/vault"	
)

```



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



> NOTE: This is NOT supported by Google



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


for a simple end-to-end, see [Trusted Platform Module (TPM) based GCP Service Account Key](https://gist.github.com/salrashid123/865ea715881cb7c020da987b08c3881a)

>> **WARNING:**  `TpmTokenSource` is experimental.  This repo is NOT supported by Google


There are two types of tokens this TokenSource fulfills:

- `JWTAccessToken`
- `Oauth2 access_tokens`.


### Usage


1. Create a VM with a `TPM`.  

	For example, create an Google Cloud [Shielded VM](https://cloud.google.com/security/shielded-cloud/shielded-vm).

You can 

* A) download a Google ServiceAccount's `json` file  and embed the private part to the TPM 
or
* B) Generate a Key _ON THE TPM_ and then import the public part to GCP.
or
* C) remote seal the service accounts RSA Private key remotely, encrypt it with the remote TPM's Endorsement Key and load it


#### A) Import Service Account json to TPM:

1) Download Service account json file

2) Extract public/private keypair

```bash
cat svc-account.json | jq -r '.private_key' > /tmp/f.json
openssl rsa -out /tmp/key_rsa.pem -traditional -in /tmp/f.json
openssl rsa -in /tmp/key_rsa.pem -outform PEM -pubout -out public.pem
```

3) Embed the key into a TPM

   There are several ways to do this:  either install and use `tpm2_tools` or use `go-tpm`.  

   The following will load the RSA key and make it persistent at a specific handle 
 
   Using `go-tpm` is easier and I've setup a small app to import a service account key:

    a) Run the following utility function which does the same steps as `tpm2_tools` steps below
   
     - [Importing an external key and load it ot the TPM]([https://github.com/salrashid123/tpm2/blob/master/utils/import_gcp_sa.go](https://github.com/salrashid123/tpm2/tree/master/tpm_import_external_rsa))
  
    b) If you choose to use `tpm2_tools`,  first [install TPM2-Tools](https://github.com/tpm2-software/tpm2-tools/blob/master/INSTALL.md)

    Then setup a primary object on the TPM and import `private.pem` we created earlier

```bash
	tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
	tpm2_import -C primary.ctx -G rsa -i /tmp/key_rsa.pem -u key.pub -r key.prv
	tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
```

At this point, the embedded key is a `transient object` reference via file context.  To make it permanent at handle `0x81010002`

```bash
tpm2_evictcontrol -C o -c key.ctx 0x81010002
		persistent-handle: 0x81010002
		action: persisted
```

---

#### B) Generate key on TPM and export public X509 certificate to GCP

1) Generate Key on TPM and make it persistent

The following uses `tpm2_tools` but is pretty straightfoward to do the same steps using `go-tpm`

```bash
tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx
tpm2_create -G rsa -u key.pub -r key.priv -C primary.ctx
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_evictcontrol -C o -c 0x81010002
tpm2_evictcontrol -C o -c key.ctx 0x81010002
tpm2_readpublic -c 0x81010002 -f PEM -o key.pem
```

2) use the TPM based private key to create an `x509` certificate

Google Cloud uses the `x509` format of a key to import.  So far all we've created ins a private RSA key on the TPM.  We need to use it to sing for an x509 cert.  I've written the following [certgen.go](https://github.com/salrashid123/signer/blob/master/util/certgen/certgen.go) utility to do that.

Remember to modify certgen.go and configure/enable the TPM Credential mode (where `persistentHandle in this example is `0x81010002`)

```golang
    rwc, err := tpm2.OpenTPM(*tpmPath)
	k, err := client.LoadCachedKey(rwc, tpmutil.Handle(*persistentHandle), nil)
	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: rwc,
		Key:       k,
	})

```

Once you run certgen.go the output should be just `cert.pem` which is infact just the x509 certificate we will use to import

```bash
 go run certgen.go 
		2019/11/28 00:49:55 Creating public x509
		2019/11/28 00:49:55 wrote cert.pem
```

3) Import `x509` cert to GCP for a given service account (note ` YOUR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com` must exist prior to this step)

The following steps are outlined [here](https://cloud.google.com/iam/docs/creating-managing-service-account-keys#uploading).

```bash
gcloud alpha iam service-accounts keys upload cert.pem  --iam-account YOUR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com
```

Verify...you should see a new certificate.  Note down the `KEY_ID`

```bash
$ gcloud iam service-accounts keys list --iam-account=YOUR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com
		KEY_ID                                    CREATED_AT            EXPIRES_AT
		a03f0c4c61864b7fe20db909a3174c6b844f8909  2019-11-27T23:20:16Z  2020-12-31T23:20:16Z
		9bd21535c9985ad922c1cf6bb3dbceef0f7375d6  2019-11-28T00:49:55Z  2020-11-27T00:49:55Z <<<<<<< note, this is the pubic cert for the TPM  based key!!
		7077c0c9164252fcfb73d8ccbd68f8c97e0ffee6  2019-11-27T23:15:32Z  2021-12-01T05:43:27Z
```

#### C)  Remotely transferring an encrypted RSA key into the TPM 

If you already have a list of EKCerts you know for sure trust and want to distribute keys to, then its pretty easy:  just use `client.ImportSigningKey()` api from `go-tpm-tools` to seal data to an EK, then transmit the encrypted key to each VM.

Each VM will then load it into non-volatile area of the TPM and you can use it to sign as much as you want.

for detaled walkthrough of that, see 

[Importing ServiceAccount Credentials to TPMs](https://gist.github.com/salrashid123/9e4a0328fd8c84374ace78c76a1e34cb)

note, there are also several ways to securely transfer public/private keys between TPM-enabled systems (eg, your laptop where you downloaded the key and a Shielded VM).  That procedure is demonstrated here: [Duplicating Objects](https://github.com/tpm2-software/tpm2-tools/wiki/Duplicating-Objects)


---

#### Post Step A) B) or C)

4. Use `TpmTokenSource`

	After the key is embedded, you can *DELETE* any reference to `private.pem` (the now exists protected by the TPM and any access policy you may want to setup).

	The TPM based `TokenSource` can now be used to access a GCP resource using either a plain HTTPClient or _native_ GCP library (`google-cloud-pubsub`)!!

```
	 go run main.go --projectId=core-eso \
	   --persistentHandle=0x81008000 \
	    --serviceAccountEmail="tpm-sa@core-eso.iam.gserviceaccount.com" \
		--bucketName=core-eso-bucket --keyId=71b831d149e4667809644840cda2e7e0080035d5
```

```golang
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"cloud.google.com/go/storage"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	sal "github.com/salrashid123/oauth2/tpm"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

var (
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81008000, "Handle value")

	projectId           = flag.String("projectId", "core-eso", "ProjectID")
	serviceAccountEmail = flag.String("serviceAccountEmail", "tpm-sa@core-eso.iam.gserviceaccount.com", "Email of the serviceaccount")
	bucketName          = flag.String("bucketName", "core-eso-bucket", "Bucket name")
	keyId               = flag.String("keyId", "71b831d149e4667809644840cda2e7e0080035d5", "GCP PRivate key id assigned.")

	flush       = flag.Bool("flush", false, "flushHandles")
	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
		"none":      {},
	}
)


func main() {

	flag.Parse()

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
		return
	}
	defer rwc.Close()

	if *flush {
		totalHandles := 0
		for _, handleType := range handleNames["all"] {
			handles, err := client.Handles(rwc, handleType)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error getting handles", *tpmPath, err)
				os.Exit(1)
			}
			for _, handle := range handles {
				if err = tpm2.FlushContext(rwc, handle); err != nil {
					fmt.Fprintf(os.Stderr, "Error flushing handle 0x%x: %v\n", handle, err)
					os.Exit(1)
				}
				fmt.Printf("Handle 0x%x flushed\n", handle)
				totalHandles++
			}
		}
	}
	k, err := client.LoadCachedKey(rwc, tpmutil.Handle(*persistentHandle), nil)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error closing tpm%v\n", err)
		os.Exit(1)
	}

	ts, err := sal.TpmTokenSource(&sal.TpmTokenConfig{
		TPMDevice: rwc,
		Key:       k,
		Email:     *serviceAccountEmail,
		//KeyId:         *keyId,
		UseOauthToken: true,
	})

	tok, err := ts.Token()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Token: %v", tok.AccessToken)

	ctx := context.Background()

	// GCS does not support JWTAccessTokens, the following will only work if UseOauthToken is set to True
	storageClient, err := storage.NewClient(ctx, option.WithTokenSource(ts))
	if err != nil {
		log.Fatal(err)
	}
	sit := storageClient.Buckets(ctx, *projectId)
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

### Usage YubiKeyTokenSource

The `YubikeyTokenSource` can be found in a different repo [https://github.com/salrashid123/yubikey](https://github.com/salrashid123/yubikey)
