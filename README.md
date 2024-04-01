
# The other Google Cloud Credential TokenSources in golang 

Implementations of various [TokenSource](https://godoc.org/golang.org/x/oauth2#TokenSource) types for use with Google Cloud.  Specifically this repo includes code that allows a developer to acquire and use the following credentials directly and use them with the Google Cloud Client golang library:

* **TPM**:  `access_token` for a serviceAccount where the private key is saved inside a Trusted Platform Module (TPM)
* **Vault**: `access_token` derived from a [HashiCorp Vault](https://www.vaultproject.io/) TOKEN using [Google Cloud Secrets Engine](https://www.vaultproject.io/docs/secrets/gcp/index.html)
* **AWS**:  `access_token` for a Federated identity or GCP service account that is _derived_ from AWSCredentials

**TPM**

  * [TPM2-TSS-Engine hello world and Google Cloud Authentication](https://github.com/salrashid123/tpm2_evp_sign_decrypt)
  * [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)
  * [Trusted Platform Module (TPM) and Google Cloud KMS based mTLS auth to HashiCorp Vault](https://github.com/salrashid123/vault_mtls_tpm)

**Vault**
  * [Google Credentials from VAULT_TOKEN](https://github.com/salrashid123/vault_gcp_credentials)
  * [Vault auth and secrets on GCP](https://github.com/salrashid123/vault_gcp)
  * [Vault Kubernetes Auth with Minikube](https://github.com/salrashid123/minikube_vault)

**AWS**
  * [Accessing resources from AWS](https://cloud.google.com/iam/docs/access-resources-aws)


> NOTE: This is NOT supported by Google

---

## Usage TpmTokenSource


for a simple end-to-end, see [Trusted Platform Module (TPM) based GCP Service Account Key](https://gist.github.com/salrashid123/865ea715881cb7c020da987b08c3881a)


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
   
     - [Importing an external key and load it ot the TPM](https://github.com/salrashid123/tpm2/tree/master/tpm_import_external_rsa)
  
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

Once you run `certgen.go` the output should be just `cert.pem` which is infact just the x509 certificate we will use to import

```bash
 go run certgen.go 
		2019/11/28 00:49:55 Creating public x509
		2019/11/28 00:49:55 wrote cert.pem
```

3) Import `x509` cert to GCP for a given service account (note ` YOUR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com` must exist prior to this step)

The following steps are outlined [here](https://cloud.google.com/iam/docs/creating-managing-service-account-keys#uploading).

```bash
gcloud  iam service-accounts keys upload cert.pem  --iam-account YOUR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com
```

Verify...you should see a new certificate.  Note down the `KEY_ID`

```bash
$ gcloud iam service-accounts keys list --iam-account=YOUR_SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com
		KEY_ID                                    CREATED_AT            EXPIRES_AT
		a03f0c4c61864b7fe20db909a3174c6b844f8909  2019-11-27T23:20:16Z  2020-12-31T23:20:16Z
		9bd21535c9985ad922c1cf6bb3dbceef0f7375d6  2019-11-28T00:49:55Z  2020-11-27T00:49:55Z <<<<<<< note, this is the pubic cert for the TPM  based key!!
		7077c0c9164252fcfb73d8ccbd68f8c97e0ffee6  2019-11-27T23:15:32Z  2021-12-01T05:43:27Z
```

Detailed end-to-end steps also detailed [here](https://gist.github.com/salrashid123/865ea715881cb7c020da987b08c3881a)

#### C)  Remotely transferring an encrypted RSA key into the TPM 

If you already have a list of EKCerts you know for sure trust and want to distribute keys to, then its pretty easy:  just use `client.ImportSigningKey()` api from `go-tpm-tools` to seal data to an EK, then transmit the encrypted key to each VM.

Each VM will then load it into non-volatile area of the TPM and you can use it to sign as much as you want.

for detailed walkthrough of that, see 

[Importing ServiceAccount Credentials to TPMs](https://gist.github.com/salrashid123/9e4a0328fd8c84374ace78c76a1e34cb)

note, there are also several ways to securely transfer public/private keys between TPM-enabled systems (eg, your laptop where you downloaded the key and a Shielded VM).  That procedure is demonstrated here: [Duplicating Objects](https://github.com/tpm2-software/tpm2-tools/wiki/Duplicating-Objects)


---

#### Post Step A) B) or C)

4. Use `TpmTokenSource`

	After the key is embedded, you can *DELETE* any reference to `private.pem` (the now exists protected by the TPM and any access policy you may want to setup).

	The TPM based `TokenSource` can now be used to access a GCP resource using either a plain HTTPClient or _native_ GCP library (`google-cloud-pubsub`)!!

```bash
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
		TPMDevice: rwc,   // tpm is managed by the caller
		//TPMPath: "/dev/tpm0",  // tpm is managed by the library
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
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go/aws/credentials"
	sal "github.com/salrashid123/oauth2/aws"
	"google.golang.org/api/option"
)

const (
	gcpBucketName  = "core-eso-bucket"
	gcpObjectName  = "foo.txt"
	awsRegion      = "us-east-1"
	awsRoleArn     = "arn:aws:iam::291738886548:role/gcpsts"
	awsSessionName = "mysession"
)

var ()

func main() {

	// with static credentials
	AWS_ACCESS_KEY_ID := "AKIAUH3H6EGKBUQOZ2DT"
	 AWS_SECRET_ACCESS_KEY := "lIs1yCocQYKX+ertfrsS--redacted"
	creds := credentials.NewStaticCredentials(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, "")

	// with env vars
	// export AWS_ACCESS_KEY_ID := "AKIAUH3H6EGKBUQOZ2DT"
	// export AWS_SECRET_ACCESS_KEY := "lIs1yCocQYKX+ertfrsS--redacted"
	// export AWS_REGION=us-east-1
	// creds := credentials.NewEnvCredentials()

	// with AWS_WEB_IDENTITY_TOKEN_FILE (eg ecs)

	// body, err := ioutil.ReadFile("/tmp/aws.txt")
	// if err != nil {
	// 	log.Fatalf("unable to read file: %v", err)
	// }

	// svc := sts.New(session.New())
	// input := &sts.AssumeRoleWithWebIdentityInput{
	// 	WebIdentityToken: aws.String(string(body)),
	// 	RoleArn:          aws.String("arn:aws:iam::291738886548:role/cicps3role"),
	// 	RoleSessionName:  aws.String(awsSessionName),
	// }
	// resp, err := svc.AssumeRoleWithWebIdentity(input)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// creds := credentials.NewStaticCredentials(*resp.Credentials.AccessKeyId, *resp.Credentials.SecretAccessKey, *resp.Credentials.SessionToken)

	// or transparently with
	// export AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/aws.txt
	// export AWS_ROLE_ARN="arn:aws:iam::291738886548:role/cicps3role"
	// export AWS_ROLE_SESSION_NAME=mysession
	// export AWS_REGION=us-east-1

	// cfg, err := config.LoadDefaultConfig(context.TODO())
	// if err != nil {
	// 	log.Fatalf("failed to load configuration, %v", err)
	// }

	// awsCreds, err := cfg.Credentials.Retrieve(context.TODO())
	// if err != nil {
	// 	log.Fatalf("failed to load creds, %v", err)
	// }
	// creds := credentials.NewStaticCredentials(awsCreds.AccessKeyID, awsCreds.SecretAccessKey, awsCreds.SessionToken)

	awsTokenSource, err := sal.AWSTokenSource(
		&sal.AwsTokenConfig{
			AwsCredential:        *creds,
			Scope:                "https://www.googleapis.com/auth/cloud-platform",
			TargetResource:       "//iam.googleapis.com/projects/995081019036/locations/global/workloadIdentityPools/aws-pool-1/providers/aws-provider-1",
			Region:               "us-east-1",
			TargetServiceAccount: "aws-federated@core-eso.iam.gserviceaccount.com",
			UseIAMToken:          true,
		},
	)

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

## Usage VaultTokenSource

`VaultTokenSource` provides a google cloud credential and tokenSource derived from a `VAULT_TOKEN`.

Vault must be configure first to return a valid `access_token` with appropriate permissions on the resource being accessed on GCP.

For more information, see [Vault access_token for GCP](https://www.vaultproject.io/docs/secrets/gcp/index.html#access-tokens) and specific implementation [here](https://github.com/salrashid123/vault_gcp#accesstoken)


For an end-to-end example, see

* [Google Credentials from VAULT_TOKEN](https://github.com/salrashid123/vault_gcp_credentials)


## Usage STS

To use this tokensource, you need to have any token you can exchange with an STS server. Basically, you exchange one token for a google oauth2 token via an STS server

This tokensource was moved to:

- [https://github.com/salrashid123/sts](https://github.com/salrashid123/sts)

also see:

- [https://tools.ietf.org/html/rfc8693](https://tools.ietf.org/html/rfc8693)
- [https://github.com/salrashid123/sts_server](https://github.com/salrashid123/sts_server)



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
