
# TPM based Google Cloud Credential Access Token 

Implementations of [TokenSource](https://godoc.org/golang.org/x/oauth2#TokenSource) for use with Google Cloud where the private key is encoded into a TPM. 

* **TPM**:  `access_token` or an `id_token` for a serviceAccount where the private key is saved inside a Trusted Platform Module (TPM)
  *  `TPM based key --> GCP AccessToken`

> NOTE: This is NOT supported by Google


*BREAKING CHANGE*

* removed AWS oauth provider (nobody's using it AFAIK)
* refactor it to top-level package `github.com/salrashid123/oauth2/v3` for simplicity


```golang
package main

import (
	"cloud.google.com/go/storage"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	sal "github.com/salrashid123/oauth2/v3"
)

func main() {

	rwc, err := tpmutil.OpenTPM("/dev/tpmrm0")

	ts, err := sal.TpmTokenSource(&sal.TpmTokenConfig{
		TPMDevice: rwc,
		Handle:    tpm2.TPMHandle(*persistentHandle), // persistent handle
		Email:     *serviceAccountEmail,
	})

	tok, err := ts.Token()

	log.Printf("Token: %v", tok.AccessToken)

	ctx := context.Background()

	storageClient, err := storage.NewClient(ctx, option.WithTokenSource(ts))

	sit := storageClient.Buckets(ctx, *projectId)
	for {
		battrs, err := sit.Next()
		if err == iterator.Done {
			break
		}
		log.Printf(battrs.Name)
	}
}
```

---

## Additional References

**TPM**

  * [TPM Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-tpm)
  * [PKCS-11 Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-pkcs)
  * [golang-jwt for Trusted Platform Module (TPM)](https://github.com/salrashid123/golang-jwt-tpm)
  * [TPM2-TSS-Engine hello world and Google Cloud Authentication](https://github.com/salrashid123/tpm2_evp_sign_decrypt)
  * [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)

---

## Usage TpmTokenSource


This library provides the option of returning two different types of access tokens:

*  `JWTAccessToken with scopes` (default)
or
* `Oauth2 AccessTokens`


Both will work with GCP apis and its preferable to use the jwt access token since it does not involve a round trip to GCP services.  For more information, see 

* [AIP 4111: Self-signed JWT](https://google.aip.dev/auth/4111)


You can enable the oauth2 flow by setting the `UseOauthToken` config value to true


### Usage


1. Create a VM with a `TPM`.  

	For example, create an Google Cloud [Shielded VM](https://cloud.google.com/security/shielded-cloud/shielded-vm).

From there you have several options on how to associate a key on a TPM with a service account.  You can either do

* **[A]** download a Google ServiceAccount's `json` file  and embed the private part to the TPM 

or

* **[B]** Generate a Key _ON THE TPM_ and then import the public part to GCP.

or

* **[C]**) remote seal the service accounts RSA Private key remotely, encrypt it with the remote TPM's Endorsement Key and load it

---

#### [A] Import Service Account json to TPM:

1) Download Service account json file

2) Extract public/private keypair

```bash
cat svc-account.json | jq -r '.private_key' > /tmp/f.json
openssl rsa -out /tmp/key_rsa.pem -traditional -in /tmp/f.json
openssl rsa -in /tmp/key_rsa.pem -outform PEM -pubout -out public.pem
```

3) Embed the key into a TPM

   There are several ways to do this:  either install and use `tpm2_tools` or use `go-tpm`.  

   The following will load the RSA key and make it persistent at a specific handle and create a PEM encoded private key thats only usable by the TPM.
  
   If you choose to use `tpm2_tools`,  first [install TPM2-Tools](https://github.com/tpm2-software/tpm2-tools/blob/master/INSTALL.md)

   Then setup a primary object on the TPM and import `private.pem` we created earlier

```bash
## if you want to use a software TPM, 
# rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
# sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear
## then specify "127.0.0.1:2321"  as the TPM device path in the examples, export the following var
# export TPM2TOOLS_TCTI="swtpm:port=2321"

## note  the primary can be the "H2" profile from https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent
## see https://gist.github.com/salrashid123/9822b151ebb66f4083c5f71fd4cdbe40
### otherwise with defaults
#tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat
# tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" 
tpm2_import -C primary.ctx -G rsa2048:rsassa:null -g sha256 -i /tmp/key_rsa.pem -u key.pub -r key.prv
tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx

## to make persistent
# tpm2_evictcontrol -C o -c key.ctx 0x81010002

## to create a PEM file
tpm2_encodeobject -C primary.ctx -u key.pub -r key.prv -o svc_account_tpm.pem
```

The encodeobject create a PEM file with the public/private TPM parts encoded into it.  The PEM file looks like this

```bash
$ cat svc_account_tpm.pem 
-----BEGIN TSS2 PRIVATE KEY-----
MIHyBgZngQUKAQMCBQCAAAAABDIAMAAIAAsABABSAAAABQALACBnst0f8mx8m2Xk
2HsQgLV1odcQFhMh85q0d9IzIwRMKASBrACqACB1+h8NZjM64tOkWsjeORqY0kFN
VqIP6LgJfZ4jJTkgUwAQ0WyWLEfxAeFJLiNFwp9mjO/LLyQ2MaewE0W5Mdsoa/7p
KVaIFlT7upOmB5/i2MxWPT4Du8EYHI+nlhb7ZHjhuItYpmbK1EhHIeaWHduXiZvc
ObcXb7YqFF53uD1qgaa0R8/6bROu1qZjuFLFOekOTQ4X/8Rs4ty7w1tsjZbIKZqL
urvq+J0=
-----END TSS2 PRIVATE KEY-----
```

Also see [Importing an external key and load it ot the TPM](https://github.com/salrashid123/tpm2/tree/master/rsa_import)

---

#### [B] Generate key on TPM and export public X509 certificate to GCP

1) Generate Key on TPM and make it persistent

The following uses `tpm2_tools` but is pretty straightfoward to do the same steps using `go-tpm`

```bash
## create an H2 primary
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
   -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

## create an rsa key, then load and evit it
tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
# tpm2_evictcontrol -C o -c key.ctx 0x81010002

### extract the publicKey PEM
tpm2_readpublic -c key.ctx -f PEM -o svc_account_tpm_pub.pem
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

## convert the entire TPM public/private key to PEM
## you may need to add a -p if your tpm2 tools is not recent (see https://github.com/tpm2-software/tpm2-tools/issues/3458)
tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o svc_account_tpm.pem
```

if you want to use `openssl` to issue a key:

```bash
## make sure openssl provider is installed
openssl list  -provider tpm2  -provider default  --providers

## generate an RSA key
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt rsa_keygen_bits:2048  \
       -pkeyopt rsa_keygen_pubexp:65537 -out svc_account_tpm.pem

## extract the public key
openssl rsa -provider tpm2  -provider default  -in svc_account_tpm.pem -pubout > svc_account_tpm_pem.pub
```

2) use the TPM based private key to create an `x509` certificate

Google Cloud uses the `x509` format of a key to import.    Note that GCP does not even verify the CA of the x509 you use to upload, you can even just self-sign the the x509.

So far all we've created ins a private RSA key on the TPM so we need to use it to generate a CSR and then have it signed some CA. 

For this step, you can either

-  Isseue `CSR` which any CA can sign

```bash
openssl req  -provider tpm2  -provider default  -new -key svc_account_tpm.pem -out svc_account_tpm.csr
```

- Issue Self-Signed certificate

```bash
openssl req  -provider tpm2  -provider default   -new -x509 -key svc_account_tpm.pem -out ssvc_account_tpm.crt -days 365
```

- `force` the public key 

Its extremely rare to do this but if you have a CA and the public key for the TPM based service account, you can issue an x509 without a CSR by using [-force_pubkey](https://docs.openssl.org/3.2/man1/openssl-x509/#certificate-output-options)

```bash
openssl x509 -new -CAkey root-ca.key  -CA root-ca.crt \
  -force_pubkey svc_account_tpm_pub.pem \
    -subj "/CN=my svc account Certificate" -out svc_account_tpm.crt
```

>> note you can do all these step using go-tpm

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


#### [C]  Remotely transferring an encrypted RSA key into the TPM 

If you already have a list of `EKCerts` you know for sure trust and want to distribute keys to, then its pretty easy:  just use [tpm2_duplicate](https://github.com/salrashid123/tpm2/tree/master/tpm2_duplicate)) with either `tpm2_tools` or `go-tpm`

for detailed walkthrough of that, see 

* [tpmcopy: Transfer RSA|ECC|AES|HMAC key to a remote Trusted Platform Module (TPM)](https://github.com/salrashid123/tpmcopy)

* [https://github.com/tpm2-software/tpm2-tools/wiki/Duplicating-Objects](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_duplicate.1.md#examples)


---

#### Post Step [A] [B] or [C]

4. Use `TpmTokenSource`

	After the key is embedded, you can *DELETE* any reference to `private.pem` (the now exists protected by the TPM and any access policy you may want to setup).

	The TPM based `TokenSource` can now be used to access a GCP resource using either a plain HTTPClient or _native_ GCP library (`google-cloud-pubsub`)!!

```bash
cd example/tpm/

go run no_policy/main.go --projectId=core-eso \
	   --persistentHandle=0x81010002 \
	    --serviceAccountEmail="tpm-sa@core-eso.iam.gserviceaccount.com" \
		--bucketName=core-eso-bucket --keyId=71b831d149e4667809644840cda2e7e0080035d5
```

eg

```golang

	// open the tpm
	rwc, err := OpenTPM(*tpmPath)

	// use it to get a tokensource 
	ts, err := sal.TpmTokenSource(&sal.TpmTokenConfig{
		TPMDevice: rwc,
		Handle: tpm2.TPMHandle(*persistentHandle), // persistent handle
		Email:         *serviceAccountEmail,
	})

	// use it with a gcp api client
	storageClient, err := storage.NewClient(ctx, option.WithTokenSource(ts))
```

If you want to enable [TPM Session Encryption](https://github.com/salrashid123/tpm2/tree/master/tpm_encrypted_session), see [here](https://github.com/salrashid123/gcp-adc-tpm/tree/main?tab=readme-ov-file#encrypted-tpm-sessions).  You will need to modify `example/tpm/main.go` to acquire the Endorsement keys and the supply them after validation as following parameters to `TpmTokenConfig`

```golang
	EncryptionHandle tpm2.TPMHandle   // (optional) handle to use for transit encryption
	EncryptionPub    *tpm2.TPMTPublic // (optional) public key to use for transit encryption
```

---
