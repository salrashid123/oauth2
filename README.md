
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

* **A)** download a Google ServiceAccount's `json` file  and embed the private part to the TPM 

or

* **B)** Generate a Key _ON THE TPM_ and then import the public part to GCP.

or

* **C**) remote seal the service accounts RSA Private key remotely, encrypt it with the remote TPM's Endorsement Key and load it

---

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

#### B) Generate key on TPM and export public X509 certificate to GCP

1) Generate Key on TPM and make it persistent

The following uses `tpm2_tools` but is pretty straightfoward to do the same steps using `go-tpm`

```bash
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
# tpm2_evictcontrol -C o -c key.ctx 0x81010002
# tpm2_readpublic -c 0x81010002 -f PEM -o key.pem
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

## you may need to add a -p if your tpm2 tools is not recent (see https://github.com/tpm2-software/tpm2-tools/issues/3458)
tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o svc_account_tpm.pem
```

2) use the TPM based private key to create an `x509` certificate

Google Cloud uses the `x509` format of a key to import.  So far all we've created ins a private RSA key on the TPM so we need to use it to generate a CSR and then have it signed some CA. 

The following example will use `openssl` and its tpm provider to issue the CSR and an external CA to sign it.  Note that GCP does not even verify the CA of the x509 you use to upload, you can even just self-sign the the x509.    We're using openssl but if you want to use `go-tpm`, you can follow the following reference: [Create CSR and self-signed x509 Certificates using Signer](https://github.com/salrashid123/signer/blob/master/util/README.md)

Anyway, with openssl, you can use a sample external CA in the repo below:

```bash
git clone https://github.com/salrashid123/go_tpm_https_embed.git
cd go_tpm_https_embed/certs/

## make sure openssl provider is installed
$ openssl list  -provider tpm2  -provider default  --providers

Providers:
  default
    name: OpenSSL Default Provider
    version: 3.5.0
    status: active
  tpm2
    name: TPM 2.0 Provider
    version: 1.3.0
    status: active

## check if it can read the private key
$ openssl rsa -provider tpm2  -provider default -in svc_account_tpm.pem --text
		Private-Key: (RSA 2048 bit, TPM 2.0)
		Parent: 0x40000001
		Modulus:
			00:cc:71:e6:2e:d5:4d:b1:27:51:07:ca:03:7a:5d:
			57:e4:0e:38:ee:2c:b9:c0:55:83:1d:98:4d:09:f9:
			4a:06:59:f9:78:9c:0b:58:8e:93:ce:38:e2:06:5b:
			22:59:8e:97:7c:83:63:98:0f:83:34:1f:82:d8:2e:
			42:fc:0f:39:72:3f:52:b0:83:93:25:ad:71:f6:a5:
			b6:a6:c3:4a:89:37:17:5d:24:32:78:62:3d:f8:28:
			07:2e:c5:27:d3:81:10:cd:79:33:d1:f7:77:f4:fe:
			34:35:5f:27:1c:be:44:35:e2:a3:4c:0a:88:9d:d8:
			05:59:36:25:54:f5:6e:d2:24:51:9b:fc:a0:83:65:
			3d:bc:eb:a6:18:9e:a3:db:77:df:96:2e:57:72:90:
			88:46:d4:5a:f1:26:25:95:fc:50:92:d9:4e:45:32:
			6e:98:74:77:28:9c:40:4b:02:41:cd:cc:17:6b:98:
			cc:52:94:88:ac:0b:d3:6e:d8:24:22:2d:5b:37:4d:
			f2:a2:dc:82:4b:47:b4:00:05:a7:4b:24:5e:a3:f0:
			25:43:68:a3:d0:95:39:1c:4f:7d:7e:e8:1b:0a:81:
			16:b3:49:c8:b5:f9:24:4d:e3:ab:96:24:de:62:33:
			f5:94:29:cc:7f:78:78:82:ee:d3:be:c4:cd:04:9c:
			8d:5f
		Exponent: 65537 (0x10001)
		Object Attributes:
		fixedTPM
		fixedParent
		sensitiveDataOrigin
		userWithAuth
		sign / encrypt
		Signature Scheme: PKCS1
		Hash: SHA256
		writing RSA key
		-----BEGIN TSS2 PRIVATE KEY-----
		MIICFAYGZ4EFCgEDoAMBAQECBEAAAAEEggEaARgAAQALAAQAcgAAABAAFAALCAAA
		AAAAAQDMceYu1U2xJ1EHygN6XVfkDjjuLLnAVYMdmE0J+UoGWfl4nAtYjpPOOOIG
		WyJZjpd8g2OYD4M0H4LYLkL8DzlyP1Kwg5MlrXH2pbamw0qJNxddJDJ4Yj34KAcu
		xSfTgRDNeTPR93f0/jQ1XyccvkQ14qNMCoid2AVZNiVU9W7SJFGb/KCDZT2866YY
		nqPbd9+WLldykIhG1FrxJiWV/FCS2U5FMm6YdHconEBLAkHNzBdrmMxSlIisC9Nu
		2CQiLVs3TfKi3IJLR7QABadLJF6j8CVDaKPQlTkcT31+6BsKgRazSci1+SRN46uW
		JN5iM/WUKcx/eHiC7tO+xM0EnI1fBIHgAN4AIInuE3XFMrF3YKawj8t0UZpeDsnM
		/VIayjDqPZ0hxBK3ABDMC2N1FMoHOx1JDQSqQrv/TvjSdFOiPb6qmQLlJU5aV7FP
		sqwipm2XnOnz07jHITtmmS8po9WT/3Fj6lysaVunkZOCI3OpdeNgXpTFDl0CNtig
		5fEsLuYFxz8GPoiaXccHUrYyN8WmzVb7/GN+/nVWACZY55ElV3mirGnkfRYyuUHY
		S+Mnu4vFuhuEGR4QBKMImwKOp9E08haNB+U7jJA0TMI5rTZP2nb1nLIeADI6w8qH
		Qm0keOa7fi4=
		-----END TSS2 PRIVATE KEY-----

## now use it to generate a csr
export SAN="DNS:client.domain.com"
openssl req -new  -provider tpm2  -provider default    -config client.conf \
  -out client.csr  \
  -key svc_account_tpm.pem  -reqexts client_reqext   \
  -subj "/C=US/O=Google/OU=Enterprise/CN=client.domain.com" 

openssl req -in client.csr -noout -text

## then issue the certificate
openssl ca \
    -config single-root-ca.conf \
    -in client.csr \
    -out cert.pem  \
    -extensions client_ext

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


#### C)  Remotely transferring an encrypted RSA key into the TPM 

If you already have a list of EKCerts you know for sure trust and want to distribute keys to, then its pretty easy:  just use `client.ImportSigningKey()` api from `go-tpm-tools` to seal data to an EK, then transmit the encrypted key to each VM.

Each VM will then load it into non-volatile area of the TPM and you can use it to sign as much as you want.

for detailed walkthrough of that, see 

* [Importing ServiceAccount Credentials to TPMs](https://gist.github.com/salrashid123/9e4a0328fd8c84374ace78c76a1e34cb)

note, there are also several ways to securely transfer public/private keys between TPM-enabled systems (eg, your laptop where you downloaded the key and a Shielded VM). 

That procedure is demonstrated here: [Duplicating Objects](https://github.com/tpm2-software/tpm2-tools/wiki/Duplicating-Objects)

(You can also duplicate a key and prevent reduplication, see [tpm2_duplicate](https://github.com/salrashid123/tpm2/tree/master/tpm2_duplicate))

---

#### Post Step A) B) or C)

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
