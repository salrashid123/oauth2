
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


`google/oauth2/TpmTokenSource` is a variation of `google/oauth2/JWTAccessTokenSourceFromJSON` where the private key used to sign the JWT is embedded within a [Trusted Platform Module](https://en.wikipedia.org/wiki/Trusted_Platform_Module) (`TPM`).

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
	// or if using TPM embedded certificates:
	// tpm2_create -G rsa -u key.pub -r key.priv -C primary.ctx

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

---

## YubiKeyTokenSource

>> **WARNING:**  `YubiKeyTokenSource` is highly experimental.  This repo is NOT supported by Google


`google/oauth2/YubiKeyTokenSource` is a variation of `google/oauth2/JWTAccessTokenSourceFromJSON` where the private key used to sign the JWT is embedded within a [PIV-enabled YubiKey](https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html).

The private key in raw form _not_ exportable or exposed to the filesystem or any process other than through the Yubikey interface.  This token source uses the TPM interface to `sign` the JWT which is then used to access a Google Cloud API.  

This library uses [go-ykpiv](https://github.com/paultag/go-ykpiv) which inturn uses C extensions to access the Yubikek provided by `libkpiv-dev`.  You must have `libkpiv-dev` the target system where this TokenSource will be used.

This repo is under Apache License but specifically this component is MIT License per [go-ykpiv](https://github.com/paultag/go-ykpiv/blob/master/LICENSE).

### Usage

1. Prepare Yubikey for Key import

	First embed a GCP Service Account file as a combined `x509` certificate within a YubiKey.

	You must have a [YubiKey Neo or YubiKey 4 or 5](https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html) as thoese keys support embedded keys.

	You are free to provision the key by any means but for reference, the following uses:

	* [yubico-piv-tool CLI](https://developers.yubico.com/yubico-piv-tool/)
	* [yubikey-manager-qt UI](https://developers.yubico.com/yubikey-manager-qt/development.html)


	On any other system, install supporting libraries for both components listed above.  

	Also install the following to allow inspection of the key:
	```
	sudo apt-get install libpcsclite-dev scdaemon build-essential libykpiv-dev
	```

	Insert the YubiKey and verify you've got the correct type (YubiKey Neo, 4,5):

	```bash
	$ lsusb  | grep -i yubikey
	Bus 001 Device 013: ID 1050:0111 Yubico.com Yubikey NEO(-N) OTP+CCID
	```

	Launch the `ykman-gui` UI Application, it should also show the type of key you are using.  We will use `ykman-gui` later to import the keys.

2. Extract Service account certificate file

	Download a GCP [Service Account](https://cloud.google.com/iam/docs/service-accounts) **in .p12 format".

	Remove default passphrase (`notasecret`), generate an `x509` file for importing into the YubiKey.
	```
	openssl pkcs12 -in svc_account.p12  -nocerts -nodes -passin pass:notasecret | openssl rsa -out privkey.pem
	openssl rsa -in privkey.pem -outform PEM -pubout -out public.pem
	openssl req -new -x509  -key privkey.pem  -out public.crt
    		 Use CN=<your_service_account_email>
	openssl pkcs12 --export -in public.crt -inkey privkey.pem -outform PEM -out cert.pfx
	```

3. Embed Service Account within YubiKey

   Launch `yubikey-manager-qt` and navigate to the `Digital Signature` (9c). (see [Certificate Slots](https://developers.yubico.com/PIV/Introduction/Certificate_slots.html))
   Import the certificate `cert.pfx`.  If this is a new Yubikey, just use the default PIN and Management Keys provided. 

   You should see a loaded certificate:

   ![images/imported.png](images/imported.png)

   You can verify certificate load Status by running the `yubico-piv-tool`:

	```bash
	$ yubico-piv-tool -a status
	Version:	1.0.4
	Serial Number:	-1879017761
	CHUID:	3019d4e739da739ced39ce739d836858210842108421c84210c3eb34109acae3dbacb7f8b5295a1be28d916b2c350832303330303130313e00fe00
	CCC:	No data available
	Slot 9c:	
		Algorithm:	RSA2048
		Subject DN:	C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=svc-2-429@project.iam.gserviceaccount.com
		Issuer DN:	C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=svc-2-429@project.iam.gserviceaccount.com
		Fingerprint:	5726b54b6b50d737307a9ec09c0fc857258e23e7c05acf3f4d28cb3a2f37056b
		Not Before:	Oct 16 05:09:20 2019 GMT
		Not After:	Nov 15 05:09:20 2019 GMT
	PIN tries left:	3
	```

	And also verify sign/verify steps:
	```bash
	$ yubico-piv-tool -a read-certificate -s 9c
	-----BEGIN CERTIFICATE-----
	...
	-----END CERTIFICATE-----

	$ yubico-piv-tool -a verify-pin -a test-signature -s 9c
	Enter PIN: 
	Successfully verified PIN.
	Please paste the certificate to verify against...
	-----BEGIN CERTIFICATE-----
	...
	-----END CERTIFICATE-----
	Successful RSA verification.
	```

4. Install `libkpiv-dev` on target system

	On any system you wish to use this library, you must first install `libkpiv-dev` (eg `$ sudo apt-get install libcupti-dev`)

5. Use TokensSource

	```golang
	package main

	import (
		"log"
		"net/http"
		"golang.org/x/oauth2"
		sal "github.com/salrashid123/oauth2/google"
	)

	func main() {
		yubiKeyTokenSource, err := sal.YubiKeyTokenSource(
			sal.YubiKeyTokenConfig{
				Email:    "svcAccount@project.iam.gserviceaccount.com",
				Audience: "https://pubsub.googleapis.com/google.pubsub.v1.Publisher",
				Pin:      "123456",
			},
		)

		// tok, err := yubiKeyTokenSource.Token()
		// if err != nil {
		// 	 log.Fatal(err)
		// }
		// log.Printf("Token: %v", tok.AccessToken)
		client := &http.Client{
			Transport: &oauth2.Transport{
				Source: yubiKeyTokenSource,
			},
		}

		url := "https://pubsub.googleapis.com/v1/projects/YOURPROJECT/topics"
		resp, err := client.Get(url)
		if err != nil {
			log.Fatalf("Unable to get Topics %v", err)
		}
		log.Printf("Response: %v", resp.Status)
	```

	Note:  by default the Yubikey allows for 3 PIN attempts before going into lockout.  To unlock, see  [PIN and Management Key](https://developers.yubico.com/yubikey-piv-manager/PIN_and_Management_Key.html)



	If you do not have the Yubikey Plugged in, you may see an error like this

	```bash
	error: SCardListReaders failed, rc=8010002e
	2019/10/16 07:33:10 Unable to open yubikey ykpiv ykpiv_connect: PKCS Error (-2) - Error in PCSC call
	```

Some notes:

  - Slot 9c: Digital Signature is reserved for Digital Signatures)
  - The default PIN for access is `123456`.  The default unlock code is `12345678`. 

See previous article about using the Yubikey NEO with GPG decryption [Encrypting Google Application Default and gcloud credentials with GPG SmardCard](https://medium.com/google-cloud/encrypting-google-application-default-and-gcloud-credentials-with-gpg-smardcard-fb6fec5c6e48).
The distinction here is that the RSA signing happens all onboard.

