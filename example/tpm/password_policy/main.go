package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"slices"
	"time"

	"cloud.google.com/go/storage"
	// keyfile "github.com/foxboron/go-tpm-keyfiles"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
	sal "github.com/salrashid123/oauth2/tpm"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

var (
	tpmPath             = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle    = flag.Uint("persistentHandle", 0x81010004, "Handle value")
	projectId           = flag.String("projectId", "core-eso", "ProjectID")
	kf                  = flag.String("keyfile", "/tmp/svc_account_tpm.pem", "TPM Encrypted private key")
	serviceAccountEmail = flag.String("serviceAccountEmail", "tpm-sa@core-eso.iam.gserviceaccount.com", "Email of the serviceaccount")
	bucketName          = flag.String("bucketName", "core-eso-bucket", "Bucket name")
	keyId               = flag.String("keyId", "71b831d149e4667809644840cda2e7e0080035d5", "GCP PRivate key id assigned.")
	keyPass             = flag.String("keyPass", "testpwd", "KeyPassword")
	ECCSRK_H_Template   = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
			},
		),
	}
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {

	flag.Parse()

	log.Printf("======= Init  ========")

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	// log.Printf("======= oauth2 end using persistent handle ========")
	//
	pub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(*persistentHandle), //persistent handle
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing tpm2.ReadPublic %v", err)
	}

	se, err := tpmjwt.NewPasswordSession(rwr, []byte(*keyPass))
	if err != nil {
		log.Fatalf("error executing tpm2.ReadPublic %v", err)
	}
	ts, err := sal.TpmTokenSource(&sal.TpmTokenConfig{
		TPMDevice: rwc,
		NamedHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(*persistentHandle), // persistent handle
			Name:   pub.Name,
		},
		AuthSession: se,
		Email:       *serviceAccountEmail,
	})
	if err != nil {
		log.Fatal(err)
	}
	tok, err := ts.Token()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Token: %v", tok.AccessToken)

	i := 0
	for {

		ctx := context.Background()

		// GCS does not support JWTAccessTokens, the following will only work if UseOauthToken is set to True
		storageClient, err := storage.NewClient(ctx, option.WithTokenSource(ts))
		if err != nil {
			log.Fatal(err)
		}
		sit := storageClient.Buckets(ctx, *projectId)
		for {
			_, err := sit.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				log.Fatal(err)
			}
			//log.Printf(battrs.Name)
		}
		i = i + 1
		log.Printf("%d\n", i)
		time.Sleep(60 * time.Second)

	}

}
