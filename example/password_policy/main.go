package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"slices"

	"cloud.google.com/go/storage"
	// keyfile "github.com/foxboron/go-tpm-keyfiles"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
	sal "github.com/salrashid123/oauth2/v3"
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

	encPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create pimaryEK: %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: encPrimary.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// log.Printf("======= oauth2 end using persistent handle ========")
	//
	se, err := tpmjwt.NewPasswordSession(rwr, []byte(*keyPass), encPrimary.ObjectHandle)
	if err != nil {
		log.Fatalf("error executing tpm2.ReadPublic %v", err)
	}
	ts, err := sal.TpmTokenSource(&sal.TpmTokenConfig{
		TPMDevice:   rwc,
		Handle:      tpm2.TPMHandle(*persistentHandle), // persistent handle
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

	ctx := context.Background()

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
