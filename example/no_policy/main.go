package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"slices"

	"cloud.google.com/go/storage"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	sal "github.com/salrashid123/oauth2/v3"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

var (
	tpmPath             = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle    = flag.Uint("persistentHandle", 0x81010002, "Handle value")
	projectId           = flag.String("projectId", "core-eso", "ProjectID")
	kf                  = flag.String("keyfile", "/tmp/svc_account_tpm.pem", "TPM Encrypted private key")
	serviceAccountEmail = flag.String("serviceAccountEmail", "tpm-sa@core-eso.iam.gserviceaccount.com", "Email of the serviceaccount")
	bucketName          = flag.String("bucketName", "core-eso-bucket", "Bucket name")
	keyId               = flag.String("keyId", "71b831d149e4667809644840cda2e7e0080035d5", "GCP PRivate key id assigned.")
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

	// log.Printf("======= oauth2 using keyfile ========")

	// rwr := transport.FromReadWriteCloser(rwc)

	// c, err := os.ReadFile(*kf)
	// if err != nil {
	// 	log.Fatalf("can't load keys %q: %v", *tpmPath, err)
	// }
	// key, err := keyfile.Decode(c)
	// if err != nil {
	// 	log.Fatalf("can't decode keys %q: %v", *tpmPath, err)
	// }

	// // specify its parent directly
	// primaryKey, err := tpm2.CreatePrimary{
	// 	PrimaryHandle: key.Parent,
	// 	InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("can't create primary %q: %v", *tpmPath, err)
	// }

	// defer func() {
	// 	flushContextCmd := tpm2.FlushContext{
	// 		FlushHandle: primaryKey.ObjectHandle,
	// 	}
	// 	_, _ = flushContextCmd.Execute(rwr)
	// }()

	// // now the actual key can get loaded from that parent
	// rsaKey, err := tpm2.Load{
	// 	ParentHandle: tpm2.AuthHandle{
	// 		Handle: primaryKey.ObjectHandle,
	// 		Name:   tpm2.TPM2BName(primaryKey.Name),
	// 		Auth:   tpm2.PasswordAuth([]byte("")),
	// 	},
	// 	InPublic:  key.Pubkey,
	// 	InPrivate: key.Privkey,
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("can't load  rsaKey : %v", err)
	// }

	// defer func() {
	// 	flushContextCmd := tpm2.FlushContext{
	// 		FlushHandle: rsaKey.ObjectHandle,
	// 	}
	// 	_, _ = flushContextCmd.Execute(rwr)
	// }()

	// ts, err := sal.TpmTokenSource(&sal.TpmTokenConfig{
	// 	TPMDevice:     rwc,
	// 	Handle:        rsaKey.ObjectHandle, // from keyfile
	// 	Email:         *serviceAccountEmail,
	// 	UseOauthToken: false,
	// })

	// ctx := context.Background()
	// storageClient, err := storage.NewClient(ctx, option.WithTokenSource(ts))
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// sit := storageClient.Buckets(ctx, *projectId)
	// for {
	// 	battrs, err := sit.Next()
	// 	if err == iterator.Done {
	// 		break
	// 	}
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	log.Printf(battrs.Name)
	// }

	log.Printf("======= oauth2 end using persistent handle ========")

	ts, err := sal.TpmTokenSource(&sal.TpmTokenConfig{
		TPMDevice: rwc,
		Handle:    tpm2.TPMHandle(*persistentHandle), // persistent handle
		Email:     *serviceAccountEmail,
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

	// now get an id_token

	its, err := sal.TpmTokenSource(&sal.TpmTokenConfig{
		TPMDevice:     rwc,
		Handle:        tpm2.TPMHandle(*persistentHandle), // persistent handle
		Email:         *serviceAccountEmail,
		IdentityToken: true,
		Audience:      "https://foo.bar",
	})
	if err != nil {
		log.Fatal(err)
	}
	itok, err := its.Token()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Identity Token: %v", itok.AccessToken)

}
