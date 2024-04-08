package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	sal "github.com/salrashid123/oauth2/tpm"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

var (
	tpmPath             = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle    = flag.Uint("persistentHandle", 0x81008004, "Handle value")
	projectId           = flag.String("projectId", "core-eso", "ProjectID")
	pcr                 = flag.Int("pcr", 23, "PCR to use")
	serviceAccountEmail = flag.String("serviceAccountEmail", "tpm-sa@core-eso.iam.gserviceaccount.com", "Email of the serviceaccount")
	bucketName          = flag.String("bucketName", "core-eso-bucket", "Bucket name")
	keyId               = flag.String("keyId", "71b831d149e4667809644840cda2e7e0080035d5", "GCP PRivate key id assigned.")
)

func main() {

	flag.Parse()

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
		return
	}
	defer rwc.Close()

	// s, err := client.NewPCRSession(rwc, tpm2.PCRSelection{tpm2.AlgSHA256, []int{*pcr}})
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "error creating pcr selection %v\n", err)
	// 	os.Exit(1)
	// }
	// k, err := client.LoadCachedKey(rwc, tpmutil.Handle(*persistentHandle), s)
	k, err := client.LoadCachedKey(rwc, tpmutil.Handle(*persistentHandle), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening key %v\n", err)
		os.Exit(1)
	}

	ts, err := sal.TpmTokenSource(&sal.TpmTokenConfig{
		TPMDevice:     rwc, // tpm is managed by the caller
		Key:           k,
		Email:         *serviceAccountEmail,
		UseOauthToken: true,
	})
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
