package main

import (
	"context"
	"flag"
	"log"

	"cloud.google.com/go/storage"
	//stscreds "github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	//sts "github.com/aws/aws-sdk-go-v2/service/sts"

	//"github.com/aws/aws-sdk-go-v2/aws/session"

	ac "github.com/aws/aws-sdk-go-v2/config"
	sal "github.com/salrashid123/oauth2/aws"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

var (
	projectId = flag.String("projectId", "core-eso", "ProjectID")
)

func main() {

	flag.Parse()

	log.Printf("======= Init  ========")

	// for the following, the IAM binding on "aws-federated@core-eso.iam.gserviceaccount.com" includes
	//  	principal://iam.googleapis.com/projects/995081019036/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:iam::291738886548:user/svcacct1
	//   in the Workload Identity User  role

	cfg, err := ac.LoadDefaultConfig(context.Background(), ac.WithRegion("us-east-1"))
	if err != nil {
		log.Fatal(err)
	}

	ts, err := sal.AWSTokenSource(
		&sal.AwsTokenConfig{
			CredentialsProvider:  &cfg.Credentials,
			Scopes:               []string{"https://www.googleapis.com/auth/cloud-platform"},
			TargetResource:       "//iam.googleapis.com/projects/995081019036/locations/global/workloadIdentityPools/aws-pool-1/providers/aws-provider-1",
			Region:               "us-east-1",
			TargetServiceAccount: "aws-federated@core-eso.iam.gserviceaccount.com",
			UseIAMToken:          true,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// // using AssumeRole credential source
	// for the following, the IAM binding on "aws-federated@core-eso.iam.gserviceaccount.com" includes
	//  	principal://iam.googleapis.com/projects/995081019036/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:sts::291738886548:assumed-role/gcpsts/mysession
	//   in the Workload Identity User  role

	// scfg, err := ac.LoadDefaultConfig(context.Background(), ac.WithRegion("us-east-1"))
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// stsSvc := sts.NewFromConfig(scfg)
	// cp := stscreds.NewAssumeRoleProvider(stsSvc, "arn:aws:iam::291738886548:role/gcpsts", func(p *stscreds.AssumeRoleOptions) {
	// 	p.RoleSessionName = "mysession"
	// })
	// cfg, err := ac.LoadDefaultConfig(context.Background(), ac.WithRegion("us-east-1"), ac.WithCredentialsProvider(cp))
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// ts, err := sal.AWSTokenSource(
	// 	&sal.AwsTokenConfig{
	// 		CredentialsProvider:  &cfg.Credentials,
	// 		Scopes:               []string{"https://www.googleapis.com/auth/cloud-platform"},
	// 		TargetResource:       "//iam.googleapis.com/projects/995081019036/locations/global/workloadIdentityPools/aws-pool-1/providers/aws-provider-1",
	// 		Region:               "us-east-1",
	// 		TargetServiceAccount: "aws-federated@core-eso.iam.gserviceaccount.com",
	// 		UseIAMToken:          true,
	// 	},
	// )
	if err != nil {
		log.Fatal(err)
	}
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
