### Configure AWS credentials for GCP Access 


To setup, please follow [GCP Workload Identity Federation using AWS Credentials](https://github.com/salrashid123/gcpcompat-aws).


If you want to impersonate service account `aws-federated@$PROJECT_ID.iam.gserviceaccount.com` as either the user or assume role, set

```yaml
$ gcloud iam service-accounts get-iam-policy aws-federated@$PROJECT_ID.iam.gserviceaccount.com  

bindings:
- members:
  - principal://iam.googleapis.com/projects/995081019036/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:iam::291738886548:user/svcacct1
  - principal://iam.googleapis.com/projects/995081019036/locations/global/workloadIdentityPools/aws-pool-1/subject/arn:aws:sts::291738886548:assumed-role/gcpsts/mysession
```