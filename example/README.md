### TPM oauth2 examples

Extract service account key

```bash
cat svc-account.json | jq -r '.private_key' > /tmp/f.json
openssl rsa -out /tmp/key_rsa.pem -traditional -in /tmp/f.json
openssl rsa -in /tmp/key_rsa.pem -outform PEM -pubout -out public.pem
```

If using `swtpm`

```bash
# swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear
## then specify "127.0.0.1:2321"  as the TPM device path in the examples, export the following var
# export TPM2TOOLS_TCTI="swtpm:port=2321"
```

#### No Policy

With no  password or policy

```bash
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_import -C primary.ctx -G rsa2048:rsassa:null -g sha256 -i /tmp/key_rsa.pem -u key.pub -r key.prv
tpm2_flushcontext -t
tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
tpm2_flushcontext -t
tpm2_evictcontrol -C o -c key.ctx 0x81010002

tpm2_encodeobject -C primary.ctx -u key.pub -r key.prv -o svc_account_tpm.pem
```

#### Policy Password

With password

```bash
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_import -C primary.ctx -p testpwd -G rsa2048:rsassa:null -g sha256 -i /tmp/key_rsa.pem -u key.pub -r key.prv
tpm2_flushcontext -t
tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
tpm2_flushcontext -t
tpm2_evictcontrol -C o -c key.ctx 0x81010004

tpm2_encodeobject -C primary.ctx -u key.pub -r key.prv -o svc_account_tpm_password.pem -p


 go run password_policy/main.go \
    --keyPass=testpwd -keyfile /tmp/svc_account_tpm_password.pem \
     -serviceAccountEmail=tpm-sa@core-eso.iam.gserviceaccount.com --tpm-path=$TPMB
```

#### Policy PCR

WIth policy bound to PCR

```bash
tpm2_pcrread sha256:23
tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
tpm2_flushcontext session.dat
tpm2_flushcontext  -t
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat
tpm2_import -C primary.ctx -G rsa2048:rsassa:null -g sha256 -i /tmp/key_rsa.pem -u key.pub -r key.prv  -L policy.dat
tpm2_flushcontext  -t
tpm2_getcap  handles-transient
tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
tpm2_evictcontrol -C o -c key.ctx 0x81010003
tpm2_flushcontext  -t

tpm2_encodeobject -C primary.ctx -u key.pub -r key.prv -o svc_account_tpm_pcr.pem


 go run password_policy/main.go \
    --pcrs=23 -keyfile /tmp/svc_account_tpm_pcr.pem \
     -serviceAccountEmail=tpm-sa@core-eso.iam.gserviceaccount.com --tpm-path=$TPMB
```


#### DuplicateSelect

see [https://github.com/salrashid123/tpmcopy](https://github.com/salrashid123/tpmcopy)

```bash
## TPM A
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
/usr/share/swtpm/swtpm-create-user-config-files
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

## in new window
export TPM2TOOLS_TCTI="swtpm:port=2321"


## TPM B
rm -rf /tmp/myvtpm2 && mkdir /tmp/myvtpm2
/usr/share/swtpm/swtpm-create-user-config-files
swtpm_setup --tpmstate /tmp/myvtpm2 --tpm2 --create-ek-cert
swtpm socket --tpmstate dir=/tmp/myvtpm2 --tpm2 --server type=tcp,port=2341 --ctrl type=tcp,port=2342 --flags not-need-init,startup-clear --log level=2

## in new window
export TPM2TOOLS_TCTI="swtpm:port=2341"

tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l

export TPMA="127.0.0.1:2321"
export TPMB="127.0.0.1:2341"

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2TOOLS_TCTI="swtpm:port=2341"
```

##### Password

```bash
### TPM-B
tpmcopy --mode publickey --parentKeyType=rsa -tpmPublicKeyFile=/tmp/public.pem --tpm-path=$TPMB
### copy public.pem to TPM-A

### TPM-A
tpmcopy --mode duplicate  --secret=/tmp/key_rsa.pem --keyType=rsa \
   --password=bar -tpmPublicKeyFile=/tmp/public.pem -out=/tmp/out.json --tpm-path=$TPMA

### copy out.json to TPM-B
### TPM-B
tpmcopy --mode import --parentKeyType=rsa \
 --in=/tmp/out.json --out=/tmp/tpmkey.pem \
 --pubout=/tmp/pub.dat --privout=/tmp/priv.dat \
  --parent=0x81008000 --tpm-path=$TPMB

tpmcopy --mode evict \
    --persistentHandle=0x81008001 \
   --in=/tmp/tpmkey.pem --tpm-path=$TPMB


 go run dupselect_password_policy/main.go \
    --keyPass=bar -keyfile /tmp/tpmkey.pem \
     -serviceAccountEmail=tpm-sa@core-eso.iam.gserviceaccount.com --tpm-path=$TPMB
```

