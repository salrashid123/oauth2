### TPM oauth2 examples

Extract service account key

```bash
cat svc-account.json | jq -r '.private_key' > /tmp/f.json
openssl rsa -out /tmp/key_rsa.pem -traditional -in /tmp/f.json
openssl rsa -in /tmp/key_rsa.pem -outform PEM -pubout -out public.pem
```

If using `swtpm`

```bash
# sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear
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
```