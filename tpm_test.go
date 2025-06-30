package tpm

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func TestTPMJWTAccessTokenHandle(t *testing.T) {

	saEmail := os.Getenv("CICD_SA_EMAIL")
	saPEM := os.Getenv("CICD_SA_PEM")

	tpmDevice, err := simulator.Get()
	if err != nil {
		t.Errorf("error getting simulator %v", err)
	}
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		t.Errorf("error creating primary %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	block, _ := pem.Decode([]byte(saPEM))
	if block == nil {
		t.Errorf("     Failed to decode PEM block containing the key %v", err)
	}
	pvp, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("error creating parsing pem %v", err)
	}
	pv := pvp.(*rsa.PrivateKey)

	rsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Exponent: uint32(pv.PublicKey.E),
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),

		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: pv.PublicKey.N.Bytes(),
			},
		),
	}

	sens2B := tpm2.Marshal(tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgRSA,
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPrivateKeyRSA{Buffer: pv.Primes[0].Bytes()},
		),
	})

	l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

	importResponse, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectPublic: tpm2.New2B(rsaTemplate),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
	}.Execute(rwr)
	if err != nil {
		t.Errorf("error importing TPM key %v", err)
	}

	rsaKeyResponse, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  tpm2.New2B(rsaTemplate),
		InPrivate: importResponse.OutPrivate,
	}.Execute(rwr)
	if err != nil {
		t.Errorf("error loading tpm key %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	ts, err := TpmTokenSource(&TpmTokenConfig{
		TPMDevice:     tpmDevice,
		Handle:        rsaKeyResponse.ObjectHandle, // from keyfile
		Email:         saEmail,
		UseOauthToken: false,
	})

	if err != nil {
		t.Errorf("error loading tpm key %v", err)
	}

	_, err = ts.Token()
	if err != nil {
		t.Errorf("error loading tpm key %v", err)
	}

}

func TestTPMOauthTokenHandle(t *testing.T) {

	saEmail := os.Getenv("CICD_SA_EMAIL")
	saPEM := os.Getenv("CICD_SA_PEM")

	tpmDevice, err := simulator.Get()
	if err != nil {
		t.Errorf("error getting simulator %v", err)
	}
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		t.Errorf("error creating primary %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	block, _ := pem.Decode([]byte(saPEM))
	if block == nil {
		t.Errorf("     Failed to decode PEM block containing the key %v", err)
	}
	pvp, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("error creating parsing pem %v", err)
	}
	pv := pvp.(*rsa.PrivateKey)

	rsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Exponent: uint32(pv.PublicKey.E),
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),

		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: pv.PublicKey.N.Bytes(),
			},
		),
	}

	sens2B := tpm2.Marshal(tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgRSA,
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPrivateKeyRSA{Buffer: pv.Primes[0].Bytes()},
		),
	})

	l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

	importResponse, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectPublic: tpm2.New2B(rsaTemplate),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
	}.Execute(rwr)
	if err != nil {
		t.Errorf("error importing TPM key %v", err)
	}

	rsaKeyResponse, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  tpm2.New2B(rsaTemplate),
		InPrivate: importResponse.OutPrivate,
	}.Execute(rwr)
	if err != nil {
		t.Errorf("error loading tpm key %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	ts, err := TpmTokenSource(&TpmTokenConfig{
		TPMDevice:     tpmDevice,
		Handle:        rsaKeyResponse.ObjectHandle, // from keyfile
		Email:         saEmail,
		UseOauthToken: true,
	})

	if err != nil {
		t.Errorf("error loading tpm key %v", err)
	}

	_, err = ts.Token()
	if err != nil {
		t.Errorf("error loading tpm key %v", err)
	}

}

func TestTPMIdTokenHandle(t *testing.T) {

	saEmail := os.Getenv("CICD_SA_EMAIL")
	saPEM := os.Getenv("CICD_SA_PEM")

	tpmDevice, err := simulator.Get()
	if err != nil {
		t.Errorf("error getting simulator %v", err)
	}
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		t.Errorf("error creating primary %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	block, _ := pem.Decode([]byte(saPEM))
	if block == nil {
		t.Errorf("     Failed to decode PEM block containing the key %v", err)
	}
	pvp, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("error creating parsing pem %v", err)
	}
	pv := pvp.(*rsa.PrivateKey)

	rsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Exponent: uint32(pv.PublicKey.E),
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),

		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: pv.PublicKey.N.Bytes(),
			},
		),
	}

	sens2B := tpm2.Marshal(tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgRSA,
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPrivateKeyRSA{Buffer: pv.Primes[0].Bytes()},
		),
	})

	l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

	importResponse, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectPublic: tpm2.New2B(rsaTemplate),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
	}.Execute(rwr)
	if err != nil {
		t.Errorf("error importing TPM key %v", err)
	}

	rsaKeyResponse, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  tpm2.New2B(rsaTemplate),
		InPrivate: importResponse.OutPrivate,
	}.Execute(rwr)
	if err != nil {
		t.Errorf("error loading tpm key %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	ts, err := TpmTokenSource(&TpmTokenConfig{
		TPMDevice:     tpmDevice,
		Handle:        rsaKeyResponse.ObjectHandle, // from keyfile
		Email:         saEmail,
		IdentityToken: true,
		Audience:      "https://foo.bar",
	})

	if err != nil {
		t.Errorf("error loading tpm key %v", err)
	}

	_, err = ts.Token()
	if err != nil {
		t.Errorf("error loading tpm key %v", err)
	}

}
