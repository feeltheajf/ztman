package pki

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"

	"github.com/feeltheajf/ztman/config"
)

// ReadCertificate loads certificate from file
func ReadCertificate(filename string) (*x509.Certificate, error) {
	b, err := ioutil.ReadFile(filename) // #nosec G304
	if err != nil {
		return nil, err
	}
	return UnmarshalCertificate(b)
}

// UnmarshalCertificate parses certificate from PEM-encoded bytes
func UnmarshalCertificate(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("failed to parse certificate: invalid PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// WriteCertificate saves certificate to file
func WriteCertificate(filename string, crt *x509.Certificate) error {
	raw, err := MarshalCertificate(crt)
	if err != nil {
		return err
	}
	return config.Write(filename, raw)
}

// MarshalCertificate returns PEM encoding of certificate
func MarshalCertificate(crt *x509.Certificate) ([]byte, error) {
	block := &pem.Block{
		Type:  pemTypeCertificate,
		Bytes: crt.Raw,
	}
	return pem.EncodeToMemory(block), nil
}
