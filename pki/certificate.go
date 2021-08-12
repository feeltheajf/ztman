package pki

import (
	"crypto/x509"

	"github.com/feeltheajf/ztman/fs"
)

// ReadCertificate loads certificate from file
func ReadCertificate(filename string) (*x509.Certificate, error) {
	raw, err := fs.Read(filename)
	if err != nil {
		return nil, err
	}
	return UnmarshalCertificate(raw)
}

// UnmarshalCertificate parses certificate from PEM-encoded string
func UnmarshalCertificate(raw string) (*x509.Certificate, error) {
	block, err := decode(raw)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(block.Bytes)
}

// WriteCertificate saves certificate to file
func WriteCertificate(filename string, crt *x509.Certificate) error {
	raw, err := MarshalCertificate(crt)
	if err != nil {
		return err
	}
	return fs.Write(filename, raw)
}

// MarshalCertificate returns PEM encoding of certificate
func MarshalCertificate(crt *x509.Certificate) (string, error) {
	return encode(PEMTypeCertificate, crt.Raw), nil
}
