package pki

import (
	"crypto/rand"
	"crypto/x509"

	"github.com/feeltheajf/ztman/fs"
)

// NewCertificateRequest creates new signed certificate request using the given key
func NewCertificateRequest(tpl *x509.CertificateRequest, priv interface{}) (*x509.CertificateRequest, error) {
	b, err := x509.CreateCertificateRequest(rand.Reader, tpl, priv)
	if err != nil {
		return nil, err
	}
	return UnmarshalCertificateRequest(encode(PEMTypeCertificateRequest, b))
}

// UnmarshalCertificateRequest parses certificate request from PEM-encoded string
func UnmarshalCertificateRequest(raw string) (*x509.CertificateRequest, error) {
	block, err := decode(raw)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// WriteCertificateRequest saves certificate request to file
func WriteCertificateRequest(filename string, csr *x509.CertificateRequest) error {
	raw, err := MarshalCertificateRequest(csr)
	if err != nil {
		return err
	}
	return fs.Write(filename, raw)
}

// MarshalCertificateRequest returns PEM encoding of certificate request
func MarshalCertificateRequest(csr *x509.CertificateRequest) (string, error) {
	return encode(PEMTypeCertificateRequest, csr.Raw), nil
}
