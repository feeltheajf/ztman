package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/feeltheajf/ztman/config"
)

// NewCertificateRequest creates new signed certificate request using the given key
func NewCertificateRequest(tpl *x509.CertificateRequest, priv interface{}) (*x509.CertificateRequest, error) {
	b, err := x509.CreateCertificateRequest(rand.Reader, tpl, priv)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  pemTypeCertificateRequest,
		Bytes: b,
	}
	return UnmarshalCertificateRequest(pem.EncodeToMemory(block))
}

// UnmarshalCertificateRequest parses certificate request from PEM-encoded bytes
func UnmarshalCertificateRequest(raw []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("failed to parse certificate request: invalid PEM")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// WriteCertificateRequest saves certificate request to file
func WriteCertificateRequest(filename string, csr *x509.CertificateRequest) error {
	raw, err := MarshalCertificateRequest(csr)
	if err != nil {
		return err
	}
	return config.WriteFile(filename, raw)
}

// MarshalCertificateRequest returns PEM encoding of certificate request
func MarshalCertificateRequest(csr *x509.CertificateRequest) ([]byte, error) {
	block := &pem.Block{
		Type:  pemTypeCertificateRequest,
		Bytes: csr.Raw,
	}
	return pem.EncodeToMemory(block), nil
}
