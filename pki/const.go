package pki

// PEMType is used for encoding objects
type PEMType string

// Known PEM types
const (
	PEMTypeCertificate        PEMType = "CERTIFICATE"
	PEMTypeECPrivateKey       PEMType = "EC PRIVATE KEY"
	PEMTypePublicKey          PEMType = "PUBLIC KEY"
	PEMTypeRevocationList     PEMType = "X509 CRL"
	PEMTypeCertificateRequest PEMType = "CERTIFICATE REQUEST"
)
