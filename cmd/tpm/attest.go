package tpm

// TODO is there a value in supporting TPM attestation

// // var attestFlags = struct {
// // 	//
// // }{}

// func init() {
// 	//
// }

// func att() error {
// 	return nil
// }

// func init() {
// 	// flag.StringVar(&ak, "ak", "", "attestation key")
// 	// flag.StringVar(&nonce, "nonce", "", "provided by IT") // TODO get nonce from server
// 	// flag.Parse()

// 	// if nonce == "" {
// 	// 	log.Fatal("nonce is required")
// 	// }
// }

// func main() {
// 	tpm, err := attest.OpenTPM(nil)
// 	if err != nil {
// 		log.Fatalf("Failed to open tpm: %v", err)
// 	}

// 	var attestationKey *attest.AK
// 	defer func() {
// 		if err := attestationKey.Close(tpm); err != nil {
// 			log.Fatalf("Failed to close AK: %v", err)
// 		}
// 		if err := tpm.Close(); err != nil {
// 			log.Fatalf("Failed to close tpm: %v", err)
// 		}
// 	}()

// 	eks, err := tpm.EKs()
// 	if err != nil {
// 		log.Fatalf("Failed to get EKs: %v", err)
// 	}

// 	if len(eks) == 0 {
// 		log.Fatalf("Failed to find any EKs")
// 	}

// 	ek := eks[0]
// 	log.Printf("i: %s\n\n", ek.Certificate.Issuer)
// 	// pki.WriteCertificate("", ek.Certificate)

// 	// 	// TODO send ek.Certificate.Raw for validation

// 	// 	ekPubRaw, err := pki.MarshalPublicKey(ek.Public)
// 	// 	if err != nil {
// 	// 		log.Fatalf("Failed to marshal EK public: %v", err)
// 	// 	}

// 	// 	if ak == "" {
// 	// 		log.Println("Generating new AK")

// 	attestationKey, err = tpm.NewAK(nil)
// 	// 		if err != nil {
// 	// 			log.Fatalf("Failed to create AK: %v", err)
// 	// 		}

// 	// 		b, err := attestationKey.Marshal()
// 	// 		if err != nil {
// 	// 			log.Fatalf("Failed to marshal AK: %v", err)
// 	// 		}

// 	// 		log.Printf("ak: %s\n\n", string(b))
// 	// 	} else {
// 	// 		log.Println("Loading AK")

// 	attestationKey, err = tpm.LoadAK([]byte(ak))
// 	// 		if err != nil {
// 	// 			log.Fatalf("Failed to load AK: %v", err)
// 	// 		}
// 	// 	}

// 	// 	nonce := []byte(nonce)

// 	// 	eventLog, err := tpm.MeasurementLog()
// 	// 	if err != nil {
// 	// 		log.Printf("Failed to open event log: %v", err)
// 	// 		eventLog = []byte{0}
// 	// 	}

// 	// 	att, err := tpm.AttestPlatform(attestationKey, nonce, &attest.PlatformAttestConfig{
// 	// 		EventLog: eventLog,
// 	// 	})
// 	// 	if err != nil {
// 	// 		log.Fatalf("Failed to attest the platform state: %v", err)
// 	// 	}
// 	// 	// no useful information here
// 	// 	// for _, pcr := range att.PCRs {
// 	// 	// 	log.Printf("pcr index: %d\n", pcr.Index)
// 	// 	// 	log.Printf("pcr digest: %s\n", hex.EncodeToString(pcr.Digest))
// 	// 	// 	log.Printf("pcr digest alg: %d\n\n", pcr.DigestAlg)
// 	// 	// }

// 	// 	// Construct an AKPublic struct from the parameters of the key. This
// 	// 	// will be used to  verify the quote signatures.
// 	// 	akPub, err := attest.ParseAKPublic(tpm.Version(), attestationKey.AttestationParameters().Public)
// 	// 	if err != nil {
// 	// 		log.Fatalf("Failed to parse AK public: %v", err)
// 	// 	}

// 	// 	// TODO inspect public key attributes like FlagFixedTPM or FlagSensitiveDataOrigin
// 	// 	// akPub2, err := tpm2.DecodePublic(attestationKey.AttestationParameters().Public)
// 	// 	// if err != nil {
// 	// 	// 	log.Fatalf("Failed to decode public blob: %v", err)
// 	// 	// }
// 	// 	// log.Printf("Key attributes: 0x%08x\n\n", akPub2.Attributes)

// 	// 	akPubRaw, err := pki.MarshalPublicKey(akPub.Public)
// 	// 	if err != nil {
// 	// 		log.Fatalf("Failed to marshal AK public: %v", err)
// 	// 	}
// 	// 	log.Printf("ak public: %s\n\n", string(akPubRaw))

// 	// 	for i, q := range att.Quotes {
// 	// 		log.Printf("q version: %d\n", q.Version)
// 	// 		log.Printf("q quote: %s\n", hex.EncodeToString(q.Quote))
// 	// 		log.Printf("q signature: %s\n\n", hex.EncodeToString(q.Signature))

// 	// 		if err := akPub.Verify(q, att.PCRs, nonce); err != nil {
// 	// 			log.Fatalf("quote[%d] verification failed: %v", i, err)
// 	// 		}
// 	// 	}

// 	// 	el, err := att.ParseEventLog(att.EventLog)
// 	// 	if err != nil {
// 	// 		log.Fatalf("Failed to parse event log: %v", err)
// 	// 	}

// 	// 	if _, err := el.Verify(att.PCRs); err != nil {
// 	// 		log.Fatalf("Failed to verify event log: %v", err)
// 	// 	}

// 	// 	ec := att.EncryptedCredential{}
// 	// 	_, err = doRequest(
// 	// 		http.MethodPost,
// 	// 		"http://192.168.31.126:8443/generate",
// 	// 		&generateRequest{
// 	// 			TPMVersion:            tpm.Version(),
// 	// 			EK:                    ekPubRaw,
// 	// 			AttestationParameters: attestationKey.AttestationParameters(),
// 	// 		},
// 	// 		&ec,
// 	// 	)
// 	// 	if err != nil {
// 	// 		log.Fatalf("Failed to do generate request: %v", err)
// 	// 	}

// 	// 	// b, err := hex.DecodeString(cred.Credential)
// 	// 	// if err != nil {
// 	// 	// 	log.Fatalf("Failed to decode credential: %v", err)
// 	// 	// }
// 	// 	// ec := &attest.EncryptedCredential{
// 	// 	// 	Credential: b,
// 	// 	// }

// 	// 	decryptedSecret, err := attestationKey.ActivateCredential(tpm, ec)
// 	// 	if err != nil {
// 	// 		log.Fatalf("Failed to activate credential: %v", err)
// 	// 	}
// 	// 	ec.Secret = decryptedSecret

// 	// 	resp := activateResponse{}
// 	// 	_, err = doRequest(
// 	// 		http.MethodPost,
// 	// 		"http://192.168.31.126:8443/activate",
// 	// 		&ec,
// 	// 		&resp,
// 	// 	)
// 	// 	if err != nil {
// 	// 		log.Fatalf("Failed to do activate request: %v", err)
// 	// 	}

// 	// 	fmt.Println(resp.Certificate)
// 	// }

// 	// type generateRequest struct {
// 	// 	TPMVersion            attest.TPMVersion            `json:"version" `
// 	// 	EndorsementKey        []byte                       `json:"ek" `
// 	// 	AttestationParameters attest.AttestationParameters `json:"params" `
// 	// }

// 	// // type credentialBody struct {
// 	// // 	Credential string `json:"credential"`
// 	// // 	Secret     string `json:"secret"`
// 	// // }

// 	// type activateResponse struct {
// 	// 	Certificate string `json:"certificate"`
// }
