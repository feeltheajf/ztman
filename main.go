package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/user"
	"regexp"
	"strings"
	"time"

	"github.com/feeltheajf/piv-go/piv"
	"github.com/manifoldco/promptui"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/trustelem/zxcvbn"

	"github.com/feeltheajf/ztman/config"
	"github.com/feeltheajf/ztman/fs"
	"github.com/feeltheajf/ztman/logging"
	"github.com/feeltheajf/ztman/pki"
)

const (
	datetimeFormat = "2006-01-02 15:04:05"

	filePub    = "piv.pub"
	filePubSSH = "piv-ssh.pub"
	fileIntAtt = "piv-att-intermediate.pem"
	fileAtt    = "piv-att.pem"
	fileCSR    = "piv.csr"
	fileCrt    = "piv.crt"
)

// from Go build system
var (
	version = "DEV"
)

var (
	cmd = &cobra.Command{
		Use:     config.App,
		Version: version,
		Run:     wrap(Run),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ztman version %s\n\n", version)
			level := zerolog.InfoLevel
			if flags.debug {
				level = zerolog.DebugLevel
			}
			logging.Setup(level)
		},
	}
	cmdInfo = &cobra.Command{
		Use:   "info",
		Run:   wrap(Info),
		Short: "Display general status of the PIV application",
	}
	cmdReset = &cobra.Command{
		Use:   "reset",
		Run:   wrap(Reset),
		Short: "Reset all PIV data",
	}
	cmdAttest = &cobra.Command{
		Use:   "attest",
		Run:   wrap(Attest),
		Short: "Generate a key pair and attestation certificates",
	}
	cmdImport = &cobra.Command{
		Use:   "import",
		Run:   wrap(Import),
		Short: "Write a certificate to one of the PIV slots on the YubiKey",
	}
	cmdUnblock = &cobra.Command{
		Use:   "unblock",
		Run:   wrap(Unblock),
		Short: "Unblock the PIN using PUK",
	}

	flags = struct {
		debug       bool
		force       bool
		interactive bool

		pin  string
		puk  string
		slot string
		cert string
	}{}

	regexPIN = regexp.MustCompile(`^\d{6,8}$`)
	regexPUK = regexp.MustCompile(`^\d{8}$`)
)

func wrap(command func() error) func(*cobra.Command, []string) {
	return func(*cobra.Command, []string) {
		err := command()
		code := 0
		switch err {
		case nil:
			break
		case promptui.ErrInterrupt, promptui.ErrEOF:
			log.Warn().Str("reason", err.Error()).Msg("aborted")
			os.Exit(0)
		default:
			code = 1
			log.Error().Err(err).Msg("exiting")
		}
		if flags.interactive {
			if code != 0 {
				flags.pin = ""
				flags.puk = ""
			}
			ok := confirm("Would you like to run another command")
			if ok {
				wrap(Run)(nil, nil)
			}
		}
		os.Exit(code)
	}
}

func getPIN() (string, error) {
	prompt := promptui.Prompt{
		Label: "Enter PIN (6-8 digits)",
		Validate: func(input string) error {
			if !regexPIN.MatchString(input) {
				return errors.New("invalid format")
			}
			if zxcvbn.PasswordStrength(input, nil).Score < 1 {
				return errors.New("weak PIN, avoid sequences and repetitions")
			}
			if input == flags.puk {
				return errors.New("PIN must be different from PUK")
			}
			return nil
		},
		Mask: '*',
	}
	var err error
	if !flags.force && flags.pin == "" {
		flags.pin, err = prompt.Run()
		if err != nil {
			return "", err
		}
	}
	if err := prompt.Validate(flags.pin); err != nil {
		return "", err
	}
	return flags.pin, nil
}

func getPUK() (string, error) {
	prompt := promptui.Prompt{
		Label: "Enter PUK (8 digits)",
		Validate: func(input string) error {
			if !regexPUK.MatchString(input) {
				return errors.New("invalid format")
			}
			if zxcvbn.PasswordStrength(input, nil).Score < 1 {
				return errors.New("weak PUK, avoid sequences and repetitions")
			}
			if input == flags.pin {
				return errors.New("PUK must be different from PIN")
			}
			return nil
		},
		Mask: '*',
	}
	var err error
	if !flags.force && flags.puk == "" {
		flags.puk, err = prompt.Run()
		if err != nil {
			return "", err
		}
	}
	if err := prompt.Validate(flags.puk); err != nil {
		return "", err
	}
	return flags.puk, nil
}

func getSlotInfo() (piv.Slot, piv.PINPolicy, piv.TouchPolicy, error) {
	prompt := promptui.Select{
		Label: "Select PIV slot",
		Items: []string{"9a", "9c"},
	}
	slot := flags.slot
	if !flags.force && flags.slot == "" {
		var err error
		_, slot, err = prompt.Run()
		if err != nil {
			return piv.Slot{}, 0, 0, err
		}
	}
	switch slot {
	case "9a":
		return piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, nil
	case "9c":
		return piv.SlotSignature, piv.PINPolicyAlways, piv.TouchPolicyNever, nil
	default:
		return piv.Slot{}, 0, 0, fmt.Errorf("unsupported PIV slot: %s", flags.slot)
	}
}

func confirm(label string) bool {
	if flags.force {
		return true
	}
	prompt := promptui.Select{
		Label: label,
		Items: []string{"No", "Yes"},
	}
	_, choice, _ := prompt.Run()
	return choice != "No"
}

func open() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("listing available smart cards: %w", err)
	}
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				return nil, fmt.Errorf("connecting to '%s': %w", card, err)
			}
			break
		}
	}
	if yk == nil {
		return nil, errors.New("no YubiKey detected")
	}
	return yk, nil
}

func Run() (err error) {
	flags.interactive = true
	p := promptui.Select{
		Label: "Select command",
		Items: []string{
			"Info",
			"Reset",
			"Attest",
			"Import",
			"Unblock",
		},
	}
	_, choice, err := p.Run()
	if err != nil {
		return err
	}
	switch choice {
	case "Info":
		return Info()
	case "Reset":
		return Reset()
	case "Attest":
		return Attest()
	case "Import":
		return Import()
	case "Unblock":
		return Unblock()
	default:
		return errors.New("unknown command")
	}
}

func Info() (err error) {
	yk, err := open()
	if err != nil {
		return err
	}
	defer yk.Close()

	serial, err := yk.Serial()
	if err != nil {
		return err
	}
	fmt.Printf("Serial number:       %d\n", serial)

	v := yk.Version()
	fmt.Printf("PIV version:         %d.%d.%d\n", v.Major, v.Minor, v.Patch)

	retries, err := yk.Retries()
	if err != nil {
		return err
	}
	fmt.Printf("PIN tries remaining: %d\n", retries)

	all := []piv.Slot{
		piv.SlotAuthentication,
		piv.SlotSignature,
		piv.SlotKeyManagement,
		piv.SlotCardAuthentication,
	}
	for _, slot := range all {
		crt, err := yk.Certificate(slot)
		if err != nil {
			continue
		}
		fmt.Printf("\nSlot %s:\n", slot.String())
		fmt.Printf("  Algorithm:\t%s\n", crt.SignatureAlgorithm.String())
		fmt.Printf("  Subject DN:\t%s\n", crt.Subject.String())
		fmt.Printf("  Issuer DN:\t%s\n", crt.Issuer.String())
		fmt.Printf("  Serial:\t%d\n", crt.SerialNumber)
		fmt.Printf("  Fingerprint:\t%x\n", sha256.Sum256(crt.Raw))
		fmt.Printf("  Not before:\t%s\n", crt.NotBefore.Format(datetimeFormat))
		fmt.Printf("  Not after:\t%s\n", crt.NotAfter.Format(datetimeFormat))
	}
	return nil
}

func Reset() (err error) {
	ok := confirm("Delete all stored PIV certificates and reset security codes")
	if !ok {
		return nil
	}

	pin, err := getPIN()
	if err != nil {
		return err
	}
	puk, err := getPUK()
	if err != nil {
		return err
	}

	yk, err := open()
	if err != nil {
		return err
	}
	defer yk.Close()

	log.Info().Msg("resetting YubiKey")
	if err := yk.Reset(); err != nil {
		return err
	}

	log.Info().Msg("setting PIN")
	if err := yk.SetPIN(piv.DefaultPIN, pin); err != nil {
		return err
	}

	log.Info().Msg("setting PUK")
	if err := yk.SetPUK(piv.DefaultPUK, puk); err != nil {
		return err
	}

	mk := [24]byte{}
	log.Info().Msg("setting management key")
	if _, err := io.ReadFull(rand.Reader, mk[:]); err != nil {
		return err
	}
	log.Debug().Str("mk", hex.EncodeToString(mk[:])).Msg("using")
	if err := yk.SetManagementKey(piv.DefaultManagementKey, mk); err != nil {
		return err
	}

	log.Info().Msg("storing management key on the card")
	m := &piv.Metadata{
		ManagementKey: &mk,
	}
	if err := yk.SetMetadata(mk, m); err != nil {
		return err
	}

	log.Info().Msg("success")
	return nil
}

func Attest() (err error) {
	pin, err := getPIN()
	if err != nil {
		return err
	}
	slot, pinPolicy, touchPolicy, err := getSlotInfo()
	if err != nil {
		return err
	}
	s := slot.String()

	if !flags.force {
		ok := confirm("Generate new key pair in slot " + s + ". You will have to request a new certificate")
		if !ok {
			return nil
		}
	}

	if err := fs.Mkdir(config.Path(s)); err != nil {
		return err
	}

	yk, err := open()
	if err != nil {
		return err
	}
	defer yk.Close()

	log.Info().Msg("getting management key")
	m, err := yk.Metadata(pin)
	if err != nil {
		return err
	}
	if m.ManagementKey == nil {
		return errors.New("management key not set")
	}
	mk := *m.ManagementKey
	log.Debug().Str("mk", hex.EncodeToString(mk[:])).Msg("using")

	log.Info().Msg("generating private key")
	key := piv.Key{
		Algorithm:   piv.AlgorithmRSA2048,
		PINPolicy:   pinPolicy,
		TouchPolicy: touchPolicy,
	}
	pub, err := yk.GenerateKey(mk, slot, key)
	if err != nil {
		return err
	}
	if err := pki.WritePublicKey(config.Path(s, filePub), pub); err != nil {
		return err
	}
	if err := pki.WritePublicKeySSH(config.Path(s, filePubSSH), pub); err != nil {
		return err
	}

	log.Info().Str("file", fileIntAtt).Msg("generating intermediate attestation certificate")
	intAtt, err := yk.AttestationCertificate()
	if err != nil {
		return err
	}
	if err := pki.WriteCertificate(config.Path(s, fileIntAtt), intAtt); err != nil {
		return err
	}

	log.Info().Str("file", fileAtt).Msg("generating attestation certificate")
	att, err := yk.Attest(slot)
	if err != nil {
		return err
	}
	if err := pki.WriteCertificate(config.Path(s, fileAtt), att); err != nil {
		return err
	}

	log.Info().Str("file", fileCSR).Msg("generating certificate request")
	serial, err := yk.Serial()
	if err != nil {
		return err
	}
	me, _ := user.Current()
	tpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   me.Username,
			SerialNumber: fmt.Sprintf("%d", serial),
		},
	}
	auth := piv.KeyAuth{PIN: pin}
	priv, err := yk.PrivateKey(slot, pub, auth)
	if err != nil {
		return err
	}
	csr, err := pki.NewCertificateRequest(tpl, priv)
	if err != nil {
		return err
	}
	if err := pki.WriteCertificateRequest(config.Path(s, fileCSR), csr); err != nil {
		return err
	}

	log.Info().Msg("generating self-signed certificate")
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("Self-signed certificate for '%s'", me.Username),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	b, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return err
	}
	crt, err := x509.ParseCertificate(b)
	if err != nil {
		return err
	}
	if err := yk.SetCertificate(mk, slot, crt); err != nil {
		return err
	}

	log.Info().Str("path", config.Path(s)).Msg("success")
	if flags.interactive {
		for {
			ok := confirm("Did you re-insert your YubiKey")
			if ok {
				return Info()
			}
		}
	}
	return nil
}

func Import() (err error) {
	pin, err := getPIN()
	if err != nil {
		return err
	}
	slot, _, _, err := getSlotInfo()
	if err != nil {
		return err
	}
	s := slot.String()

	if !flags.force {
		for {
			if ok := confirm("Did you request a new certificate"); ok {
				break
			}
		}
	}

	pathCrt := flags.cert
	if flags.cert == "" {
		pathCrt = config.Path(s, fileCrt)

		if !flags.force {
			for {
				fmt.Println(promptui.IconInitial, "Paste the certificate below and press Enter:")
				crtString := ""
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					line := scanner.Text()
					crtString += line + "\n"
					if line == "-----END CERTIFICATE-----" {
						break
					}
				}
				_, err := pki.UnmarshalCertificate(crtString)
				if err != nil {
					log.Error().Err(err).Msg("reading certificate")
					continue
				}
				if err := fs.Write(pathCrt, crtString); err != nil {
					return err
				}
				break
			}
		}
	}

	yk, err := open()
	if err != nil {
		return err
	}
	defer yk.Close()

	log.Info().Msg("getting management key")
	m, err := yk.Metadata(pin)
	if err != nil {
		return err
	}
	if m.ManagementKey == nil {
		return errors.New("management key not set")
	}
	mk := *m.ManagementKey
	log.Debug().Str("mk", hex.EncodeToString(mk[:])).Msg("using")

	log.Info().Str("path", pathCrt).Msg("importing certificate")
	crt, err := pki.ReadCertificate(pathCrt)
	if err != nil {
		return err
	}
	crtPub, err := pki.MarshalPublicKey(crt.PublicKey)
	if err != nil {
		return err
	}
	att, err := yk.Attest(slot)
	if err != nil {
		return err
	}
	attPub, err := pki.MarshalPublicKey(att.PublicKey)
	if err != nil {
		return err
	}
	if crtPub != attPub {
		return errors.New("certificate issued for different key pair")
	}
	if err := yk.SetCertificate(mk, slot, crt); err != nil {
		return err
	}

	if flags.interactive {
		for {
			ok := confirm("Did you re-insert your YubiKey")
			if ok {
				return Info()
			}
		}
	}

	log.Info().Msg("success")
	return nil
}

func Unblock() (err error) {
	puk, err := getPUK()
	if err != nil {
		return err
	}
	pin, err := getPIN()
	if err != nil {
		return err
	}

	yk, err := open()
	if err != nil {
		return err
	}
	defer yk.Close()

	log.Info().Msg("unblocking PIN")
	if err := yk.Unblock(puk, pin); err != nil {
		return err
	}

	log.Info().Msg("success")
	return nil
}

func main() {
	cobra.EnableCommandSorting = false
	cobra.MousetrapHelpText = ""

	cmd.CompletionOptions.DisableDefaultCmd = true

	cmd.PersistentFlags().BoolVarP(&flags.debug, "debug", "d", false, "debug mode")
	cmd.PersistentFlags().BoolVarP(&flags.force, "force", "f", false, "disable interactive prompts")

	cmdReset.Flags().StringVar(&flags.pin, "pin", "", "PIV PIN")
	cmdReset.Flags().StringVar(&flags.puk, "puk", "", "PIV PUK")

	cmdAttest.Flags().StringVar(&flags.pin, "pin", "", "PIV PIN")
	cmdAttest.Flags().StringVarP(&flags.slot, "slot", "s", "", "PIV slot")

	cmdImport.Flags().StringVar(&flags.pin, "pin", "", "PIV PIN")
	cmdImport.Flags().StringVarP(&flags.slot, "slot", "s", "", "PIV slot")
	cmdImport.Flags().StringVarP(&flags.cert, "cert", "c", "", "path to certificate")

	cmdUnblock.Flags().StringVar(&flags.pin, "pin", "", "PIV PIN")
	cmdUnblock.Flags().StringVar(&flags.puk, "puk", "", "PIV PUK")

	cmd.AddCommand(cmdInfo)
	cmd.AddCommand(cmdReset)
	cmd.AddCommand(cmdAttest)
	cmd.AddCommand(cmdImport)
	cmd.AddCommand(cmdUnblock)

	if err := cmd.Execute(); err != nil {
		os.Exit(64)
	}
}
