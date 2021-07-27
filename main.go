package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"regexp"
	"strings"

	"github.com/feeltheajf/piv-go/piv"
	"github.com/manifoldco/promptui"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/feeltheajf/ztman/config"
	"github.com/feeltheajf/ztman/logging"
	"github.com/feeltheajf/ztman/pki"
)

const (
	datetimeFormat = "2006-01-02 15:04:05"

	filePub    = "piv.pub"
	filePubSSH = "piv-ssh.pub"
	fileIntAtt = "piv-attestation-intermediate.crt"
	fileAtt    = "piv-attestation.crt"
	fileCSR    = "piv.csr"
	fileCrt    = "piv.crt"
)

var (
	Version = "DEV" // from Go build system

	promptCmd = promptui.Select{
		Label: "Select command",
		Items: []string{"info", "init", "update"},
	}
	promptReset = promptui.Prompt{
		Label:     "Reset PIV (delete all certificates on YubiKey)",
		IsConfirm: true,
	}
	promptPIN = promptui.Prompt{
		Label:    "Enter PIN (6 digits)",
		Validate: validatePassword(regexp.MustCompile(`^\d{6}$`), piv.DefaultPIN),
		Mask:     '*',
	}
	promptPUK = promptui.Prompt{
		Label:    "Enter PUK (8 digits)",
		Validate: validatePassword(regexp.MustCompile(`^\d{8}$`), piv.DefaultPUK),
		Mask:     '*',
	}
	promptSlot = promptui.Select{
		Label: "Select PIV slot",
		Items: []string{"9a", "9c"},
	}

	slots = map[string]*meta{
		"9a": {
			piv.SlotAuthentication,
			piv.PINPolicyOnce,
			piv.TouchPolicyNever,
		},
		"9c": {
			piv.SlotSignature,
			piv.PINPolicyAlways,
			piv.TouchPolicyNever,
		},
	}

	cmd = &cobra.Command{
		Use:     config.App,
		Version: Version,
		Run: wrap(func(yk *piv.YubiKey) error {
			_, cmd, _ := promptCmd.Run()
			switch cmd {
			case "info":
				return Info(yk)
			case "init":
				return Init(yk)
			case "update":
				return Update(yk)
			default:
				return errors.New("unknown command")
			}
		}),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
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
		Short: "Display general status",
	}
	cmdInit = &cobra.Command{
		Use:   "init",
		Run:   wrap(Init),
		Short: "Init YubiKey PIV slots",
	}
	cmdUpdate = &cobra.Command{
		Use:   "update",
		Run:   wrap(Update),
		Short: "Update PIV certificate",
	}

	flags = struct {
		debug bool

		reset bool
		pin   string
		puk   string
		slot  string
	}{}
)

type meta struct {
	slot        piv.Slot
	pinPolicy   piv.PINPolicy
	touchPolicy piv.TouchPolicy
}

func wrap(command func(yk *piv.YubiKey) error) func(*cobra.Command, []string) {
	return func(*cobra.Command, []string) {
		cards, err := piv.Cards()
		if err != nil {
			log.Fatal().Err(err).Msg("listing available smart cards")
		}

		var yk *piv.YubiKey
		for _, card := range cards {
			if strings.Contains(strings.ToLower(card), "yubikey") {
				if yk, err = piv.Open(card); err != nil {
					log.Fatal().Err(err).Msg("connecting to YubiKey")
				}
				break
			}
		}
		if yk == nil {
			log.Fatal().Msg("no YubiKey detected")
		}
		defer yk.Close()

		if err := command(yk); err != nil {
			log.Fatal().Err(err).Msg("fatal")
		}
	}
}

func validatePassword(re *regexp.Regexp, defaults string) func(string) error {
	return func(input string) error {
		if input == defaults {
			return errors.New("default value is forbidden")
		}
		if !re.MatchString(input) {
			return errors.New("invalid format")
		}
		return nil
	}
}

func Info(yk *piv.YubiKey) error {
	v := yk.Version()
	fmt.Printf("PIV version: %d.%d.%d\n", v.Major, v.Minor, v.Patch)

	retries, err := yk.Retries()
	if err != nil {
		return err
	}
	fmt.Printf("PIN tries remaining: %d\n", retries)

	for _, meta := range slots {
		crt, err := yk.Certificate(meta.slot)
		if err != nil {
			continue
		}

		fmt.Printf("Slot %s:\n", meta.slot.String())
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

func Init(yk *piv.YubiKey) error {
	reset := flags.reset
	if !reset {
		choice, _ := promptReset.Run()
		reset = strings.ToLower(choice) == "y"
	}
	if reset {
		log.Info().Msg("resetting YubiKey")
		if err := yk.Reset(); err != nil {
			return err
		}
	}

	pin := flags.pin
	if pin == "" || pin == piv.DefaultPIN {
		pin, _ = promptPIN.Run()
	}
	if reset {
		log.Info().Msg("setting PIN")
		if err := yk.SetPIN(piv.DefaultPIN, pin); err != nil {
			return err
		}
	}

	if reset {
		puk := flags.puk
		if puk == "" || puk == piv.DefaultPUK {
			puk, _ = promptPUK.Run()
		}
		log.Info().Msg("setting PUK")
		if err := yk.SetPUK(piv.DefaultPUK, puk); err != nil {
			return err
		}
	}

	mk := [24]byte{}
	if reset {
		log.Info().Msg("setting management key")
		if _, err := io.ReadFull(rand.Reader, mk[:]); err != nil {
			return err
		}
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
	} else {
		log.Info().Msg("getting management key")
		m, err := yk.Metadata(pin)
		if err != nil {
			return err
		}
		if m.ManagementKey == nil {
			return errors.New("management key not set")
		}
		mk = *m.ManagementKey
	}
	log.Debug().Str("mk", hex.EncodeToString(mk[:])).Msg("using")

	s := flags.slot
	if s == "" {
		_, s, _ = promptSlot.Run()
	}
	meta := slots[s]
	slot := meta.slot
	ctx := log.With().Str("slot", slot.String()).Logger()
	if err := config.Mkdir(config.Path(s)); err != nil {
		return err
	}

	ctx.Info().Msg("generating private key")
	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   meta.pinPolicy,
		TouchPolicy: meta.touchPolicy,
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

	ctx.Info().Msg("loading intermediate attestation statement")
	intAtt, err := yk.AttestationCertificate()
	if err != nil {
		return err
	}
	if err := pki.WriteCertificate(config.Path(s, fileIntAtt), intAtt); err != nil {
		return err
	}

	ctx.Info().Msg("generating attestation statement")
	att, err := yk.Attest(slot)
	if err != nil {
		return err
	}
	if err := pki.WriteCertificate(config.Path(s, fileAtt), att); err != nil {
		return err
	}

	ctx.Info().Msg("generating certificate request")
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

	pathCrt := config.Path(slot.String(), fileCrt)
	var crt *x509.Certificate
	p := promptui.Prompt{
		Label: "Request certificate and save it to " + pathCrt,
		Validate: func(input string) error {
			crt, err = pki.ReadCertificate(pathCrt)
			return err
		},
	}
	p.Run()

	ctx.Info().Msg("setting certificate")
	if err := yk.SetCertificate(mk, slot, crt); err != nil {
		return err
	}

	return Info(yk)
}

func Update(yk *piv.YubiKey) error {
	pin := flags.pin
	if pin == "" || pin == piv.DefaultPIN {
		pin, _ = promptPIN.Run()
	}

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

	s := flags.slot
	if s == "" {
		_, s, _ = promptSlot.Run()
	}
	meta := slots[s]
	slot := meta.slot
	ctx := log.With().Str("slot", slot.String()).Logger()

	pathCrt := config.Path(slot.String(), fileCrt)
	crt, err := pki.ReadCertificate(pathCrt)
	if err != nil {
		return err
	}
	ctx.Info().Msg("setting certificate")
	if err := yk.SetCertificate(mk, slot, crt); err != nil {
		return err
	}

	return Info(yk)
}

func main() {
	cmd.CompletionOptions.DisableDefaultCmd = true

	cmd.PersistentFlags().BoolVarP(&flags.debug, "debug", "d", false, "enable debug logging")
	cmd.PersistentFlags().StringVarP(&flags.pin, "pin", "p", "", "PIV PIN")
	cmd.PersistentFlags().StringVarP(&flags.slot, "slot", "s", "", "PIV slot")

	cmdInit.Flags().BoolVar(&flags.reset, "reset", false, "reset PIV application")
	cmdInit.Flags().StringVar(&flags.puk, "puk", "", "PIV PUK")

	cmd.AddCommand(cmdInfo)
	cmd.AddCommand(cmdInit)
	cmd.AddCommand(cmdUpdate)

	if err := cmd.Execute(); err != nil {
		os.Exit(64)
	}
}
