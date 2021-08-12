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
	"github.com/feeltheajf/ztman/fs"
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
	version = "DEV" // from Go build system

	promptCmd = promptui.Select{
		Label: "Select command",
		Items: []string{"info", "reset", "attest", "import"},
	}
	promptReset = promptui.Select{
		Label: "Reset the YubiKey PIV application (delete all certificates)",
		Items: []string{"no", "yes"},
	}
	promptPIN = promptui.Prompt{
		Label:    "Enter PIN (6-8 digits)",
		Validate: validatePassword(regexp.MustCompile(`^\d{6,8}$`), piv.DefaultPIN),
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
	promptExit = promptui.Select{
		Label: "Press enter to exit",
		Items: []string{"ok"},
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
		Version: version,
		Run: wrap(func(yk *piv.YubiKey) error {
			_, cmd, err := promptCmd.Run()
			if err != nil {
				return err
			}
			switch cmd {
			case "info":
				return Info(yk)
			case "reset":
				return Reset(yk)
			case "attest":
				return Attest(yk)
			case "import":
				return Import(yk)
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

	flags = struct {
		debug bool
		force bool

		pin  string
		puk  string
		slot string
		cert string
	}{}
)

type meta struct {
	slot        piv.Slot
	pinPolicy   piv.PINPolicy
	touchPolicy piv.TouchPolicy
}

func open() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}

	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				return nil, err
			}
			break
		}
	}
	if yk == nil {
		return nil, errors.New("no YubiKey detected")
	}

	return yk, nil
}

func wrap(command func(yk *piv.YubiKey) error) func(*cobra.Command, []string) {
	return func(*cobra.Command, []string) {
		yk, err := open()
		if err != nil {
			log.Error().Err(err).Msg("connecting to YubiKey")
			exit(1)
		}
		defer yk.Close()

		switch err := command(yk); err {
		case nil, promptui.ErrInterrupt, promptui.ErrEOF:
			exit(0)
		default:
			log.Error().Err(err).Msg("fatal")
			exit(1)
		}
	}
}

func exit(code int) {
	if config.Sht && !flags.force {
		promptExit.Run() // #nosec G104
	}
	os.Exit(code)
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

func Info(yk *piv.YubiKey) (err error) {
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

func Reset(yk *piv.YubiKey) (err error) {
	if !flags.force {
		_, choice, err := promptReset.Run()
		if err != nil {
			return err
		}
		if choice != "yes" {
			return nil
		}
	}

	log.Info().Msg("resetting YubiKey")
	if err := yk.Reset(); err != nil {
		return err
	}

	pin := flags.pin
	if pin == "" || pin == piv.DefaultPIN {
		pin, err = promptPIN.Run()
		if err != nil {
			return err
		}
	}
	log.Info().Msg("setting PIN")
	if err := yk.SetPIN(piv.DefaultPIN, pin); err != nil {
		return err
	}

	puk := flags.puk
	if puk == "" || puk == piv.DefaultPUK {
		puk, err = promptPUK.Run()
		if err != nil {
			return err
		}
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

	log.Info().Msg("finished")
	return nil
}

func Attest(yk *piv.YubiKey) (err error) {
	pin := flags.pin
	if pin == "" || pin == piv.DefaultPIN {
		pin, err = promptPIN.Run()
		if err != nil {
			return err
		}
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
		_, s, err = promptSlot.Run()
		if err != nil {
			return err
		}
	}
	meta := slots[s]
	slot := meta.slot
	ctx := log.With().Str("slot", slot.String()).Logger()
	if err := fs.Mkdir(config.Path(s)); err != nil {
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

	ctx.Info().Msg("generating intermediate attestation certificate")
	intAtt, err := yk.AttestationCertificate()
	if err != nil {
		return err
	}
	if err := pki.WriteCertificate(config.Path(s, fileIntAtt), intAtt); err != nil {
		return err
	}

	ctx.Info().Msg("generating attestation certificate")
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

	ctx.Info().Str("path", config.Path(s)).Msg("finished")
	return nil
}

func Import(yk *piv.YubiKey) (err error) {
	pin := flags.pin
	if pin == "" || pin == piv.DefaultPIN {
		pin, err = promptPIN.Run()
		if err != nil {
			return err
		}
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
		_, s, err = promptSlot.Run()
		if err != nil {
			return err
		}
	}
	meta := slots[s]
	slot := meta.slot
	ctx := log.With().Str("slot", slot.String()).Logger()

	if flags.cert == "" {
		flags.cert = config.Path(slot.String(), fileCrt)
	}
	if !flags.force {
		p := promptui.Select{
			Label: "Import certificate from " + flags.cert,
			Items: []string{"ok"},
		}
		_, _, err := p.Run()
		if err != nil {
			return err
		}
	}

	ctx.Info().Str("path", flags.cert).Msg("importing certificate")
	crt, err := pki.ReadCertificate(flags.cert)
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

	ctx.Info().Msg("finished")
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

	cmd.AddCommand(cmdInfo)
	cmd.AddCommand(cmdReset)
	cmd.AddCommand(cmdAttest)
	cmd.AddCommand(cmdImport)

	if err := cmd.Execute(); err != nil {
		os.Exit(64)
	}
}
