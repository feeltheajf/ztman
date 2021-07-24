package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/go-piv/piv-go/piv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/feeltheajf/ztman/config"
	"github.com/feeltheajf/ztman/logging"
	"github.com/feeltheajf/ztman/pki"
)

const (
	keyAlgorithm = piv.AlgorithmEC256

	filePub    = "piv.pub"
	filePubSSH = "piv-ssh.pub"
	fileIntAtt = "piv-attestation-intermediate.crt"
	fileAtt    = "piv-attestation.crt"
	fileCrt    = "piv.crt"
)

var (
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
		Run:     wrap(Init),
		Version: config.Version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			level := zerolog.InfoLevel
			if flags.debug {
				level = zerolog.DebugLevel
			}
			logging.Setup(level)
		},
	}

	cmdInfo = &cobra.Command{
		Use: "info",
		Run: wrap(Info),
	}

	cmdInit = &cobra.Command{
		Use: "init",
		Run: wrap(Init),
	}

	flags = struct {
		debug bool

		pin  string
		puk  string
		slot string
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

		fmt.Printf("Slot %x:\n", meta.slot.Key)
		fmt.Printf("  Algorithm:\t%s\n", crt.SignatureAlgorithm)
		fmt.Printf("  Subject DN:\t%s\n", crt.Subject.String())
		fmt.Printf("  Issuer DN:\t%s\n", crt.Issuer.String())
		fmt.Printf("  Serial:\t%d\n", crt.SerialNumber)
		fmt.Printf("  Fingerprint:\t%x\n", sha256.Sum256(crt.Raw))
	}
	return nil
}

func Init(yk *piv.YubiKey) error {
	log.Info().Msg("resetting YubiKey")
	if err := yk.Reset(); err != nil {
		return err
	}

	log.Info().Msg("setting PIN")
	pin := flags.pin
	if pin == "" || pin == piv.DefaultPIN {
		pin = promptSecure("Enter PIN (6 digits): ", piv.DefaultPIN, regexp.MustCompile(`\d{6}`))
	}
	if err := yk.SetPIN(piv.DefaultPIN, pin); err != nil {
		return err
	}

	log.Info().Msg("setting PUK")
	puk := flags.puk
	if puk == "" || puk == piv.DefaultPUK {
		puk = promptSecure("Enter PUK (8 digits): ", piv.DefaultPUK, regexp.MustCompile(`\d{6}`))
	}
	if err := yk.SetPUK(piv.DefaultPUK, puk); err != nil {
		return err
	}

	log.Info().Msg("setting management key")
	mk := [24]byte{}
	_, err := io.ReadFull(rand.Reader, mk[:])
	if err != nil {
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

	s := flags.slot
	if s == "" {
		s = prompt("PIV Slot: ", "9a", "9c")
	}
	meta := slots[s]
	slot := meta.slot

	log.Info().Msgf("initializing slot %s", slot.String())
	ctx := log.With().Str("slot", slot.String()).Logger()
	if err := config.Mkdir(config.Path(s)); err != nil {
		return err
	}

	ctx.Info().Msg("generating private key")
	key := piv.Key{
		Algorithm:   keyAlgorithm,
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

	pathCrt := config.Path(slot.String(), fileCrt)
	var crt *x509.Certificate
	for {
		ctx.Info().Str("path", pathCrt).Msg("request certificate and press enter to continue")
		fmt.Scanln()

		crt, err = pki.ReadCertificate(pathCrt)
		if err != nil {
			ctx.Error().Err(err).Msg("loading certificate")
		} else {
			break
		}
	}

	if err := yk.SetCertificate(mk, slot, crt); err != nil {
		return err
	}

	return Info(yk)
}

func prompt(msg string, expected ...string) string {
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print(msg)
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}

		if expected == nil {
			return text
		}

		for _, v := range expected {
			if v == text {
				return text
			}
		}
		log.Error().Strs("expected", expected).Msg("invalid value")
	}
}

func promptSecure(msg string, defaults string, re *regexp.Regexp) string {
	for {
		fmt.Print(msg)
		b, _ := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()

		if string(b) == defaults {
			log.Error().Msg("default value is forbidden")
			continue
		}

		if !re.Match(b) {
			log.Error().Msg("invalid format")
			continue
		}

		return string(b)
	}
}

func main() {
	cmd.PersistentFlags().BoolVarP(&flags.debug, "debug", "d", false, "enable debug logging")

	cmdInit.Flags().StringVar(&flags.pin, "pin", "", "PIV PIN")
	cmdInit.Flags().StringVar(&flags.puk, "puk", "", "PIV PUK")
	cmdInit.Flags().StringVarP(&flags.slot, "slot", "s", "", "PIV slot to initialize")

	cmd.AddCommand(cmdInfo)
	cmd.AddCommand(cmdInit)

	if err := cmd.Execute(); err != nil {
		os.Exit(64)
	}
}
