package cmd

import (
	"fmt"

	"github.com/99designs/keyring"
	analytics "github.com/segmentio/analytics-go"
	"github.com/segmentio/aws-okta/lib"
	"github.com/spf13/cobra"
)

var (
	clientId string
)

// envCmd represents the env command
var oidcCmd = &cobra.Command{
	Use:     "oidc <something>",
	Short:   "get's an OIDC token",
	RunE:    oidcRun,
	Example: "source <(aws-okta env test)",
}

func init() {
	RootCmd.AddCommand(oidcCmd)
	envCmd.Flags().StringVarP(&clientId, "client-id", "c", "", "CLient Id to use")
}

func oidcRun(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return ErrTooFewArguments
	}

	profile := args[0]
	config, err := lib.NewConfigFromEnv()
	if err != nil {
		return err
	}

	profiles, err := config.Parse()
	if err != nil {
		return err
	}

	// TODO: decouple okta auth and SAML auth
	updateMfaConfig(cmd, profiles, "okta", &mfaConfig)

	opts := lib.ProviderOptions{
		MFAConfig:          mfaConfig,
		Profiles:           profiles,
		SessionDuration:    sessionTTL,
		AssumeRoleDuration: assumeRoleTTL,
	}

	var allowedBackends []keyring.BackendType
	if backend != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backend))
	}

	kr, err := lib.OpenKeyring(allowedBackends)
	if err != nil {
		return err
	}

	if analyticsEnabled && analyticsClient != nil {
		analyticsClient.Enqueue(analytics.Track{
			UserId: username,
			Event:  "Ran Command",
			Properties: analytics.NewProperties().
				Set("backend", backend).
				Set("aws-okta-version", version).
				Set("profile", profile).
				Set("command", "env"),
		})
	}

	opts.SessionCacheSingleItem = flagSessionCacheSingleItem

	p, err := lib.NewProvider(kr, "okta", opts)
	if err != nil {
		return err
	}

	//creds, err := p.Retrieve()
	//	if err != nil {
	//		return err
	//	}
	loginURL, err := p.GetSAMLLoginURL()
	if err != nil {
		return err
	}
	fmt.Printf("Maybe one day a token: %s", loginURL)
	return nil
}
