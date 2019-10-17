package cmd

/*
currently the only things we need from the profile is the MFA config. As a short
term solution we can require the user pass the MFA config via a cli arg.

If we also setup our own credential caching we can just create and OktaProvider
or an Okta client directly and skip the multiple layers of indirection.

TODO: figure out caching and what would be stored in the keyring.

*/
import (
	"fmt"

	"github.com/99designs/keyring"
	"github.com/segmentio/aws-okta/lib"
	"github.com/spf13/cobra"
)

var (
	clientId string
)

// oidcCmd represents the oidc command
var oidcCmd = &cobra.Command{
	Use:     "oidc",
	Short:   "get's an OIDC token",
	RunE:    oidcRun,
	Example: "source < (aws-okta env test)",
}

func init() {
	RootCmd.AddCommand(oidcCmd)
	oidcCmd.Flags().StringVarP(&clientId, "client-id", "c", "", "Client Id to use")
}

func oidcRun(cmd *cobra.Command, args []string) error {
	//	if len(args) < 1 {
	//		return ErrTooFewArguments
	//	}

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

	opts.SessionCacheSingleItem = flagSessionCacheSingleItem

	p, err := lib.NewProvider(kr, "okta", opts)
	if err != nil {
		return err
	}

	idToken, err := p.GetOIDCToken(clientId)
	if err != nil {
		return err
	}
	fmt.Printf("Maybe one day a token :fingerscrossed: : %s", idToken)
	return nil
}
