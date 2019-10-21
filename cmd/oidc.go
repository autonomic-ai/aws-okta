package cmd

/*
currently the only things we need from the profile is the MFA config. As a short
term solution we can require the user pass the MFA config via a cli arg.

If we also setup our own credential caching we can just create and OktaProvider
or an Okta client directly and skip the multiple layers of indirection.
*/
import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/99designs/keyring"
	"github.com/segmentio/aws-okta/lib"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	clientId      string
	outputFormat  string
	outputFormats = map[string]bool{execCredentials: true, plaintext: true}
)

const (
	execCredentials = "exec-credentials"
	plaintext       = "plaintext"
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
	oidcCmd.Flags().StringVarP(&outputFormat, "output-format", "o", "exec-credentials", "Output Format [*exec-credentials|plaintext]")
	oidcCmd.MarkFlagRequired("client-id")
}

func oidcRun(cmd *cobra.Command, args []string) error {
	if clientId == "" {
		fmt.Fprintln(os.Stderr, "Error: Flag --client-id is required")
		return ErrTooFewArguments
	}

	if _, ok := outputFormats[outputFormat]; !ok {
		return fmt.Errorf("Error: unsupported output format %s", outputFormat)
	}

	config, err := lib.NewConfigFromEnv()
	if err != nil {
		return err
	}

	profiles, err := config.Parse()
	if err != nil {
		return err
	}

	log.Debug("MFA Config:\n", mfaConfig)
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

	switch outputFormat {
	case "plaintext":
		fmt.Println(idToken)
	default: /*case "exec-credentials"*/
		k8sToken := KubernetesToken{
			Kind:       "ExecCredential",
			ApiVersion: "client.authentication.k8s.io/v1alpha1",
			Spec:       map[string]string{},
			Status:     OIDCToken{Token: idToken},
		}

		output, err := json.Marshal(k8sToken)
		if err != nil {
			return err
		}

		os.Stdout.Write(output)
	}

	return nil
}

type KubernetesToken struct {
	Kind       string            `json:"kind"`
	ApiVersion string            `json:"apiVersion"`
	Spec       map[string]string `json:"spec"`
	Status     OIDCToken         `json:"status"`
}

type OIDCToken struct {
	Token string `json:"token"`
}
