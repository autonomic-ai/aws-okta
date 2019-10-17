package cmd

/*
currently the only things we need from the profile is the MFA config. As a short
term solution we can require the user pass the MFA config via a cli arg.

If we also setup our own credential caching we can just create and OktaProvider
or an Okta client directly and skip the multiple layers of indirection.

TODO: figure out caching and what would be stored in the keyring.

*/
import (
	"encoding/json"
	"os"

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
	/*
	   {"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1alpha1","spec":{},"status":{"token":"alicloud.v1.tokenaHR0cHM6Ly9zdHMuYWxpeXVuY3MuY29tLz9BY2Nlc3NLZXlJZD1MVEFJbGZnOFY0bVpNa0YwJkFjdGlvbj1HZXRDYWxsZXJJZGVudGl0eSZGb3JtYXQ9SlNPTiZSZWdpb25JZD1jbi1zaGFuZ2hhaSZTaWduYXR1cmU9ZTBDSkY3QmdBJTJGMDJJd1hxeUNOUXZnbnM3UFklM0QmU2lnbmF0dXJlTWV0aG9kPUhNQUMtU0hBMSZTaWduYXR1cmVOb25jZT03Zjg3NTg3MzhjZDc0ZGIzYjBkNDY0MDcyOTQ2ODBjZiZTaWduYXR1cmVUeXBlPSZTaWduYXR1cmVWZXJzaW9uPTEuMCZUaW1lc3RhbXA9MjAxOS0xMC0xN1QyMCUzQTMyJTNBMjhaJlZlcnNpb249MjAxNS0wNC0wMQ=="}}
	*/
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
	//fmt.Println(string(output))
	//"{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1alpha1","spec":{},"status":{"token":""}} %s", idToken)
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
