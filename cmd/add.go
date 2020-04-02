package cmd

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/99designs/keyring"
	"github.com/autonomic-ai/aws-okta/lib"
	"github.com/autonomic-ai/aws-okta/lib/client"
	analytics "github.com/segmentio/analytics-go"
	"github.com/spf13/cobra"
)

var (
	organization    string
	oktaDomain      string
	oktaRegion      string
	oktaAccountName string
)

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "add your okta credentials",
	RunE:  add,
}

func init() {
	RootCmd.AddCommand(addCmd)
	addCmd.Flags().StringVarP(&oktaDomain, "domain", "", "", "Okta domain (e.g. <orgname>.okta.com)")
	addCmd.Flags().StringVarP(&username, "username", "", "", "Okta username")
	addCmd.Flags().StringVarP(&oktaAccountName, "account", "", "", "Okta account name")
}

func add(cmd *cobra.Command, args []string) error {
	var allowedBackends []keyring.BackendType
	if backend != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backend))
	}
	kr, err := lib.OpenKeyring(allowedBackends)

	if err != nil {
		log.Fatal(err)
	}

	if analyticsEnabled && analyticsClient != nil {
		analyticsClient.Enqueue(analytics.Track{
			UserId: username,
			Event:  "Ran Command",
			Properties: analytics.NewProperties().
				Set("backend", backend).
				Set("aws-okta-version", version).
				Set("command", "add"),
		})
	}

	// Ask Okta organization details if not given in command line argument
	if oktaDomain == "" {
		organization, err = lib.Prompt("Okta organization", false)
		if err != nil {
			return err
		}

		oktaRegion, err = lib.Prompt("Okta region ([us], emea, preview)", false)
		if err != nil {
			return err
		}
		if oktaRegion == "" {
			oktaRegion = "us"
		}

		tld, err := client.GetOktaDomain(oktaRegion)
		if err != nil {
			return err
		}
		defaultOktaDomain := fmt.Sprintf("%s.%s", organization, tld)

		oktaDomain, err = lib.Prompt("Okta domain ["+defaultOktaDomain+"]", false)
		if err != nil {
			return err
		}
		if oktaDomain == "" {
			oktaDomain = defaultOktaDomain
		}
	}

	if username == "" {
		username, err = lib.Prompt("Okta username", false)
		if err != nil {
			return err
		}
	}

	if oktaAccountName == "" {
		oktaAccountName = "okta-creds"
	} else {
		oktaAccountName = "okta-creds-" + oktaAccountName
	}
	log.Debugf("Keyring key: %s", oktaAccountName)

	// Ask for password from prompt
	password, err := lib.Prompt("Okta password", true)
	if err != nil {
		return err
	}
	fmt.Println()

	creds := client.OktaCredential{
		Username: username,
		Password: password,
		Domain:   oktaDomain,
	}

	// Profiles aren't parsed during `add`, but still want
	// to centralize the MFA config logic
	var dummyProfiles lib.Profiles
	updateMfaConfig(cmd, dummyProfiles, "", &mfaConfig)
	creds.MFA = mfaConfig

	// Initialize and pass in MFAInputs below so as to avoid panic
	// when the client attempts to use it to choose a "factor"
	oktaClient, err := client.NewOktaClient(creds, nil, &MFAInputs{}, nil)
	if err != nil {
		return err
	}
	if err := oktaClient.AuthenticateUser(); err != nil {
		log.Debugf("Failed to validate credentials: %s", err)
		return fmt.Errorf("%w: %s", ErrFailedToValidateCredentials, err)
	}

	encoded, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	item := keyring.Item{
		Key:                         oktaAccountName,
		Data:                        encoded,
		Label:                       "okta credentials",
		KeychainNotTrustApplication: false,
	}

	if err := kr.Set(item); err != nil {
		log.Debugf("Failed to add user to keyring: %s", err)
		return ErrFailedToSetCredentials
	}

	log.Infof("Added credentials for user %s", username)
	return nil
}
