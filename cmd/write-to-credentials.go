package cmd

// N.B. This file implements an ancillary command that is only included in this
// repository for convenience. As a result, it is maintained by @apechimp.
// Please request a review from him if you are submitting a pull request
// against this file.

import (
	"fmt"
	"os"
	"time"

	analytics "github.com/segmentio/analytics-go"
	"github.com/autonomic-ai/aws-okta/lib"
	"github.com/autonomic-ai/aws-okta/lib/provider"
	"github.com/spf13/cobra"
	ini "gopkg.in/ini.v1"
)

// writeToCredentialsCmd represents the write-to-credentials command
var writeToCredentialsCmd = &cobra.Command{
	Use: "write-to-credentials <profile> <credentials-file>",
	// N.B. The credentials file is a required argument so that the command makes
	// it clear which file will be written to.
	Short:     "write-to-credentials writes credentials for the specified profile to the specified credentials file",
	RunE:      writeToCredentialsRun,
	Example:   "aws-okta write-to-credentials test ~/.aws/credentials",
	ValidArgs: listProfileNames(mustListProfiles()),
}

func init() {
	RootCmd.AddCommand(writeToCredentialsCmd)
	writeToCredentialsCmd.Flags().DurationVarP(&sessionTTL, "session-ttl", "t", time.Hour, "Expiration time for okta role session")
	writeToCredentialsCmd.Flags().DurationVarP(&assumeRoleTTL, "assume-role-ttl", "a", time.Hour, "Expiration time for assumed role")
}

func writeToCredentialsRun(cmd *cobra.Command, args []string) error {
	if len(args) < 2 {
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

	if _, ok := profiles[profile]; !ok {
		return fmt.Errorf("profile '%s' not found in your aws config. Use list command to see configured profiles", profile)
	}

	updateMfaConfig(cmd, profiles, profile, &mfaConfig)

	// check for an assume_role_ttl in the profile if we don't have a more explicit one
	if !cmd.Flags().Lookup("assume-role-ttl").Changed {
		if err := updateDurationFromConfigProfile(profiles, profile, &assumeRoleTTL); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not parse duration from profile config")
		}
	}

	credFilePath := args[1]
	_, err = os.Stat(credFilePath)
	if err != nil {
		return err
	}

	opts := provider.AWSSAMLProviderOptions{
		Profiles:           profiles,
		SessionDuration:    sessionTTL,
		AssumeRoleDuration: assumeRoleTTL,
	}

	if analyticsEnabled && analyticsClient != nil {
		analyticsClient.Enqueue(analytics.Track{
			UserId: username,
			Event:  "Ran Command",
			Properties: analytics.NewProperties().
				Set("backend", backend).
				Set("aws-okta-version", version).
				Set("profile", profile).
				Set("command", "writeToCredentials"),
		})
	}

	p, err := createAWSSAMLProvider(backend, mfaConfig, profile, opts)
	if err != nil {
		return err
	}

	creds, err := p.Retrieve()
	if err != nil {
		return err
	}
	credIni, err := ini.Load(credFilePath)
	if err != nil {
		return err
	}
	section := credIni.Section(profile)
	section.Key("aws_access_key_id").SetValue(creds.AccessKeyID)
	section.Key("aws_secret_access_key").SetValue(creds.SecretAccessKey)
	section.Key("aws_session_token").SetValue(creds.SessionToken)
	section.Key("aws_security_token").SetValue(creds.SessionToken)

	credFile, err := os.OpenFile(credFilePath, os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = credIni.WriteTo(credFile)
	if err != nil {
		return err
	}
	err = credFile.Close()
	if err != nil {
		return err
	}

	return nil
}
