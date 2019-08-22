package cmd

import (
	"github.com/99designs/keyring"
	"github.com/segmentio/aws-okta/lib"
	"github.com/spf13/cobra"
)

var termCmd = &cobra.Command{
	Use:   "terminate <profile>",
	Short: "terminates the session for provided profile",
	RunE:  termRun,
}

func init() {
	RootCmd.AddCommand(termCmd)
}

func termRun(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
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

	var allowedBackends []keyring.BackendType
	if backend != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backend))
	}

	kr, err := lib.OpenKeyring(allowedBackends)
	if err != nil {
		return err
	}

	k, err := lib.NewKeyringSessions(kr, profiles)
	if err != nil {
		return err
	}
	_, err = k.Delete(profile)
	if err != nil {
		return err
	}
	return nil
}
