package lib

import (
	"os"

	"github.com/99designs/keyring"
	"github.com/segmentio/aws-okta/lib/util"
)

func keyringPrompt(prompt string) (string, error) {
	return util.PromptWithOutput(prompt, true, os.Stderr)
}

func OpenKeyring(allowedBackends []keyring.BackendType) (kr keyring.Keyring, err error) {
	kr, err = keyring.Open(keyring.Config{
		AllowedBackends:          allowedBackends,
		KeychainTrustApplication: true,
		// this keychain name is for backwards compatibility
		ServiceName:             "aws-okta-login",
		LibSecretCollectionName: "awsvault",
		FileDir:                 "~/.aws-okta/",
		FilePasswordFunc:        keyringPrompt,
	})

	return
}
