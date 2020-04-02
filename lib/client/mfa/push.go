package mfa

import (
	"encoding/json"
	"fmt"

	"github.com/autonomic-ai/aws-okta/lib/client/types"
)

const (
	StatusMFAChallenge = "MFA_CHALLENGE"
	ResultWaiting      = "WAITING"
	ResultRejected     = "REJECTED"
	ResultTimeout      = "TIMEOUT"
)

// PushDevice is implementation of MFADevice for OKTA PUSH
type PushDevice struct {
}

// Supported will check if the mfa config can be used by this device
func (d *PushDevice) Supported(factor Config) error {
	// this is the Okta factor type and is always "puh" when provider is "Okta"
	// more details: https://developer.okta.com/docs/reference/api/factors/#factor-type
	if factor.FactorType == "push" && factor.Provider == "OKTA" {
		return nil
	}

	return fmt.Errorf("oktapush doesn't support %s %w", factor.FactorType, types.ErrNotSupported)
}

// Verify is called to get generate the payload that will be sent to Okta.
func (d *PushDevice) Verify(authResp types.OktaUserAuthn) (string, []byte, error) {
	if authResp.Status == StatusMFAChallenge {
		if authResp.FactorResult == ResultRejected {
			return "", []byte(""), fmt.Errorf("Okta push verify rejected.")
		} else if authResp.FactorResult == ResultTimeout {
			return "", []byte(""), fmt.Errorf("Okta push verify timed out.")
		}
	}

	payload, err := json.Marshal(basicPayload{
		StateToken: authResp.StateToken,
	})
	return "verify", payload, err
}
