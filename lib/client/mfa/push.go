package mfa

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/autonomic-ai/aws-okta/lib/client/types"
)

const (
	StatusMFAChallenge = "MFA_CHALLENGE"
	StatusMFARequired  = "MFA_REQUIRED"
	ResultWaiting      = "WAITING"
	ResultRejected     = "REJECTED"
	ResultTimeout      = "TIMEOUT"

	OktaPushDefaultPollIntervalInSeconds = 3
	OktaPushDefaultPollTimeoutInSeconds  = 120
)

// PushDevice is implementation of MFADevice for OKTA PUSH
type PushDevice struct {
	PollIntervalInSeconds int
	PollTimeoutInSeconds  int

	verifyStartTime time.Time
}

func NewPushDevice() *PushDevice {
	return &PushDevice{
		PollIntervalInSeconds: OktaPushDefaultPollIntervalInSeconds,
		PollTimeoutInSeconds:  OktaPushDefaultPollTimeoutInSeconds,
	}
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
	switch authResp.Status {
	case StatusMFARequired:
		// Setup timers here
		d.verifyStartTime = time.Now()

		// Apply sensible defaults here if not provided
		if d.PollIntervalInSeconds == 0 {
			d.PollIntervalInSeconds = OktaPushDefaultPollIntervalInSeconds
		}
		if d.PollTimeoutInSeconds == 0 {
			d.PollTimeoutInSeconds = OktaPushDefaultPollTimeoutInSeconds
		}
		fmt.Fprintf(os.Stderr, "\nApprove the push notification on your Okta Verify app...\n")
	case StatusMFAChallenge:
		switch authResp.FactorResult {
		case ResultRejected:
			// User rejected the push notification.
			return "", []byte(""), fmt.Errorf("okta push verify rejected.")
		case ResultTimeout:
			// Push notification timed out.
			return "", []byte(""), fmt.Errorf("okta push verify timed out.")
		case ResultWaiting:
			// Check if we're past the timeout
			timeout := d.verifyStartTime.Add(time.Duration(d.PollTimeoutInSeconds) * time.Second)
			if time.Now().After(timeout) {
				return "", []byte(""), fmt.Errorf("timed out while waiting for user to action okta push notification.")
			}
			// Waiting for user to action the push notification.
			time.Sleep(time.Duration(d.PollIntervalInSeconds) * time.Second)
		default:
			return "", []byte(""), fmt.Errorf("unknown factor result: %s", authResp.FactorResult)
		}

	default:
		return "", []byte(""), fmt.Errorf("unknown factor status: %s", authResp.Status)
	}

	payload, err := json.Marshal(basicPayload{
		StateToken: authResp.StateToken,
	})
	return "verify", payload, err
}
