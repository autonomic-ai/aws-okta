package mfa

import (
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	u2fhost "github.com/marshallbrekka/go-u2fhost"
)

const (
	MaxOpenRetries = 10
	RetryDelayMS   = 200 * time.Millisecond
)

type FidoClient struct {
	ChallengeNonce string
	AppId          string
	Version        string
	Device         u2fhost.Device
	KeyHandle      string
	StateToken     string
}

type SignedAssertion struct {
	StateToken    string `json:"stateToken"`
	ClientData    string `json:"clientData"`
	SignatureData string `json:"signatureData"`
}

func NewFidoClient(challengeNonce, appId, version, keyHandle, stateToken string) FidoClient {
	// Filter only the devices that can be opened.
	openDevices := []u2fhost.Device{}
	allDevices := u2fhost.Devices()
	for i, device := range allDevices {
		log.Debug("Test Open for device: ", device)

		retry_count := 0
		for retry_count < MaxOpenRetries {
			err := device.Open()
			if err == nil {
				openDevices = append(openDevices, allDevices[i])
				defer func(i int) {
					allDevices[i].Close()
				}(i)
				break
			} else {
				log.Debug(err)
				retry_count += 1
				time.Sleep(RetryDelayMS)
			}
		}
	}
	if len(openDevices) != 1 {
		log.Debug("Got ", len(openDevices), " expecting 1 ")
		return FidoClient{}
	}
	return FidoClient{
		Device:         openDevices[0],
		ChallengeNonce: challengeNonce,
		AppId:          appId,
		Version:        version,
		KeyHandle:      keyHandle,
		StateToken:     stateToken,
	}
}

func (d *FidoClient) ChallengeU2f() (*SignedAssertion, error) {

	if d.Device == nil {
		return nil, errors.New("No Device Found")
	}
	request := &u2fhost.AuthenticateRequest{
		Challenge: d.ChallengeNonce,
		// the appid is the only facet.
		Facet:     d.AppId,
		AppId:     d.AppId,
		KeyHandle: d.KeyHandle,
	}
	// do the change
	prompted := false
	timeout := time.After(time.Second * 25)
	interval := time.NewTicker(time.Millisecond * 250)
	var responsePayload *SignedAssertion

	d.Device.Open()

	defer func() {
		d.Device.Close()
	}()
	defer interval.Stop()
	for {
		select {
		case <-timeout:
			return nil, errors.New("Failed to get authentication response after 25 seconds")
		case <-interval.C:
			response, err := d.Device.Authenticate(request)
			if err == nil {
				responsePayload = &SignedAssertion{
					StateToken:    d.StateToken,
					ClientData:    response.ClientData,
					SignatureData: response.SignatureData,
				}
				fmt.Println("  ==> Touch accepted. Proceeding with authentication\n")
				return responsePayload, nil
			} else {
				switch t := err.(type) {
				case *u2fhost.TestOfUserPresenceRequiredError:
					if !prompted {
						fmt.Println("\nTouch the flashing U2F device to authenticate...\n")
						prompted = true
					}
				default:
					log.Debug("Got ErrType: ", t)
					return responsePayload, err
				}
			}

		}
	}
	return responsePayload, nil
}
