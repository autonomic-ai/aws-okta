package lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/99designs/keyring"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	oktaAccountName = "okta-creds"
)

type OIDCProvider struct {
	keyring    keyring.Keyring
	mfaConfig  MFAConfig
	oktaClient *OktaClient
}

func NewOIDCProvider(kr keyring.Keyring, mfaConfig MFAConfig) (oidcProvider *OIDCProvider, err error) {
	var oktaCreds OktaCreds
	var item keyring.Item
	var oktaClient *OktaClient

	item, err = kr.Get(oktaAccountName)
	if err != nil {
		log.Debugf("Couldn't get okta creds from keyring: %s", err)
		return
	}

	if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
		err = errors.New("Failed to get okta credentials from your keyring.  Please make sure you have added okta credentials with `aws-okta add`")
		return
	}

	oktaClient, err = NewOktaClient(oktaCreds, &kr, mfaConfig)
	if err != nil {
		return
	}

	return &OIDCProvider{
		keyring:    kr,
		mfaConfig:  mfaConfig,
		oktaClient: oktaClient,
	}, nil
}

func (p *OIDCProvider) Retrieve(clientId string) (idToken string, err error) {
	// Check for stored id token
	var idTokenItem keyring.Item
	idTokenItem, err = p.keyring.Get(clientId)
	if err == nil {
		idToken = string(idTokenItem.Data)
		if p.validateIdToken(idToken) {
			return
		}
	}

	idToken, err = p.authenticateOIDC(clientId, map[string]string{})
	if err != nil {
		return
	}

	if !p.validateIdToken(idToken) {
		err = fmt.Errorf("Token retrieved but was invalid")
		return
	}

	newIdTokenItem := keyring.Item{
		Key:                         clientId,
		Data:                        []byte(idToken),
		Label:                       "okta OIDC Token",
		KeychainNotTrustApplication: false,
	}
	p.keyring.Set(newIdTokenItem)

	return
}

func (p *OIDCProvider) authenticateOIDC(clientId string, authOpts map[string]string) (idToken string, err error) {
	var state uuid.UUID
	var nonce uuid.UUID
	var sessionValid bool

	state, err = uuid.NewUUID()
	if err != nil {
		return
	}
	nonce, err = uuid.NewUUID()
	if err != nil {
		return
	}

	path := "oauth2/v1/authorize"
	queryParams := url.Values{}
	queryParams.Set("client_id", clientId)
	queryParams.Set("response_type", "id_token")
	queryParams.Set("scope", "openid profile groups email")
	queryParams.Set("prompt", "none")
	queryParams.Set("redirect_uri", "https://127.0.0.1:7789/callback")
	queryParams.Set("nonce", nonce.String())
	queryParams.Set("state", state.String())

	sessionValid, err = p.oktaClient.ValidateSession()
	if err != nil {
		return
	}
	if !sessionValid {
		if err = p.oktaClient.AuthenticateUser(); err != nil {
			return
		}
	}

	// Step 3 : Get SAML Assertion and retrieve IAM Roles
	log.Debug("Step: 3")
	queryParams.Set("sessionToken", p.oktaClient.UserAuth.SessionToken)
	idToken, err = p.getOIDCToken(path, queryParams, state.String())

	return
}

func (p *OIDCProvider) getOIDCToken(path string, queryParams url.Values, reqState string) (idToken string, err error) {
	var queryValues url.Values
	var redirectUrl *url.URL

	res, err := p.oktaClient.request("GET", path, queryParams, []byte(""), "json", false)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusFound {
		err = fmt.Errorf("%s %v: %s", "GET", res.Request.URL, res.Status)
	} else {
		rawUrl, ok := res.Header["Location"]
		if !ok {
			err = fmt.Errorf("Redirect Location missing.")
			return
		}
		if len(rawUrl) != 1 {
			err = fmt.Errorf("Expecting one location value got: ", rawUrl)
			return
		}
		redirectUrl, err = url.Parse(rawUrl[0])
		if err != nil {
			return
		}
		queryValues, err = url.ParseQuery(redirectUrl.Fragment)
		if err != nil {
			return
		}

		if resState := queryValues.Get("state"); resState != reqState {
			err = fmt.Errorf("Request state does not match response state")
			return
		}

		if idToken = queryValues.Get("id_token"); idToken == "" {
			log.Debug("Unable to get idToken: ", rawUrl[0])
			err = fmt.Errorf(queryValues.Get("error_description"))
		}
	}
	p.oktaClient.saveSessionCookie()
	return
}

func (p OIDCProvider) validateIdToken(idToken string) bool {
	token, _ := jwt.ParseWithClaims(idToken, &jwt.StandardClaims{}, nil)

	expiryUnix := token.Claims.(*jwt.StandardClaims).ExpiresAt
	expiry := time.Unix(expiryUnix, 0).UTC()
	now := time.Now().UTC()
	expired := now.After(expiry)

	if expired {

		log.Debug("Token expired:")
		log.Debug("  expiryUnix: ", expiryUnix)
		log.Debug("  expiry: ", expiry.String())
		log.Debug("  now: ", now.String())
	}
	return !expired
}
