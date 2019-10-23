// Client for making requests to Okta APIs
package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/99designs/keyring"
	"github.com/segmentio/aws-okta/lib"
	"github.com/segmentio/aws-okta/lib/mfa"
	log "github.com/sirupsen/logrus"
)

const (
	OktaServerUs      = "okta.com"
	OktaServerEmea    = "okta-emea.com"
	OktaServerPreview = "oktapreview.com"
	OktaServerDefault = OktaServerUs

	// deprecated; use OktaServerUs
	OktaServer = OktaServerUs

	Timeout = time.Duration(60 * time.Second)
)

type OktaUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type OktaClient struct {
	creds        OktaCredential
	UserAuth     *OktaUserAuthn
	DuoClient    *lib.DuoClient
	SessionToken string
	Expiration   time.Time
	CookieJar    http.CookieJar
	BaseURL      *url.URL
	MFAConfig    MFAConfig
	Keyring      *keyring.Keyring
	client       http.Client
}

type MFAConfig struct {
	Provider   string // Which MFA provider to use when presented with an MFA challenge
	FactorType string // Which of the factor types of the MFA provider to use
	DuoDevice  string // Which DUO device to use for DUO MFA
}

// type: OktaCredential struct stores Okta credentials and domain information that will
// be used by OktaClient when making API calls to Okta
type OktaCredential struct {
	Username string
	Password string
	Domain   string
}

// Checks the validity of OktaCredential and should be called before
// using the credentials to make API calls.
//
// This public method will only validate that credentials exist, it will NOT
// validate them for correctness. To validate correctness an OktaClient must be
// used to make a request to Okta.
func (c *OktaCredential) IsValid() bool {
	return c.Username != "" && c.Password != "" && c.Domain != ""
}

// Will fetch your Okta username, password, and domain from your keyring secret
// backend.
//
// Will get the default credentials stored under the `okta-creds` key.
//
// feat-request: add support for getting additional sets of credentials.
// The interface for this functionality needs to be defined, it's
// possible to then implement alternative credential backends
// to flexibly support alternative implementations.
func GetOktaCredentialFromKeyring(kr keyring.Keyring) (OktaCredential, error) {
	var oktaCreds OktaCredential

	item, err := kr.Get("okta-creds")
	if err != nil {
		return oktaCreds, err
	}

	if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
		return oktaCreds, fmt.Errorf("Failed to get okta credentials from your keyring.  Please make sure you have added okta credentials with `aws-okta add`")
	}
	return oktaCreds, nil
}

// looks up the okta domain based on the region. For example, the okta domain
// for "us" is `okta.com` making your api domain as `<your-org>.okta.com`
func GetOktaDomain(region string) (string, error) {
	switch region {
	case "us":
		return OktaServerUs, nil
	case "emea":
		return OktaServerEmea, nil
	case "preview":
		return OktaServerPreview, nil
	}
	return "", fmt.Errorf("invalid region %s", region)
}

// Creates and initializes an OktaClient. This is intended to provide a simple
// way to create a client that can make requests to the Okta APIs.
//
// As an example for how a client might be used:
// This client can then be passed to a provider that will manage auth
// for other platforms. Currently AWS SAML provider is supported to get STS
// credentials to get access to AWS services.
//
// Supported configuration options:
//       TODO: expand on configuration options and add tests.
//
// -- proxy config: TBD
// -- session caching: Passing in a keyring will enable support for caching.
//      this will cache a valid okta session securely in the keyring. This
//			session is only for access to the Okta APIs, any additional sessions
//			(for example, aws STS credentials) will be cached by the provider that
//      creates them.
func NewOktaClient(creds OktaCredential, kr *keyring.Keyring, mfaConfig MFAConfig) (*OktaClient, error) {

	if creds.IsValid() {
		log.Debug("Credentials are valid :", creds.Username, " @ ", creds.Domain)
	} else {
		return nil, errors.New("credentials aren't complete. To remedy this, re-add your credentials with `aws-okta add`")
	}

	// url parse & set base
	base, err := url.Parse(fmt.Sprintf(
		"https://%s", creds.Domain,
	))
	if err != nil {
		return nil, err
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}

	transCfg := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: Timeout,
	}

	client := http.Client{
		Transport: transCfg,
		Timeout:   Timeout,
		Jar:       jar,
	}

	oktaClient := OktaClient{
		creds: creds,
		// remove this now that we're storing the client
		CookieJar: jar,
		BaseURL:   base,
		MFAConfig: mfaConfig,
		UserAuth:  &OktaUserAuthn{},
		Keyring:   kr,
		client:    client,
	}

	// this can fail if we don't have have a backend defined.
	// failing to retrived a cached cookie shouldn't fail the entire
	// operation.
	err = oktaClient.retrieveSessionCookie()
	if err != nil {
		// log the error to debug and continue
		log.Debug("func:NewOktaClient ", err)
	}
	return &oktaClient, nil
}

// Gets the Okta session cookie and stores it in the cookie jar used by the
// http client which is used as the primary authentication mechanism.
//
// If a keyring isn't provided to the client then an error will be returned.
// This error indicates that the session wasn't retrieved and should be handled
// appropriately.
func (o *OktaClient) retrieveSessionCookie() (err error) {

	if o.Keyring == nil {
		return fmt.Errorf("Session NOT retrieved. Reason: Session Backend not defined")
	}
	cookieItem, err := (*o.Keyring).Get(o.getSessionCookieKeyringKey())
	if err == nil {
		o.CookieJar.SetCookies(o.BaseURL, []*http.Cookie{
			{
				Name:  "sid",
				Value: string(cookieItem.Data),
			},
		})
		log.Debug("Using Okta session: ", string(cookieItem.Data))
	}

	return
}

// returns the sesion key that is username and domain aware.
func (o *OktaClient) getSessionCookieKeyringKey() string {
	return "okta-session-cookie-" + o.creds.Username + "-" + o.creds.Domain
}

// Takes a session cookie in the cookie jar and saves it in the keychain,
// this allows it to be used across invocations where the client making the
// request is destroyed/created between requests.
func (o *OktaClient) SaveSessionCookie() (err error) {

	if o.Keyring == nil {
		return fmt.Errorf("Session NOT saved. Reason: Session Backend not defined")
	}
	cookies := o.CookieJar.Cookies(o.BaseURL)
	for _, cookie := range cookies {
		if cookie.Name == "sid" {
			newCookieItem := keyring.Item{
				Key:                         o.getSessionCookieKeyringKey(),
				Data:                        []byte(cookie.Value),
				Label:                       "okta session cookie for " + o.creds.Username,
				KeychainNotTrustApplication: false,
			}
			err = (*o.Keyring).Set(newCookieItem)
			if err != nil {
				return
			}
			log.Debug("Saving Okta Session Cookie: ", cookie.Value)
		}
	}
	return
}

// Sends a request to the Okta Sessions API to validate if the session cookie
// is valid or not. This doesn't always mean that the session can be used for
// all Okta applications but it does accurately fetch the state of the session.
func (o *OktaClient) ValidateSession() (sessionValid bool, err error) {
	var mySessionResponse *http.Response
	sessionValid = false

	log.Debug("Checking if we have a valid Okta session")
	mySessionResponse, err = o.Request("GET", "api/v1/sessions/me", url.Values{}, []byte{}, "json", false)
	if err != nil {
		return
	}
	defer mySessionResponse.Body.Close()

	// https://developer.okta.com/docs/reference/api/sessions/#get-current-session
	// "if the session is invalid, a 404 Not Found response will be returned."
	// checking for ok status (200) is adequate to see if the session is still valid.
	sessionValid = mySessionResponse.StatusCode == http.StatusOK

	return
}

// Will authenticate a user and create a new session. Depending on how the Okta
// domain is configured MFA may be requested. Authentication flow supports
// several different MFA types including:
//
// SMS: Okta will send an SMS to the user that includes a code that needs to be
//      sent back as the verify step.
// PUSH: Either OKTA verify or DUO are supported.
// U2F: a u2f hardware token, eg. Yubikey
//
// TODO: document full list of MFA supported and create tests
//
// More details about the auth flow implemented by this client can be found in
// Okta documentation: https://developer.okta.com/docs/reference/api/authn
//
func (o *OktaClient) AuthenticateUser() (err error) {
	var payload []byte
	//TODO(switj): cleanup this marshal struct
	payload, err = json.Marshal(OktaUser{Username: o.creds.Username, Password: o.creds.Password})
	if err != nil {
		return
	}

	log.Debug("Posting first call to authenticate the user.")
	res, err := o.Request("POST", "api/v1/authn", url.Values{}, payload, "json", true)
	if err != nil {
		return fmt.Errorf("Failed to authenticate with okta. If your credentials have changed, use 'aws-okta add': %#v", err)
	}
	defer res.Body.Close()

	err = json.NewDecoder(res.Body).Decode(&o.UserAuth)
	if err != nil {
		return
	}
	// Step 2 : Challenge MFA if needed
	if o.UserAuth.Status == "MFA_REQUIRED" {
		log.Info("Requesting MFA. Please complete two-factor authentication with your second device")
		if err = o.challengeMFA(); err != nil {
			return
		}
	} else if o.UserAuth.Status == "PASSWORD_EXPIRED" {
		return fmt.Errorf("Password is expired, login to Okta console to change")
	}

	if o.UserAuth.SessionToken == "" {
		log.Debug("Auth failed. Reason: Session token isn't present.")
		return fmt.Errorf("authentication failed for %s", o.creds.Username)
	}
	return
}

// Public interface to get the Okta session token.
func (o *OktaClient) GetSessionToken() string {
	return o.UserAuth.SessionToken
}

// Validates the provided MFA config matches what the user has configured in
// Okta. If the provided config doesn't match an error will be returned.
func selectMFADeviceFromConfig(o *OktaClient) (*OktaUserAuthnFactor, error) {
	log.Debugf("MFAConfig: %v\n", o.MFAConfig)
	if o.MFAConfig.Provider == "" || o.MFAConfig.FactorType == "" {
		return nil, nil
	}

	for _, f := range o.UserAuth.Embedded.Factors {
		log.Debugf("%v\n", f)
		if strings.EqualFold(f.Provider, o.MFAConfig.Provider) && strings.EqualFold(f.FactorType, o.MFAConfig.FactorType) {
			log.Debugf("Using matching factor \"%v %v\" from config\n", f.Provider, f.FactorType)
			return &f, nil
		}
	}

	return nil, fmt.Errorf("Failed to select MFA device with Provider = \"%s\", FactorType = \"%s\"", o.MFAConfig.Provider, o.MFAConfig.FactorType)
}

// Will prompt the user to select one of the configured MFA devices if an MFA
// configuration isn't provided.
//
// TODO: convert this to a passed io reader to facilitate simple testing.
func (o *OktaClient) selectMFADevice() (*OktaUserAuthnFactor, error) {
	factors := o.UserAuth.Embedded.Factors
	if len(factors) == 0 {
		return nil, errors.New("No available MFA Factors")
	} else if len(factors) == 1 {
		return &factors[0], nil
	}

	factor, err := selectMFADeviceFromConfig(o)
	if err != nil {
		return nil, err
	}

	if factor != nil {
		return factor, nil
	}

	log.Info("Select a MFA from the following list")
	for i, f := range factors {
		log.Infof("%d: %s (%s)", i, f.Provider, f.FactorType)
	}
	i, err := lib.Prompt("Select MFA method", false)
	if i == "" {
		return nil, errors.New("Invalid selection - Please use an option that is listed")
	}
	if err != nil {
		return nil, err
	}
	factorIdx, err := strconv.Atoi(i)
	if err != nil {
		return nil, err
	}
	if factorIdx > (len(factors) - 1) {
		return nil, errors.New("Invalid selection - Please use an option that is listed")
	}
	return &factors[factorIdx], nil
}

// Makes any initial requests that are needed to verify MFA
//
// as an example this would include sending a request for an SMS code.
func (o *OktaClient) preChallenge(oktaFactorId, oktaFactorType string) ([]byte, error) {
	var mfaCode string
	var err error

	//Software and Hardware based OTP Tokens
	if strings.Contains(oktaFactorType, "token") {
		log.Debug("Token MFA")
		mfaCode, err = lib.Prompt("Enter MFA Code", false)
		if err != nil {
			return nil, err
		}
	} else if strings.Contains(oktaFactorType, "sms") {
		log.Debug("SMS MFA")
		payload, err := json.Marshal(OktaStateToken{
			StateToken: o.UserAuth.StateToken,
		})
		if err != nil {
			return nil, err
		}
		log.Debug("Requesting SMS Code")
		res, err := o.Request("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify", url.Values{}, payload, "json", true)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		mfaCode, err = lib.Prompt("Enter MFA Code from SMS", false)
		if err != nil {
			return nil, err
		}
	}

	payload, err := json.Marshal(OktaStateToken{
		StateToken: o.UserAuth.StateToken,
		PassCode:   mfaCode,
	})
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// executes the second step (if required) of the MFA verifaction process to get
// a valid session cookie.
func (o *OktaClient) postChallenge(payload []byte, oktaFactorProvider string, oktaFactorId string) error {
	//Initiate Push Notification
	if o.UserAuth.Status == "MFA_CHALLENGE" {
		f := o.UserAuth.Embedded.Factor
		errChan := make(chan error, 1)

		if oktaFactorProvider == "DUO" {
			// Contact the Duo to initiate Push notification
			if f.Embedded.Verification.Host != "" {
				o.DuoClient = &lib.DuoClient{
					Host:       f.Embedded.Verification.Host,
					Signature:  f.Embedded.Verification.Signature,
					Callback:   f.Embedded.Verification.Links.Complete.Href,
					Device:     o.MFAConfig.DuoDevice,
					StateToken: o.UserAuth.StateToken,
				}

				log.Debugf("Host:%s\nSignature:%s\nStateToken:%s\n",
					f.Embedded.Verification.Host, f.Embedded.Verification.Signature,
					o.UserAuth.StateToken)

				go func() {
					log.Debug("challenge u2f")
					log.Info("Sending Push Notification...")
					err := o.DuoClient.ChallengeU2f(f.Embedded.Verification.Host)
					if err != nil {
						errChan <- err
					}
				}()
			}
		} else if oktaFactorProvider == "FIDO" {
			f := o.UserAuth.Embedded.Factor

			log.Debug("FIDO U2F Details:")
			log.Debug("  ChallengeNonce: ", f.Embedded.Challenge.Nonce)
			log.Debug("  AppId: ", f.Profile.AppId)
			log.Debug("  CredentialId: ", f.Profile.CredentialId)
			log.Debug("  StateToken: ", o.UserAuth.StateToken)

			fidoClient, err := mfa.NewFidoClient(f.Embedded.Challenge.Nonce,
				f.Profile.AppId,
				f.Profile.Version,
				f.Profile.CredentialId,
				o.UserAuth.StateToken)
			if err != nil {
				return err
			}

			signedAssertion, err := fidoClient.ChallengeU2f()
			if err != nil {
				return err
			}
			// re-assign the payload to provide U2F responses.
			payload, err = json.Marshal(signedAssertion)
			if err != nil {
				return err
			}
		}
		// Poll Okta until authentication has been completed
		for o.UserAuth.Status != "SUCCESS" {
			select {
			case duoErr := <-errChan:
				log.Printf("Err: %s", duoErr)
				if duoErr != nil {
					return fmt.Errorf("Failed Duo challenge. Err: %s", duoErr)
				}
			default:
				res, err := o.Request("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify", url.Values{}, payload, "json", true)
				if err != nil {
					return fmt.Errorf("Failed authn verification for okta. Err: %s", err)
				}
				defer res.Body.Close()

				err = json.NewDecoder(res.Body).Decode(&o.UserAuth)
				if err != nil {
					return err
				}
			}
			time.Sleep(2 * time.Second)
		}
	}
	return nil
}

// helper function to get a url, including path, for an Okta api or app.
func (o *OktaClient) GetURL(path string) (fullURL *url.URL, err error) {

	fullURL, err = url.Parse(fmt.Sprintf(
		"%s/%s",
		o.BaseURL,
		path,
	))
	return
}
func (o *OktaClient) challengeMFA() (err error) {
	var oktaFactorProvider string
	var oktaFactorId string
	var payload []byte
	var oktaFactorType string

	factor, err := o.selectMFADevice()
	if err != nil {
		log.Debug("Failed to select MFA device")
		return
	}
	oktaFactorProvider = factor.Provider
	if oktaFactorProvider == "" {
		return
	}
	oktaFactorId, err = GetFactorId(factor)
	if err != nil {
		return
	}
	oktaFactorType = factor.FactorType
	if oktaFactorId == "" {
		return
	}
	log.Debugf("Okta Factor Provider: %s", oktaFactorProvider)
	log.Debugf("Okta Factor ID: %s", oktaFactorId)
	log.Debugf("Okta Factor Type: %s", oktaFactorType)

	payload, err = o.preChallenge(oktaFactorId, oktaFactorType)

	res, err := o.Request("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify", url.Values{}, payload, "json", true)
	if err != nil {
		return fmt.Errorf("Failed authn verification for okta. Err: %s", err)
	}
	defer res.Body.Close()

	err = json.NewDecoder(res.Body).Decode(&o.UserAuth)
	if err != nil {
		return
	}

	//Handle Push Notification
	err = o.postChallenge(payload, oktaFactorProvider, oktaFactorId)
	if err != nil {
		return err
	}
	return
}

// gets the factor ID that uniquely identifies an MFA device.
func GetFactorId(f *OktaUserAuthnFactor) (id string, err error) {
	switch f.FactorType {
	case "web":
		id = f.Id
	case "token":
		if f.Provider == "SYMANTEC" {
			id = f.Id
		} else {
			err = fmt.Errorf("provider %s with factor token not supported", f.Provider)
		}
	case "token:software:totp":
		id = f.Id
	case "token:hardware":
		id = f.Id
	case "sms":
		id = f.Id
	case "u2f":
		id = f.Id
	case "push":
		if f.Provider == "OKTA" || f.Provider == "DUO" {
			id = f.Id
		} else {
			err = fmt.Errorf("provider %s with factor push not supported", f.Provider)
		}
	default:
		err = fmt.Errorf("factor %s not supported", f.FactorType)
	}
	return
}

// Makes a request to Okta.
//
// Supports Core okta APIs or Okta apps that extend the Okta functionaliy.
//
// Options:
// -- method. the http method to use.
// -- path. the url path to use.
// -- queryParams. the query parameters to use in the request.
// -- data. the data that will be sent as part of the request body.
// -- format. use to set the encoding format header.
// -- followRedirects. will change the http client configuration to follow
//                     redirects or not.
//
// TODO: refactor this method signature to clarify the interface.
// something like:
// -- method.
// -- url.URL (including RawParams).
// -- requestBody.
// -- clientOptions. this would include things like encoding and follow redirects
func (o *OktaClient) Request(method string, path string, queryParams url.Values, data []byte, format string, followRedirects bool) (res *http.Response, err error) {
	var header http.Header

	requestUrl, err := url.Parse(fmt.Sprintf(
		"%s/%s", o.BaseURL, path,
	))
	if err != nil {
		return
	}
	requestUrl.RawQuery = queryParams.Encode()

	if format == "json" {
		header = http.Header{
			"Accept":        []string{"application/json"},
			"Content-Type":  []string{"application/json"},
			"Cache-Control": []string{"no-cache"},
		}
	} else {
		// disable gzip encoding; it was causing spurious EOFs
		// for some users; see #148
		header = http.Header{
			"Accept-Encoding": []string{"identity"},
		}
	}

	var checkRedirectFunc func(req *http.Request, via []*http.Request) error
	if !followRedirects {
		checkRedirectFunc = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	o.client.CheckRedirect = checkRedirectFunc

	req := &http.Request{
		Method:        method,
		URL:           requestUrl,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          ioutil.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
	}
	log.Debug(method, " ", requestUrl.String())

	res, err = o.client.Do(req)
	return
}
