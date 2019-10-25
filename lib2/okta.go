package lib

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

type OktaClient struct {
	// Organization will be deprecated in the future
	Organization string
	Username     string
	Password     string
	UserAuth     *OktaUserAuthn
	DuoClient    *DuoClient
	SessionToken string
	Expiration   time.Time
	CookieJar    http.CookieJar
	BaseURL      *url.URL
	Domain       string
	MFAConfig    MFAConfig
	Keyring      *keyring.Keyring
}

type MFAConfig struct {
	Provider   string // Which MFA provider to use when presented with an MFA challenge
	FactorType string // Which of the factor types of the MFA provider to use
	DuoDevice  string // Which DUO device to use for DUO MFA
}

type OktaCreds struct {
	// Organization will be deprecated in the future
	Organization string
	Username     string
	Password     string
	Domain       string
}

func (c *OktaCreds) Validate(mfaConfig MFAConfig) error {
	// OktaClient assumes we're doing some AWS SAML calls, but Validate doesn't
	o, err := NewOktaClient(*c, nil, mfaConfig)
	if err != nil {
		return err
	}

	if err := o.AuthenticateUser(); err != nil {
		return err
	}

	return nil
}

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

func NewOktaClient(creds OktaCreds, kr *keyring.Keyring, mfaConfig MFAConfig) (*OktaClient, error) {
	var domain string

	// maintain compatibility for deprecated creds.Organization
	if creds.Domain == "" && creds.Organization != "" {
		domain = fmt.Sprintf("%s.%s", creds.Organization, OktaServerDefault)
	} else if creds.Domain != "" {
		domain = creds.Domain
	} else {
		return &OktaClient{}, errors.New("either creds.Organization (deprecated) or creds.Domain must be set, but not both. To remedy this, re-add your credentials with `aws-okta add`")
	}

	// url parse & set base
	base, err := url.Parse(fmt.Sprintf(
		"https://%s", domain,
	))
	if err != nil {
		return nil, err
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}

	oktaClient := OktaClient{
		// Setting Organization for backwards compatibility
		Organization: creds.Organization,
		Username:     creds.Username,
		Password:     creds.Password,
		CookieJar:    jar,
		BaseURL:      base,
		Domain:       domain,
		MFAConfig:    mfaConfig,
		UserAuth:     &OktaUserAuthn{},
		Keyring:      kr,
	}

	oktaClient.retrieveSessionCookie()

	log.Debug("domain: " + domain)

	return &oktaClient, nil
}

func (o *OktaClient) retrieveSessionCookie() (err error) {

	if o.Keyring == nil {
		return
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

func (o *OktaClient) getSessionCookieKeyringKey() string {
	return "okta-session-cookie-" + o.Username
}

func (o *OktaClient) saveSessionCookie() (err error) {

	if o.Keyring == nil {
		return
	}
	cookies := o.CookieJar.Cookies(o.BaseURL)
	for _, cookie := range cookies {
		if cookie.Name == "sid" {
			newCookieItem := keyring.Item{
				Key:                         o.getSessionCookieKeyringKey(),
				Data:                        []byte(cookie.Value),
				Label:                       "okta session cookie for " + o.Username,
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

func (o *OktaClient) ValidateSession() (sessionValid bool, err error) {
	var mySessionResponse *http.Response
	sessionValid = false

	// Step 0 : Check if we have valid session
	log.Debug("Step: 0")
	mySessionResponse, err = o.request("GET", "api/v1/sessions/me", url.Values{}, []byte{}, "json", false)
	if err != nil {
		return
	}
	defer mySessionResponse.Body.Close()

	sessionValid = mySessionResponse.StatusCode == http.StatusOK

	return
}

func (o *OktaClient) AuthenticateUser() (err error) {
	var payload []byte

	// Step 1 : Basic authentication
	user := OktaUser{
		Username: o.Username,
		Password: o.Password,
	}

	payload, err = json.Marshal(user)
	if err != nil {
		return
	}

	log.Debug("Step: 1")
	res, err := o.request("POST", "api/v1/authn", url.Values{}, payload, "json", true)
	if err != nil {
		err = fmt.Errorf("Failed to authenticate with okta. If your credentials have changed, use 'aws-okta add': %#v", err)
		return
	}
	defer res.Body.Close()

	err = json.NewDecoder(res.Body).Decode(&o.UserAuth)
	if err != nil {
		return
	}

	// Step 2 : Challenge MFA if needed
	log.Debug("Step: 2")
	if o.UserAuth.Status == "MFA_REQUIRED" {
		log.Info("Requesting MFA. Please complete two-factor authentication with your second device")
		if err = o.challengeMFA(); err != nil {
			return
		}
	}

	if o.UserAuth.SessionToken == "" {
		return fmt.Errorf("authentication failed for %s", o.Username)
	}
	return
}

type SessionRequest struct {
	SessionToken string `json:"sessionToken"`
}

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
	i, err := Prompt("Select MFA method", false)
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

func (o *OktaClient) preChallenge(oktaFactorId, oktaFactorType string) ([]byte, error) {
	var mfaCode string
	var err error

	//Software and Hardware based OTP Tokens
	if strings.Contains(oktaFactorType, "token") {
		log.Debug("Token MFA")
		mfaCode, err = Prompt("Enter MFA Code", false)
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
		res, err := o.request("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify", url.Values{}, payload, "json", true)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		mfaCode, err = Prompt("Enter MFA Code from SMS", false)
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

func (o *OktaClient) postChallenge(payload []byte, oktaFactorProvider string, oktaFactorId string) error {
	//Initiate Push Notification
	if o.UserAuth.Status == "MFA_CHALLENGE" {
		f := o.UserAuth.Embedded.Factor
		errChan := make(chan error, 1)

		if oktaFactorProvider == "DUO" {
			// Contact the Duo to initiate Push notification
			if f.Embedded.Verification.Host != "" {
				o.DuoClient = &DuoClient{
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
				res, err := o.request("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify", url.Values{}, payload, "json", true)
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

	res, err := o.request("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify", url.Values{}, payload, "json", true)
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

func (o *OktaClient) request(method string, path string, queryParams url.Values, data []byte, format string, followRedirects bool) (res *http.Response, err error) {
	//var res *http.Response
	var body []byte
	var header http.Header
	var client http.Client

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

	transCfg := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: Timeout,
	}

	var checkRedirectFunc func(req *http.Request, via []*http.Request) error
	if !followRedirects {
		checkRedirectFunc = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	client = http.Client{
		Transport:     transCfg,
		Timeout:       Timeout,
		Jar:           o.CookieJar,
		CheckRedirect: checkRedirectFunc,
	}

	req := &http.Request{
		Method:        method,
		URL:           requestUrl,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          ioutil.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(body)),
	}
	log.Debug(method, " ", requestUrl.String())

	res, err = client.Do(req)
	return
}
