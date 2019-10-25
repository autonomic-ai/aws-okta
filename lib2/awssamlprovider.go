package lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/segmentio/aws-okta/internal/sessioncache"
	"github.com/segmentio/aws-okta/lib/saml"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	aws_session "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	log "github.com/sirupsen/logrus"
	// use xerrors until 1.13 is stable/oldest supported version
	"golang.org/x/xerrors"
)

const (
	MaxSessionDuration    = time.Hour * 24 * 90
	MinSessionDuration    = time.Minute * 15
	MinAssumeRoleDuration = time.Minute * 15
	MaxAssumeRoleDuration = time.Hour * 12

	DefaultSessionDuration    = time.Hour * 4
	DefaultAssumeRoleDuration = time.Minute * 15
)

type AwsSamlProvider struct {
	credentials.Expiry
	AwsSamlProviderOptions
	oktaClient             OktaClient
	keyring                keyring.Keyring
	profileARN             string
	oktaAwsSAMLUrl         string
	oktaAccountName        string
	awsRegion              string
	profile                string
	expires                time.Time
	sessions               SessionCacheInterface
	defaultRoleSessionName string
}

type AwsSamlProviderOptions struct {
	SessionDuration    time.Duration
	AssumeRoleDuration time.Duration
	ExpiryWindow       time.Duration
	Profiles           Profiles
	MFAConfig          MFAConfig
	AssumeRoleArn      string
	// if true, use store_singlekritem SessionCache (new)
	// if false, use store_kritempersession SessionCache (old)
	SessionCacheSingleItem bool
}

func (o *AwsSamlProviderOptions) Validate() error {
	if o.SessionDuration < MinSessionDuration {
		return errors.New("Minimum session duration is " + MinSessionDuration.String())
	} else if o.SessionDuration > MaxSessionDuration {
		return errors.New("Maximum session duration is " + MaxSessionDuration.String())
	}
	if o.AssumeRoleDuration < MinAssumeRoleDuration {
		return errors.New("Minimum duration for assumed roles is " + MinAssumeRoleDuration.String())
	} else if o.AssumeRoleDuration > MaxAssumeRoleDuration {
		log.Println(o.AssumeRoleDuration)
		return errors.New("Maximum duration for assumed roles is " + MaxAssumeRoleDuration.String())
	}

	return nil
}

func (o *AwsSamlProviderOptions) ApplyDefaults() {
	if o.AssumeRoleDuration == 0 {
		o.AssumeRoleDuration = DefaultAssumeRoleDuration
	}
	if o.SessionDuration == 0 {
		o.SessionDuration = DefaultSessionDuration
	}
}

type SessionCacheInterface interface {
	Get(sessioncache.Key) (*sessioncache.Session, error)
	Put(sessioncache.Key, *sessioncache.Session) error
}

func NewAwsSamlProvider(kr keyring.Keyring, profile string, opts AwsSamlProviderOptions) (*AwsSamlProvider, error) {
	var sessions SessionCacheInterface
	var profileARN string
	var ok bool

	opts.ApplyDefaults()
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	if opts.SessionCacheSingleItem {
		log.Debugf("Using SingleKrItemStore")
		sessions = &sessioncache.SingleKrItemStore{kr}
	} else {
		log.Debugf("Using KrItemPerSessionStore")
		sessions = &sessioncache.KrItemPerSessionStore{kr}
	}

	source := sourceProfile(profile, opts.Profiles)

	// if the assumable role is passed it have it override what is in the profile
	if opts.AssumeRoleArn != "" {
		profileARN = opts.AssumeRoleArn
		log.Debug("Overriding Assumable role with: ", profileARN)
	} else {
		profileARN, ok = opts.Profiles[source]["role_arn"]
		if !ok {
			return nil, errors.New("Source profile must provide `role_arn`")
		}
	}

	item, err := kr.Get("okta-creds")
	if err != nil {
		log.Debugf("couldnt get okta creds from keyring: %s", err)
		return nil, err
	}

	var oktaCreds OktaCreds
	if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
		return nil, errors.New("Failed to get okta credentials from your keyring.  Please make sure you have added okta credentials with `aws-okta add`")
	}

	oktaClient, err := NewOktaClient(oktaCreds, &kr, opts.MFAConfig)
	if err != nil {
		return nil, err
	}

	provider := AwsSamlProvider{
		AwsSamlProviderOptions: opts,
		oktaClient:             *oktaClient,
		keyring:                kr,
		profileARN:             profileARN,
		sessions:               sessions,
		profile:                profile,
	}

	if region := opts.Profiles[source]["region"]; region != "" {
		provider.awsRegion = region
	}
	err = provider.getSamlURL()
	if err != nil {
		return nil, err
	}
	return &provider, nil
}

func (p *AwsSamlProvider) Retrieve() (credentials.Value, error) {

	window := p.ExpiryWindow
	if window == 0 {
		window = time.Minute * 5
	}

	// TODO(nick): why are we using the source profile name and not the actual profile's name?
	source := sourceProfile(p.profile, p.Profiles)
	profileConf, ok := p.Profiles[p.profile]
	if !ok {
		return credentials.Value{}, fmt.Errorf("missing profile named %s", p.profile)
	}
	key := sessioncache.OrigKey{
		ProfileName: source,
		ProfileConf: profileConf,
		Duration:    p.SessionDuration,
	}

	var creds sts.Credentials
	if cachedSession, err := p.sessions.Get(key); err != nil {
		creds, err = p.getSamlSessionCreds()
		if err != nil {
			return credentials.Value{}, xerrors.Errorf("getting creds via SAML: %w", err)
		}
		newSession := sessioncache.Session{
			Name:        p.roleSessionName(),
			Credentials: creds,
		}
		if err = p.sessions.Put(key, &newSession); err != nil {
			return credentials.Value{}, xerrors.Errorf("putting to sessioncache", err)
		}

		// TODO(nick): not really clear why this is done
		p.defaultRoleSessionName = newSession.Name
	} else {
		creds = cachedSession.Credentials
		p.defaultRoleSessionName = cachedSession.Name
	}

	log.Debugf("Using session %s, expires in %s",
		(*(creds.AccessKeyId))[len(*(creds.AccessKeyId))-4:],
		creds.Expiration.Sub(time.Now()).String())

	// If sourceProfile returns the same source then we do not need to assume a
	// second role. Not assuming a second role allows us to assume IDP enabled
	// roles directly.
	if p.profile != source {
		if role, ok := p.Profiles[p.profile]["role_arn"]; ok {
			var err error
			creds, err = p.assumeRoleFromSession(creds, role)
			if err != nil {
				return credentials.Value{}, err
			}

			log.Debugf("using role %s expires in %s",
				(*(creds.AccessKeyId))[len(*(creds.AccessKeyId))-4:],
				creds.Expiration.Sub(time.Now()).String())
		}
	}

	p.SetExpiration(*(creds.Expiration), window)
	p.expires = *(creds.Expiration)

	value := credentials.Value{
		AccessKeyID:     *(creds.AccessKeyId),
		SecretAccessKey: *(creds.SecretAccessKey),
		SessionToken:    *(creds.SessionToken),
		ProviderName:    "okta",
	}

	return value, nil
}

func (p *AwsSamlProvider) getSamlURL() error {
	oktaAwsSAMLUrl, profile, err := p.Profiles.GetValue(p.profile, "aws_saml_url")
	if err != nil {
		return errors.New("aws_saml_url missing from ~/.aws/config")
	}
	log.Debugf("Using aws_saml_url from profile %s: %s", profile, oktaAwsSAMLUrl)
	p.oktaAwsSAMLUrl = oktaAwsSAMLUrl
	return nil
}

func (p *AwsSamlProvider) getOktaSessionCookieKey() string {
	oktaSessionCookieKey, profile, err := p.Profiles.GetValue(p.profile, "okta_session_cookie_key")
	if err != nil {
		return "okta-session-cookie"
	}
	log.Debugf("Using okta_session_cookie_key from profile: %s", profile)
	return oktaSessionCookieKey
}

func (p *AwsSamlProvider) getOktaAccountName() string {
	oktaAccountName, profile, err := p.Profiles.GetValue(p.profile, "okta_account_name")
	if err != nil {
		return "okta-creds"
	}
	log.Debugf("Using okta_account_name: %s from profile: %s", oktaAccountName, profile)
	return "okta-creds-" + oktaAccountName
}

func (p *AwsSamlProvider) getSamlSessionCreds() (sts.Credentials, error) {
	log.Debugf("Using okta provider (%s)", p.oktaAccountName)
	creds, err := p.authenticateProfileWithRegion(p.profileARN, p.SessionDuration, p.oktaAwsSAMLUrl, p.awsRegion)
	if err != nil {
		return sts.Credentials{}, err
	}

	//	p.defaultRoleSessionName = p.oktaClient.oktaCreds.Username

	return creds, nil
}

// assumeRoleFromSession takes a session created with an okta SAML login and uses that to assume a role
func (p *AwsSamlProvider) assumeRoleFromSession(creds sts.Credentials, roleArn string) (sts.Credentials, error) {
	client := sts.New(aws_session.New(&aws.Config{Credentials: credentials.NewStaticCredentials(
		*creds.AccessKeyId,
		*creds.SecretAccessKey,
		*creds.SessionToken,
	)}))

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(p.roleSessionName()),
		DurationSeconds: aws.Int64(int64(p.AssumeRoleDuration.Seconds())),
	}

	log.Debugf("Assuming role %s from session token", roleArn)
	resp, err := client.AssumeRole(input)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

// roleSessionName returns the profile's `role_session_name` if set, or the
// provider's defaultRoleSessionName if set. If neither is set, returns some
// arbitrary unique string
func (p *AwsSamlProvider) roleSessionName() string {
	if name := p.Profiles[p.profile]["role_session_name"]; name != "" {
		return name
	}

	if p.defaultRoleSessionName != "" {
		return p.defaultRoleSessionName
	}

	// Try to work out a role name that will hopefully end up unique.
	return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
}

// GetRoleARN makes a call to AWS to get-caller-identity and returns the
// assumed role's name and ARN.
func GetRoleARN(c credentials.Value) (string, error) {
	client := sts.New(aws_session.New(&aws.Config{Credentials: credentials.NewStaticCredentialsFromCreds(c)}))

	indentity, err := client.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		log.Errorf("Error getting caller identity: %s", err.Error())
		return "", err
	}
	arn := *indentity.Arn
	return arn, nil
}

type SAMLAssertion struct {
	Resp    *saml.Response
	RawData []byte
}

func (p *AwsSamlProvider) authenticateProfileWithRegion(profileARN string, duration time.Duration, oktaAwsSAMLUrl string, region string) (sts.Credentials, error) {

	// Attempt to reuse session cookie
	var assertion SAMLAssertion
	queryParams := url.Values{}

	err := p.getAwsSAML(oktaAwsSAMLUrl, queryParams, nil, &assertion, "saml")
	if err != nil {
		log.Debug("Failed to reuse session token, starting flow from start")

		if err := p.oktaClient.AuthenticateUser(); err != nil {
			return sts.Credentials{}, err
		}

		// Step 3 : Get SAML Assertion and retrieve IAM Roles
		log.Debug("Step: 3")
		queryParams.Set("onetimetoken", p.oktaClient.UserAuth.SessionToken)
		if err = p.getAwsSAML(oktaAwsSAMLUrl, queryParams, nil, &assertion, "saml"); err != nil {
			return sts.Credentials{}, err
		}
	}

	principal, role, err := GetRoleFromSAML(assertion.Resp, profileARN)
	if err != nil {
		return sts.Credentials{}, err
	}

	// Step 4 : Assume Role with SAML
	log.Debug("Step 4: Assume Role with SAML")
	var samlSess *session.Session
	if region != "" {
		log.Debugf("Using region: %s\n", region)
		conf := &aws.Config{
			Region: aws.String(region),
		}
		samlSess = session.Must(session.NewSession(conf))
	} else {
		samlSess = session.Must(session.NewSession())
	}
	svc := sts.New(samlSess)

	samlParams := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(principal),
		RoleArn:         aws.String(role),
		SAMLAssertion:   aws.String(string(assertion.RawData)),
		DurationSeconds: aws.Int64(int64(duration.Seconds())),
	}

	samlResp, err := svc.AssumeRoleWithSAML(samlParams)
	if err != nil {
		log.WithField("role", role).Errorf(
			"error assuming role with SAML: %s", err.Error())
		return sts.Credentials{}, err
	}

	p.oktaClient.saveSessionCookie()

	return *samlResp.Credentials, nil
}

func (p *AwsSamlProvider) getAwsSAML(path string, queryParams url.Values, data []byte, recv interface{}, format string) (err error) {
	res, err := p.oktaClient.request("GET", path, queryParams, data, format, true)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s %v: %s", "GET", res.Request.URL, res.Status)
	} else if recv != nil {
		switch format {
		case "json":
			err = json.NewDecoder(res.Body).Decode(recv)
		default:
			var rawData []byte
			rawData, err = ioutil.ReadAll(res.Body)
			if err != nil {
				return
			}
			if err := ParseSAML(rawData, recv.(*SAMLAssertion)); err != nil {
				log.Debug("SAML parsing failed: ", err)
				return fmt.Errorf("Okta user %s does not have the AWS app added to their account.  Please contact your Okta admin to make sure things are configured properly.", p.oktaClient.Username)
			}
		}
	}

	return
}

func (p *AwsSamlProvider) GetSAMLLoginURL() (*url.URL, error) {
	item, err := p.keyring.Get("okta-creds")
	if err != nil {
		log.Debugf("couldnt get okta creds from keyring: %s", err)
		return &url.URL{}, err
	}

	var oktaCreds OktaCreds
	if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
		return &url.URL{}, errors.New("Failed to get okta credentials from your keyring.  Please make sure you have added okta credentials with `aws-okta add`")
	}

	var samlURL string

	// maintain compatibility for deprecated creds.Organization
	if oktaCreds.Domain == "" && oktaCreds.Organization != "" {
		samlURL = fmt.Sprintf("%s.%s", oktaCreds.Organization, OktaServerDefault)
	} else if oktaCreds.Domain != "" {
		samlURL = oktaCreds.Domain
	} else {
		return &url.URL{}, errors.New("either oktaCreds.Organization (deprecated) or oktaCreds.Domain must be set, but not both. To remedy this, re-add your credentials with `aws-okta add`")
	}

	fullSamlURL, err := url.Parse(fmt.Sprintf(
		"https://%s/%s",
		samlURL,
		p.oktaAwsSAMLUrl,
	))

	if err != nil {
		return &url.URL{}, err
	}

	return fullSamlURL, nil
}
