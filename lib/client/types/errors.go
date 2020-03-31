package types

import "errors"

var (
	ErrInvalidCredentials = errors.New("okta credentials are not valid")
	ErrInvalidSession     = errors.New("okta session is not valid")
	ErrUnexpectedResponse = errors.New("we got an unexpected response")
	ErrNotImplemented     = errors.New("not implemented")
	ErrNotSupported       = errors.New("not supported")
	ErrPasswordExpired    = errors.New("okta credentials are not valid: your user password is expired")
)
