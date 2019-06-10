package saml

import (
	"errors"
	"fmt"
	"github.com/segmentio/aws-okta/lib/util"
	"strconv"
	"strings"
)

func (roleList *AssumableRoles) GetRole(profileARN string) (string, string, error) {

	// if the user doesn't have any roles they can assume return an error.
	if len(roleList.Roles) == 0 {
		return "", "", fmt.Errorf("There are no roles that can be assumed")
	}

	// A role arn was provided as part of the profile, we will assume that role.
	if profileARN != "" {
		for _, arole := range roleList.Roles {
			if profileARN == arole.Role {
				return arole.Role, arole.Principal, nil
			}
		}
		return "", "", fmt.Errorf("ARN isn't valid")
	}

	// if the user only has one role assume that role without prompting.
	if len(roleList.Roles) == 1 {
		return roleList.Roles[0].Role, roleList.Roles[0].Principal, nil
	}

	for i, arole := range roleList.Roles {
		fmt.Printf("%d - %s\n", i, arole.Role)
	}

	i, err := util.Prompt("Select Role to Assume", false)
	if err != nil {
		return "", "", err
	}
	if i == "" {
		return "", "", errors.New("Invalid selection - Please use an option that is listed")
	}
	factorIdx, err := strconv.Atoi(i)
	if err != nil {
		return "", "", err
	}
	if factorIdx > (len(roleList.Roles) - 1) {
		return "", "", errors.New("Invalid selection - Please use an option that is listed")
	}
	return roleList.Roles[factorIdx].Role, roleList.Roles[factorIdx].Principal, nil
}
func (resp *Response) GetAssumableRolesFromSAML() (AssumableRoles, error) {
	roleList := []AssumableRole{}

	for _, a := range resp.Assertion.AttributeStatement.Attributes {
		if strings.HasSuffix(a.Name, "SAML/Attributes/Role") {
			for _, v := range a.AttributeValues {
				tokens := strings.Split(v.Value, ",")
				if len(tokens) != 2 {
					continue
				}

				// Amazon's documentation suggests that the
				// Role ARN should appear first in the comma-delimited
				// set in the Role Attribute that SAML IdP returns.
				//
				// See the section titled "An Attribute element with the Name attribute set
				// to https://aws.amazon.com/SAML/Attributes/Role" on this page:
				// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html
				//
				// In practice, though, Okta SAML integrations with AWS will succeed
				// with either the role or principal ARN first, and these `if` statements
				// allow that behavior in this program.
				if strings.Contains(tokens[0], ":saml-provider/") {
					// if true, Role attribute is formatted like:
					// arn:aws:iam::ACCOUNT:saml-provider/provider,arn:aws:iam::account:role/roleName
					roleList = append(roleList, AssumableRole{Role: tokens[1],
						Principal: tokens[0]})
				} else if strings.Contains(tokens[1], ":saml-provider/") {
					// if true, Role attribute is formatted like:
					// arn:aws:iam::account:role/roleName,arn:aws:iam::ACCOUNT:saml-provider/provider
					roleList = append(roleList, AssumableRole{Role: tokens[0],
						Principal: tokens[1]})
				} else {
					return AssumableRoles{}, fmt.Errorf("Unable to get roles from %s", v.Value)
				}

			}
		}
	}
	return AssumableRoles{Roles: roleList}, nil
}
