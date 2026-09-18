package aws

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	ErrInvalidRoleARN   = errors.New("roleArn format not allowed")
	ErrInvalidAccountID = errors.New("accountId format not allowed")
	ErrInvalidRegion    = errors.New("region not allowed")
)

var (
	roleNameRE = regexp.MustCompile(`^[a-zA-Z0-9_+=,.@\-]+$`)
	regionRE   = regexp.MustCompile(`^[a-z]{2}-[a-z]+-\d+$`)
	arnRE      = regexp.MustCompile(`^arn:aws:iam::(\d{12}):role/(.+)$`)
	reservedPaths = []string{"aws-reserved/", "service-role/", "aws-service-role/"}
)

// ValidateRoleARN checks that the ARN is a well-formed IAM role ARN in the
// aws partition, with a 12-digit account ID, a valid role name, and no
// reserved path prefixes. Returns the extracted account ID on success.
func ValidateRoleARN(roleARN string) (accountID string, err error) {
	if roleARN == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalidRoleARN)
	}

	matches := arnRE.FindStringSubmatch(roleARN)
	if matches == nil {
		return "", fmt.Errorf("%w: malformed ARN", ErrInvalidRoleARN)
	}

	accountID = matches[1]
	roleName := matches[2]

	// Reject reserved paths
	for _, prefix := range reservedPaths {
		if strings.HasPrefix(roleName, prefix) {
			return "", fmt.Errorf("%w: reserved path prefix", ErrInvalidRoleARN)
		}
	}

	// roleName may contain a path (e.g. service/rolename); validate the
	// final segment after the last slash and reject reserved path prefixes.
	pathPrefix := ""
	if idx := strings.LastIndex(roleName, "/"); idx != -1 {
		pathPrefix = roleName[:idx+1]
		roleName = roleName[idx+1:]
	}
	// Check the full path+name against reserved prefixes
	fullPath := pathPrefix + roleName
	for _, prefix := range reservedPaths {
		if strings.HasPrefix(fullPath, prefix) {
			return "", fmt.Errorf("%w: reserved path prefix", ErrInvalidRoleARN)
		}
	}

	if !roleNameRE.MatchString(roleName) {
		return "", fmt.Errorf("%w: invalid role name", ErrInvalidRoleARN)
	}

	return accountID, nil
}

// ValidateAccountID checks that the account ID is exactly 12 digits.
func ValidateAccountID(accountID string) error {
	if len(accountID) != 12 || !isAllDigits(accountID) {
		return fmt.Errorf("%w: must be 12 digits", ErrInvalidAccountID)
	}
	return nil
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ValidateRegions checks that each region matches the expected pattern and
// the total count does not exceed maxRegions.
func ValidateRegions(regions []string, maxRegions int) error {
	if len(regions) > maxRegions {
		return fmt.Errorf("%w: %d > %d", ErrInvalidRegion, len(regions), maxRegions)
	}
	for _, r := range regions {
		if !regionRE.MatchString(r) {
			return fmt.Errorf("%w: %s", ErrInvalidRegion, r)
		}
	}
	return nil
}
