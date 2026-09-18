package aws

import (
	"errors"
	"fmt"
	"regexp"
)

var (
	ErrInvalidRegion = errors.New("region not allowed")
)

var regionRE = regexp.MustCompile(`^[a-z]{2}-[a-z]+-\d+$`)

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
