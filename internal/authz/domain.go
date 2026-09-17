package authz

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/psycho-prince/pqc-sdk/internal/model"
)

var (
	ErrNotVerified = errors.New("domain is not verified for this organization")
	ErrNotFound    = errors.New("domain verification record not found")
)

type Store interface {
	GetVerification(ctx context.Context, orgID, domain string) (*model.DomainVerification, error)
	UpsertVerification(ctx context.Context, v *model.DomainVerification) error
}

type Verifier struct {
	store Store
	local bool
}

func NewVerifier(store Store, local bool) *Verifier {
	return &Verifier{store: store, local: local}
}

func (v *Verifier) IssueToken(ctx context.Context, orgID, domain string) (*model.DomainVerification, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	token := "quantumblue-verify=" + base64.RawURLEncoding.EncodeToString(b)
	
	record := &model.DomainVerification{
		OrganizationId: orgID,
		Domain:         domain,
		Token:          token,
	}
	if err := v.store.UpsertVerification(ctx, record); err != nil {
		return nil, err
	}
	return record, nil
}

func (v *Verifier) VerifyDomain(ctx context.Context, orgID, domain string) error {
	record, err := v.store.GetVerification(ctx, orgID, domain)
	if err != nil {
		return err
	}
	if record == nil {
		return ErrNotFound
	}
	
	now := time.Now()
	record.LastCheckedAt = &now

	if checkTXT(domain, record.Token) || checkHTTP(domain, record.Token) {
		record.VerifiedAt = &now
		record.Method = "dns_txt" // Or http_file, depending on which matched
		return v.store.UpsertVerification(ctx, record)
	}

	return ErrNotVerified
}

func (v *Verifier) RequireVerified(ctx context.Context, orgID, domain string) error {
	if v.local {
		return nil // Handled by CLI flags
	}
	record, err := v.store.GetVerification(ctx, orgID, domain)
	if err != nil {
		return err
	}
	if record == nil || record.VerifiedAt == nil {
		return ErrNotVerified
	}
	if time.Since(*record.VerifiedAt) > 30*24*time.Hour {
		return errors.New("domain verification expired (30 days limit), please re-verify")
	}
	return nil
}

func checkTXT(domain, expected string) bool {
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return false
	}
	for _, txt := range txts {
		if txt == expected {
			return true
		}
	}
	return false
}

func checkHTTP(domain, expected string) bool {
	url := fmt.Sprintf("https://%s/.well-known/quantumblue-%s", domain, strings.TrimPrefix(expected, "quantumblue-verify="))
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if strings.TrimSpace(string(body)) == expected {
			return true
		}
	}
	return false
}
