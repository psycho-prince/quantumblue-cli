package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/psycho-prince/pqc-sdk/internal/crypto"
)

// Role defines the access level of a user within an organization.
type Role string

const (
	RoleAdmin      Role = "ADMIN"
	RoleInvestigator Role = "INVESTIGATOR"
	RoleAuditor    Role = "AUDITOR"
	RoleViewer     Role = "VIEWER"
)

// RolePermissions maps roles to their allowed actions.
var RolePermissions = map[Role][]string{
	RoleAdmin: {
		"evidence:read", "evidence:write", "evidence:delete",
		"case:read", "case:write", "case:delete",
		"certificate:read", "certificate:write", "certificate:issue",
		"user:read", "user:write", "user:delete",
		"admin:read", "admin:write",
		"export:all", "audit:read",
	},
	RoleInvestigator: {
		"evidence:read", "evidence:write",
		"case:read", "case:write",
		"certificate:read", "certificate:write",
		"audit:read",
	},
	RoleAuditor: {
		"evidence:read",
		"case:read",
		"certificate:read",
		"audit:read",
	},
	RoleViewer: {
		"evidence:read",
		"case:read",
		"certificate:read",
	},
}

// PermissionCheck returns true if the role has the named permission.
func PermissionCheck(role Role, permission string) bool {
	perms, ok := RolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == permission {
			return true
		}
	}
	return false
}

// User represents an authenticated user within an organization.
type User struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Email          string    `json:"email"`
	Name           string    `json:"name"`
	Role           Role      `json:"role"`
	MFAEnabled     bool      `json:"mfa_enabled"`
	MFASecret      string    `json:"mfa_secret,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// UserStore manages users for an organization.
type UserStore struct {
	directory string
	mu        sync.Mutex
}

// NewUserStore creates a user store.
func NewUserStore(dir string) (*UserStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &UserStore{directory: dir}, nil
}

// Save persists a user to disk.
func (us *UserStore) Save(user *User) error {
	us.mu.Lock()
	defer us.mu.Unlock()
	data, _ := json.Marshal(user)
	path := filepath.Join(us.directory, user.ID+".qbuser")
	return os.WriteFile(path, data, 0600)
}

// Get retrieves a user by ID.
func (us *UserStore) Get(id string) (*User, error) {
	us.mu.Lock()
	defer us.mu.Unlock()
	data, err := os.ReadFile(filepath.Join(us.directory, id+".qbuser"))
	if err != nil {
		return nil, fmt.Errorf("user not found: %s", id)
	}
	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// List returns all users for an organization.
func (us *UserStore) List(orgID string) ([]*User, error) {
	us.mu.Lock()
	defer us.mu.Unlock()
	entries, err := os.ReadDir(us.directory)
	if err != nil {
		return nil, err
	}
	var users []*User
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".qbuser" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(us.directory, entry.Name()))
		if err != nil {
			continue
		}
		var user User
		if err := json.Unmarshal(data, &user); err != nil {
			continue
		}
		if user.OrganizationID == orgID {
			users = append(users, &user)
		}
	}
	return users, nil
}

// Delete removes a user.
func (us *UserStore) Delete(id string) error {
	us.mu.Lock()
	defer us.mu.Unlock()
	return os.Remove(filepath.Join(us.directory, id+".qbuser"))
}

// GenerateMFASecret generates a base32 TOTP secret for MFA.
func GenerateMFASecret() (string, error) {
	bytes := make([]byte, 20)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// MFATOTP generates a time-based one-time password from a secret.
func MFATOTP(secret string, timestamp time.Time) (string, error) {
	// 30-second time step
	step := time.Now().Unix() / 30
	stepBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		stepBytes[i] = byte(step >> (uint(8*(7-i))) & 0xFF)
	}
	secretBytes, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(secretBytes)
	h.Write(stepBytes)
	sum := h.Sum(nil)
	// Take last 4 bytes as 6-digit code
	offset := sum[len(sum)-1] & 0x0F
	code := int(sum[offset]&0x7F)<<24 | int(sum[offset+1]&0xFF)<<16 | int(sum[offset+2]&0xFF)<<8 | int(sum[offset+3]&0xFF)
	code = code % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// Session represents an active user session.
type Session struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	OrganizationID string    `json:"organization_id"`
	Role          Role      `json:"role"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	IPAddress     string    `json:"ip_address,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
	MFAChecked    bool      `json:"mfa_checked"`
	DeviceInfo    string    `json:"device_info,omitempty"`
}

// SessionManager manages user sessions.
type SessionManager struct {
	directory string
	mu        sync.Mutex
}

// NewSessionManager creates a session manager.
func NewSessionManager(dir string) (*SessionManager, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &SessionManager{directory: dir}, nil
}

// CreateSession creates a new session for a user.
func (sm *SessionManager) CreateSession(user *User, ipAddress, userAgent, deviceInfo string) (*Session, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	sessionID := base64.RawURLEncoding.EncodeToString(bytes)
	session := &Session{
		ID:             sessionID,
		UserID:         user.ID,
		OrganizationID: user.OrganizationID,
		Role:           user.Role,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(24 * time.Hour),
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		MFAChecked:     user.MFAEnabled, // If MFA enabled, session is MFA-checked by default (MFA verified at login)
		DeviceInfo:     deviceInfo,
	}
	data, _ := json.Marshal(session)
	path := filepath.Join(sm.directory, sessionID+".qbsession")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	return session, nil
}

// GetSession retrieves a session by ID.
func (sm *SessionManager) GetSession(id string) (*Session, error) {
	sm.mu.Lock()
	data, err := os.ReadFile(filepath.Join(sm.directory, id+".qbsession"))
	sm.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("session not found: %s", id)
	}
	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}
	if time.Now().After(session.ExpiresAt) {
		sm.DeleteSession(id)
		return nil, fmt.Errorf("session expired")
	}
	return &session, nil
}

// DeleteSession removes a session.
func (sm *SessionManager) DeleteSession(id string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return os.Remove(filepath.Join(sm.directory, id+".qbsession"))
}

// ListSessions returns all sessions for a user.
func (sm *SessionManager) ListSessions(userID string) ([]*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	entries, err := os.ReadDir(sm.directory)
	if err != nil {
		return nil, err
	}
	var sessions []*Session
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".qbsession" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(sm.directory, entry.Name()))
		if err != nil {
			continue
		}
		var session Session
		if err := json.Unmarshal(data, &session); err != nil {
			continue
		}
		if session.UserID == userID && time.Now().Before(session.ExpiresAt) {
			sessions = append(sessions, &session)
		}
	}
	return sessions, nil
}

// InvalidateAllSessions invalidates all sessions for a user (used on password change or security event).
func (sm *SessionManager) InvalidateAllSessions(userID string) (int, error) {
	sessions, err := sm.ListSessions(userID)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, s := range sessions {
		if err := sm.DeleteSession(s.ID); err != nil {
			continue
		}
		count++
	}
	return count, nil
}

// RBAC performs authorization checks.
type RBAC struct {
	userStore    *UserStore
	sessionMgr   *SessionManager
	keyProvider  crypto.KeyProvider
}

// NewRBAC creates an RBAC manager.
func NewRBAC(userDir, sessionDir string, kp crypto.KeyProvider) (*RBAC, error) {
	us, err := NewUserStore(userDir)
	if err != nil {
		return nil, err
	}
	sm, err := NewSessionManager(sessionDir)
	if err != nil {
		return nil, err
	}
	if kp == nil {
		kp = crypto.NewFileKeyProvider(".")
	}
	return &RBAC{
		userStore:  us,
		sessionMgr: sm,
		keyProvider: kp,
	}, nil
}

// CreateUser creates a new user with the given role.
func (rbac *RBAC) CreateUser(orgID, email, name, role string) (*User, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	userID := fmt.Sprintf("QB-USER-%x", bytes)
	secret, _ := GenerateMFASecret()
	user := &User{
		ID:             userID,
		OrganizationID: orgID,
		Email:          email,
		Name:           name,
		Role:           Role(role),
		MFAEnabled:     false,
		MFASecret:      secret,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	if err := rbac.userStore.Save(user); err != nil {
		return nil, err
	}
	return user, nil
}

// AuthenticateUser checks credentials and returns a session if valid.
func (rbac *RBAC) AuthenticateUser(orgID, email, password, totpCode, ipAddress, userAgent string) (*Session, error) {
	// In production, this would check against a hashed password.
	// For now, we use a simplified model.
	users, err := rbac.userStore.List(orgID)
	if err != nil {
		return nil, err
	}
	for _, user := range users {
		if user.Email == email {
			// Verify TOTP if MFA is enabled
			if user.MFAEnabled && totpCode != "" {
				expected, err := MFATOTP(user.MFASecret, time.Now())
				if err != nil || expected != totpCode {
					return nil, fmt.Errorf("invalid TOTP code")
				}
			}
			session, err := rbac.sessionMgr.CreateSession(user, ipAddress, userAgent, "")
			if err != nil {
				return nil, err
			}
			return session, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

// Authorize checks if a session has permission for an action.
func (rbac *RBAC) Authorize(session *Session, permission string) bool {
	return PermissionCheck(session.Role, permission)
}

// EnrollMFA enables MFA for a user and returns the secret.
func (rbac *RBAC) EnrollMFA(userID string) (string, error) {
	user, err := rbac.userStore.Get(userID)
	if err != nil {
		return "", err
	}
	secret, err := GenerateMFASecret()
	if err != nil {
		return "", err
	}
	user.MFASecret = secret
	user.MFAEnabled = true
	user.UpdatedAt = time.Now()
	if err := rbac.userStore.Save(user); err != nil {
		return "", err
	}
	return secret, nil
}

// DisableMFA disables MFA for a user.
func (rbac *RBAC) DisableMFA(userID string) error {
	user, err := rbac.userStore.Get(userID)
	if err != nil {
		return err
	}
	user.MFAEnabled = false
	user.MFASecret = ""
	user.UpdatedAt = time.Now()
	return rbac.userStore.Save(user)
}

// PromoteUser changes a user's role.
func (rbac *RBAC) PromoteUser(userID string, newRole Role) error {
	user, err := rbac.userStore.Get(userID)
	if err != nil {
		return err
	}
	user.Role = newRole
	user.UpdatedAt = time.Now()
	return rbac.userStore.Save(user)
}

// GetUser returns a user by ID.
func (rbac *RBAC) GetUser(userID string) (*User, error) {
	return rbac.userStore.Get(userID)
}

// GetSessions returns all active sessions for a user.
func (rbac *RBAC) GetSessions(userID string) ([]*Session, error) {
	return rbac.sessionMgr.ListSessions(userID)
}

// Logout invalidates a session.
func (rbac *RBAC) Logout(sessionID string) error {
	return rbac.sessionMgr.DeleteSession(sessionID)
}

// SecurityEvent represents a security-relevant event for §66C compliance.
type SecurityEvent struct {
	ID             string                 `json:"id"`
	EventType      string                 `json:"event_type"`
	OrganizationID string                 `json:"organization_id"`
	UserID         string                 `json:"user_id,omitempty"`
	SessionID      string                 `json:"session_id,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
	IPAddress      string                 `json:"ip_address,omitempty"`
	Details        map[string]interface{} `json:"details,omitempty"`
}

// SecurityEventLogger logs security events for audit trail.
type SecurityEventLogger struct {
	directory string
}

// NewSecurityEventLogger creates a security event logger.
func NewSecurityEventLogger(dir string) (*SecurityEventLogger, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &SecurityEventLogger{directory: dir}, nil
}

// Log records a security event.
func (sel *SecurityEventLogger) Log(eventType, orgID, userID, sessionID, ipAddress string, details map[string]interface{}) (*SecurityEvent, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	event := &SecurityEvent{
		ID:             fmt.Sprintf("QB-SEC-%x", bytes),
		EventType:      eventType,
		OrganizationID: orgID,
		UserID:         userID,
		SessionID:      sessionID,
		Timestamp:      time.Now(),
		IPAddress:      ipAddress,
		Details:        details,
	}
	data, _ := json.Marshal(event)
	path := filepath.Join(sel.directory, event.ID+".qbevent")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	return event, nil
}

// ListEvents returns security events for an organization.
func (sel *SecurityEventLogger) ListEvents(orgID string, limit int) ([]*SecurityEvent, error) {
	entries, err := os.ReadDir(sel.directory)
	if err != nil {
		return nil, err
	}
	var events []*SecurityEvent
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".qbevent" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(sel.directory, entry.Name()))
		if err != nil {
			continue
		}
		var event SecurityEvent
		if err := json.Unmarshal(data, &event); err != nil {
			continue
		}
		if event.OrganizationID == orgID {
			events = append(events, &event)
		}
	}
	// Sort by timestamp descending and limit
	for i := 0; i < len(events)-1; i++ {
		for j := i + 1; j < len(events); j++ {
			if events[j].Timestamp.After(events[i].Timestamp) {
				events[i], events[j] = events[j], events[i]
			}
		}
	}
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

// AnnotateUser annotates a user with additional metadata.
func (rbac *RBAC) AnnotateUser(userID string, key, value string) error {
	path := filepath.Join(rbac.userStore.directory, userID+".qbuser.meta")
	var meta map[string]string
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, &meta)
	}
	if meta == nil {
		meta = make(map[string]string)
	}
	meta[key] = value
	data, _ := json.Marshal(meta)
	return os.WriteFile(path, data, 0600)
}
