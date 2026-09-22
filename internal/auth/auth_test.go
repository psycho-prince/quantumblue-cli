package auth

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psycho-prince/pqc-sdk/internal/crypto"
)

func TestPermissionCheck(t *testing.T) {
	tests := []struct {
		role       Role
		permission string
		want       bool
	}{
		{RoleAdmin, "evidence:read", true},
		{RoleAdmin, "evidence:write", true},
		{RoleAdmin, "evidence:delete", true},
		{RoleAdmin, "admin:write", true},
		{RoleAdmin, "audit:read", true},

		{RoleInvestigator, "evidence:read", true},
		{RoleInvestigator, "evidence:write", true},
		{RoleInvestigator, "evidence:delete", false},
		{RoleInvestigator, "admin:write", false},

		{RoleAuditor, "evidence:read", true},
		{RoleAuditor, "evidence:write", false},
		{RoleAuditor, "audit:read", true},

		{RoleViewer, "evidence:read", true},
		{RoleViewer, "evidence:write", false},
		{RoleViewer, "audit:read", false},

		{RoleViewer, "nonexistent:permission", false},
	}

	for _, tt := range tests {
		if got := PermissionCheck(tt.role, tt.permission); got != tt.want {
			t.Errorf("PermissionCheck(%s, %s) = %v, want %v", tt.role, tt.permission, got, tt.want)
		}
	}
}

func TestUserStore_SaveAndGet(t *testing.T) {
	dir := t.TempDir()
	us, err := NewUserStore(dir)
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}

	user := &User{
		ID:             "test-user-1",
		OrganizationID: "org-1",
		Email:          "test@example.com",
		Name:           "Test User",
		Role:           RoleInvestigator,
		MFAEnabled:     false,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if err := us.Save(user); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := us.Get("test-user-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Email != user.Email {
		t.Errorf("Email = %q, want %q", got.Email, user.Email)
	}
	if got.OrganizationID != user.OrganizationID {
		t.Errorf("OrganizationID = %q, want %q", got.OrganizationID, user.OrganizationID)
	}

	// Non-existent user
	_, err = us.Get("nonexistent")
	if err == nil {
		t.Error("Get(nonexistent) should return error")
	}
}

func TestUserStore_List(t *testing.T) {
	dir := t.TempDir()
	us, err := NewUserStore(dir)
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}

	u1 := &User{ID: "u1", OrganizationID: "org-a", Email: "a@example.com", Name: "A", Role: RoleViewer, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	u2 := &User{ID: "u2", OrganizationID: "org-a", Email: "b@example.com", Name: "B", Role: RoleViewer, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	u3 := &User{ID: "u3", OrganizationID: "org-b", Email: "c@example.com", Name: "C", Role: RoleViewer, CreatedAt: time.Now(), UpdatedAt: time.Now()}

	if err := us.Save(u1); err != nil {
		t.Fatal(err)
	}
	if err := us.Save(u2); err != nil {
		t.Fatal(err)
	}
	if err := us.Save(u3); err != nil {
		t.Fatal(err)
	}

	users, err := us.List("org-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Errorf("List(org-a) returned %d users, want 2", len(users))
	}

	usersB, err := us.List("org-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(usersB) != 1 {
		t.Errorf("List(org-b) returned %d users, want 1", len(usersB))
	}
}

func TestUserStore_Delete(t *testing.T) {
	dir := t.TempDir()
	us, err := NewUserStore(dir)
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}

	user := &User{ID: "del-me", OrganizationID: "org-1", Email: "del@example.com", Name: "Del", Role: RoleViewer, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := us.Save(user); err != nil {
		t.Fatal(err)
	}

	if err := us.Delete("del-me"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = us.Get("del-me")
	if err == nil {
		t.Error("Get after delete should fail")
	}
}

func TestGenerateMFASecret(t *testing.T) {
	secret, err := GenerateMFASecret()
	if err != nil {
		t.Fatalf("GenerateMFASecret: %v", err)
	}
	if secret == "" {
		t.Error("MFA secret is empty")
	}
	// Should be valid base32
	if _, err := base64.RawURLEncoding.DecodeString(secret); err != nil {
		t.Errorf("MFA secret should be valid base32: %v", err)
	}
	// Length should be reasonable (20 bytes base32-encoded ≈ 32 chars)
	if len(secret) < 20 {
		t.Errorf("MFA secret too short: %d chars", len(secret))
	}
}

func TestMFATOTP(t *testing.T) {
	secret, err := GenerateMFASecret()
	if err != nil {
		t.Fatal(err)
	}

	code, err := MFATOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("MFATOTP: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("TOTP code length = %d, want 6", len(code))
	}
	// Should be all digits
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("TOTP code contains non-digit: %c", c)
		}
	}
}

func TestSessionManager_CreateAndGet(t *testing.T) {
	dir := t.TempDir()
	sm, err := NewSessionManager(dir)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	user := &User{
		ID: "user-1", OrganizationID: "org-1", Email: "s@example.com",
		Name: "S", Role: RoleAdmin, MFAEnabled: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}

	session, err := sm.CreateSession(user, "192.168.1.1", "Mozilla/5.0", "MacBook Pro")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if session.UserID != "user-1" {
		t.Errorf("session.UserID = %q, want %q", session.UserID, "user-1")
	}
	if session.IPAddress != "192.168.1.1" {
		t.Errorf("session.IPAddress = %q, want %q", session.IPAddress, "192.168.1.1")
	}
	if !session.MFAChecked {
		t.Error("MFA-enabled user session should have MFAChecked=true")
	}

	// Retrieve
	got, err := sm.GetSession(session.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ID != session.ID {
		t.Errorf("GetSession returned different session ID")
	}
}

func TestSessionManager_ExpiredSession(t *testing.T) {
	dir := t.TempDir()
	sm, err := NewSessionManager(dir)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	user := &User{ID: "user-exp", OrganizationID: "org-1", Email: "e@example.com", Name: "E", Role: RoleViewer, CreatedAt: time.Now(), UpdatedAt: time.Now()}

	session, err := sm.CreateSession(user, "10.0.0.1", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Manually expire the session by modifying the file
	sessionPath := filepath.Join(dir, session.ID+".qbsession")
	sessionData, _ := os.ReadFile(sessionPath)
	var s Session
	json.Unmarshal(sessionData, &s) //nolint:errcheck
	s.ExpiresAt = time.Now().Add(-1 * time.Hour)
	modifiedData, _ := json.Marshal(s)
	os.WriteFile(sessionPath, modifiedData, 0600)

	_, err = sm.GetSession(session.ID)
	if err == nil {
		t.Error("GetSession on expired session should fail")
	}
}

func TestSessionManager_DeleteAndList(t *testing.T) {
	dir := t.TempDir()
	sm, err := NewSessionManager(dir)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	user := &User{ID: "user-list", OrganizationID: "org-1", Email: "l@example.com", Name: "L", Role: RoleViewer, CreatedAt: time.Now(), UpdatedAt: time.Now()}

	s1, _ := sm.CreateSession(user, "1.1.1.1", "", "")
	sm.CreateSession(user, "2.2.2.2", "", "")

	sessions, err := sm.ListSessions("user-list")
	_ = s1
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Errorf("ListSessions returned %d, want 2", len(sessions))
	}

	if err := sm.DeleteSession(s1.ID); err != nil {
		t.Fatal(err)
	}

	sessions, err = sm.ListSessions("user-list")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Errorf("after delete, ListSessions returned %d, want 1", len(sessions))
	}
}

func TestSessionManager_InvalidateAll(t *testing.T) {
	dir := t.TempDir()
	sm, err := NewSessionManager(dir)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	user := &User{ID: "user-inv", OrganizationID: "org-1", Email: "i@example.com", Name: "I", Role: RoleViewer, CreatedAt: time.Now(), UpdatedAt: time.Now()}

	sm.CreateSession(user, "1.1.1.1", "", "")
	sm.CreateSession(user, "2.2.2.2", "", "")
	sm.CreateSession(user, "3.3.3.3", "", "")

	count, err := sm.InvalidateAllSessions("user-inv")
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("InvalidateAllSessions returned %d, want 3", count)
	}

	sessions, _ := sm.ListSessions("user-inv")
	if len(sessions) != 0 {
		t.Errorf("after invalidation, %d sessions remain, want 0", len(sessions))
	}
}

func TestRBAC_CreateUser(t *testing.T) {
	dir := t.TempDir()
	rbac, err := NewRBAC(dir, dir, nil)
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}

	user, err := rbac.CreateUser("org-test", "create@example.com", "Create User", "INVESTIGATOR")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.Email != "create@example.com" {
		t.Errorf("Email = %q, want %q", user.Email, "create@example.com")
	}
	if user.OrganizationID != "org-test" {
		t.Errorf("OrganizationID = %q, want %q", user.OrganizationID, "org-test")
	}
	if user.Role != RoleInvestigator {
		t.Errorf("Role = %q, want %q", user.Role, RoleInvestigator)
	}
	// New user has a secret generated but MFA not enabled until enrolled
	if user.MFASecret == "" {
		t.Error("new user should have MFA secret generated")
	}
	if user.MFAEnabled {
		t.Error("new user should NOT have MFA enabled by default (must be enrolled)")
	}
}

func TestRBAC_AuthenticateUser(t *testing.T) {
	dir := t.TempDir()
	rbac, err := NewRBAC(dir, dir, nil)
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}

	_, err = rbac.CreateUser("org-auth", "auth@example.com", "Auth User", "VIEWER")
	if err != nil {
		t.Fatal(err)
	}

	session, err := rbac.AuthenticateUser("org-auth", "auth@example.com", "", "", "10.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("AuthenticateUser: %v", err)
	}
	if session.UserID == "" {
		t.Error("session.UserID is empty")
	}

	// Wrong email
	_, err = rbac.AuthenticateUser("org-auth", "wrong@example.com", "", "", "", "")
	if err == nil {
		t.Error("AuthenticateUser with wrong email should fail")
	}
}

func TestRBAC_Authorize(t *testing.T) {
	dir := t.TempDir()
	rbac, err := NewRBAC(dir, dir, nil)
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}

	rbac.CreateUser("org-authz", "authz@example.com", "AuthZ", "ADMIN")

	session, err := rbac.AuthenticateUser("org-authz", "authz@example.com", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if !rbac.Authorize(session, "evidence:delete") {
		t.Error("ADMIN should be authorized for evidence:delete")
	}
	if !rbac.Authorize(session, "admin:write") {
		t.Error("ADMIN should be authorized for admin:write")
	}
}

func TestRBAC_EnrollAndDisableMFA(t *testing.T) {
	dir := t.TempDir()
	rbac, err := NewRBAC(dir, dir, nil)
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}

	user, err := rbac.CreateUser("org-mfa", "mfa@example.com", "MFA User", "VIEWER")
	if err != nil {
		t.Fatal(err)
	}

	// Enroll MFA
	secret, err := rbac.EnrollMFA(user.ID)
	if err != nil {
		t.Fatalf("EnrollMFA: %v", err)
	}
	if secret == "" {
		t.Error("EnrollMFA returned empty secret")
	}

	updated, err := rbac.GetUser(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.MFAEnabled {
		t.Error("user should have MFA enabled after EnrollMFA")
	}
	if updated.MFASecret == "" {
		t.Error("user should have MFA secret after EnrollMFA")
	}

	// Disable MFA
	if err := rbac.DisableMFA(user.ID); err != nil {
		t.Fatalf("DisableMFA: %v", err)
	}

	updated, err = rbac.GetUser(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.MFAEnabled {
		t.Error("user should have MFA disabled after DisableMFA")
	}
}

func TestRBAC_PromoteUser(t *testing.T) {
	dir := t.TempDir()
	rbac, err := NewRBAC(dir, dir, nil)
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}

	user, err := rbac.CreateUser("org-promo", "promo@example.com", "Promo", "VIEWER")
	if err != nil {
		t.Fatal(err)
	}

	if err := rbac.PromoteUser(user.ID, "ADMIN"); err != nil {
		t.Fatalf("PromoteUser: %v", err)
	}

	updated, err := rbac.GetUser(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Role != RoleAdmin {
		t.Errorf("Role = %q, want %q", updated.Role, RoleAdmin)
	}
}

func TestRBAC_Logout(t *testing.T) {
	dir := t.TempDir()
	rbac, err := NewRBAC(dir, dir, nil)
	if err != nil {
		t.Fatalf("NewRBAC: %v", err)
	}

	_, err = rbac.CreateUser("org-logout", "logout@example.com", "Logout", "VIEWER")
	if err != nil {
		t.Fatal(err)
	}
	session, _ := rbac.AuthenticateUser("org-logout", "logout@example.com", "", "", "", "")

	if err := rbac.Logout(session.ID); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	_, err = rbac.GetUser(session.UserID) // user should still exist
	if err != nil {
		t.Error("user should still exist after logout")
	}
}

func TestSecurityEventLogger_LogAndList(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewSecurityEventLogger(dir)
	if err != nil {
		t.Fatalf("NewSecurityEventLogger: %v", err)
	}

	event, err := logger.Log("LOGIN_SUCCESS", "org-events", "user-events", "sess-events", "10.0.0.1", map[string]interface{}{"method": "password"})
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if event.EventType != "LOGIN_SUCCESS" {
		t.Errorf("EventType = %q, want %q", event.EventType, "LOGIN_SUCCESS")
	}
	if event.OrganizationID != "org-events" {
		t.Errorf("OrganizationID = %q, want %q", event.OrganizationID, "org-events")
	}

	// Log another event
	logger.Log("PASSWORD_CHANGE", "org-events", "user-events", "sess-events", "10.0.0.2", nil)

	events, err := logger.ListEvents("org-events", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Errorf("ListEvents returned %d events, want 2", len(events))
	}

	// Events should be sorted by timestamp descending
	if len(events) >= 2 {
		if events[0].Timestamp.Before(events[1].Timestamp) {
			t.Error("events should be sorted by timestamp descending")
		}
	}

	// Wrong org should return empty
	empty, _ := logger.ListEvents("wrong-org", 10)
	if len(empty) != 0 {
		t.Errorf("ListEvents(wrong-org) returned %d events, want 0", len(empty))
	}
}

func TestRBAC_Integration(t *testing.T) {
	dir := t.TempDir()
	rbac, err := NewRBAC(dir, dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Full lifecycle
	user, err := rbac.CreateUser("org-full", "full@example.com", "Full User", "VIEWER")
	if err != nil {
		t.Fatal(err)
	}

	// Authenticate
	session, err := rbac.AuthenticateUser("org-full", "full@example.com", "", "", "192.168.1.100", "TestClient")
	if err != nil {
		t.Fatal(err)
	}

	// Check permission
	if !rbac.Authorize(session, "evidence:read") {
		t.Error("VIEWER should have evidence:read")
	}
	if rbac.Authorize(session, "evidence:write") {
		t.Error("VIEWER should NOT have evidence:write")
	}

	// Enroll MFA
	rbac.EnrollMFA(user.ID)

	// Get sessions
	sessions, err := rbac.GetSessions(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Errorf("GetSessions returned %d, want 1", len(sessions))
	}

	// Get user
	retrieved, err := rbac.GetUser(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retrieved.Email != "full@example.com" {
		t.Errorf("Email = %q, want %q", retrieved.Email, "full@example.com")
	}

	// Logout
	rbac.Logout(session.ID)

	sessions, _ = rbac.GetSessions(user.ID)
	if len(sessions) != 0 {
		t.Errorf("after logout, %d sessions remain, want 0", len(sessions))
	}
}

func TestNewRBAC_NilKeyProvider(t *testing.T) {
	dir := t.TempDir()
	rbac, err := NewRBAC(dir, dir, nil)
	if err != nil {
		t.Fatalf("NewRBAC with nil key provider: %v", err)
	}
	if rbac.keyProvider == nil {
		t.Error("keyProvider should not be nil after NewRBAC with nil input")
	}
	if _, ok := rbac.keyProvider.(*crypto.FileKeyProvider); !ok {
		t.Error("keyProvider should be FileKeyProvider when nil is passed")
	}
}
