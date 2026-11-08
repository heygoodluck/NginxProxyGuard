package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
)

// ChangeCredentials must only be callable by accounts in initial setup state.
// Established accounts must not be able to mutate their email or credentials
// via this self-service route, preventing SSO pre-hijack privilege escalation.
func TestChangeCredentialsRejectsConfiguredUser(t *testing.T) {
	h := NewAuthHandler(nil, nil)

	e := echo.New()
	reqBody := `{"current_password":"oldPassword!1","new_username":"alice","new_password":"NewPassword!1","new_password_confirm":"NewPassword!1","new_email":"admin@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-credentials", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// User whose initial setup is already complete (is_initial_setup = false)
	c.Set("user", &model.User{
		ID:             "00000000-0000-0000-0000-000000000001",
		Username:       "viewer",
		IsInitialSetup: false,
	})

	err := h.ChangeCredentials(c)
	if err != nil {
		t.Fatalf("unexpected handler error: %v", err)
	}

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusForbidden)
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] != "Initial setup has already been completed" {
		t.Fatalf("unexpected error message: %q", resp["error"])
	}
}

func TestChangeCredentialsRejectsUnauthenticated(t *testing.T) {
	h := NewAuthHandler(nil, nil)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-credentials", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.ChangeCredentials(c)
	if err != nil {
		t.Fatalf("unexpected handler error: %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

