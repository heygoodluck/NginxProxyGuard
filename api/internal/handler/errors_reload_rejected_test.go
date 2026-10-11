package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/nginx"
)

func rejectedErr() error {
	return fmt.Errorf("apply access list changes to nginx: %w",
		&nginx.ReloadRejectedError{Detail: `bind() to 0.0.0.0:18998 failed (98: Address in use)`})
}

func TestInternalErrorAnswersARejectedReloadWith409(t *testing.T) {
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodPut, "/", nil), rec)
	if err := internalError(c, "apply", rejectedErr()); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	var body ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "nginx_reload_rejected" {
		t.Errorf("code = %q", body.Code)
	}
	if !strings.Contains(body.Details, "Address in use") {
		t.Errorf("details = %q, want nginx's line", body.Details)
	}
	if !strings.Contains(body.Error, "free that port") {
		t.Errorf("error = %q, want the port hint", body.Error)
	}
}

func TestDirectInternalErrorAnswersARejectedReloadWith409(t *testing.T) {
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodPut, "/", nil), rec)
	if err := directInternalError(c, rejectedErr()); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}
