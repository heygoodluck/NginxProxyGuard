package handler

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/nginx"
)

// Common error messages for clients (no internal details)
const (
	ErrMsgInternalError    = "An internal error occurred"
	// Same string the scrub substitutes for driver text, by reference rather
	// than by copy: a stored error and a returned one must not start wording
	// the same failure differently.
	ErrMsgDatabaseError    = database.MsgDatabaseError
	ErrMsgNotFound         = "Resource not found"
	ErrMsgUnauthorized     = "Authentication required"
	ErrMsgForbidden        = "Access denied"
	ErrMsgBadRequest       = "Invalid request"
	ErrMsgConflict         = "Resource conflict"
	ErrMsgValidationFailed = "Validation failed"
)

// ErrorResponse is the standard error response structure
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
	// Code names a failure the client can act on, e.g. nginx_reload_rejected.
	Code string `json:"code,omitempty"`
}

// internalError logs the actual error and returns a generic message to the client
func internalError(c echo.Context, operation string, err error) error {
	log.Printf("[ERROR] %s: %v", operation, err)
	if status, body, ok := reloadRejectedResponse(err); ok {
		return c.JSON(status, body)
	}
	if status, msg, ok := ClientStatusForDBError(err); ok {
		return c.JSON(status, ErrorResponse{Error: msg})
	}
	return c.JSON(http.StatusInternalServerError, ErrorResponse{
		Error:   ErrMsgInternalError,
		Details: SafeErrorDetail(err),
	})
}

// databaseError logs the database error and returns a generic message
func databaseError(c echo.Context, operation string, err error) error {
	log.Printf("[DB ERROR] %s: %v", operation, err)
	if status, body, ok := reloadRejectedResponse(err); ok {
		return c.JSON(status, body)
	}
	if status, msg, ok := ClientStatusForDBError(err); ok {
		return c.JSON(status, ErrorResponse{Error: msg})
	}
	return c.JSON(http.StatusInternalServerError, ErrorResponse{
		Error:   ErrMsgDatabaseError,
		Details: SafeErrorDetail(err),
	})
}

// notFoundError returns a not found error
func notFoundError(c echo.Context, resource string) error {
	return c.JSON(http.StatusNotFound, map[string]string{
		"error": resource + " not found",
	})
}

// badRequestError returns a bad request error with a safe message.
// Callers hand it a rendered service error in 30-odd places, so the driver
// scrub happens here rather than at each of them. (#298)
func badRequestError(c echo.Context, message string) error {
	return c.JSON(http.StatusBadRequest, map[string]string{
		"error": scrubbedClientText(message),
	})
}

// unauthorizedError returns an unauthorized error
func unauthorizedError(c echo.Context) error {
	return c.JSON(http.StatusUnauthorized, map[string]string{
		"error": ErrMsgUnauthorized,
	})
}

// forbiddenError returns a forbidden error
func forbiddenError(c echo.Context) error {
	return c.JSON(http.StatusForbidden, map[string]string{
		"error": ErrMsgForbidden,
	})
}

// httpJSONError writes a JSON error response for standard http.ResponseWriter handlers
func httpJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: scrubbedClientText(message)})
}

// httpJSONErrorWithDetails writes a JSON error response with details
func httpJSONErrorWithDetails(w http.ResponseWriter, message string, status int, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: scrubbedClientText(message), Details: scrubbedClientText(details)})
}

// httpInternalError is for standard http.ResponseWriter handlers
func httpInternalError(w http.ResponseWriter, operation string, err error) {
	log.Printf("[ERROR] %s: %v", operation, err)
	if status, body, ok := reloadRejectedResponse(err); ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(body)
		return
	}
	if status, msg, ok := ClientStatusForDBError(err); ok {
		httpJSONError(w, msg, status)
		return
	}
	httpJSONErrorWithDetails(w, ErrMsgInternalError, http.StatusInternalServerError, SafeErrorDetail(err))
}

// httpDatabaseError is for standard http.ResponseWriter handlers
func httpDatabaseError(w http.ResponseWriter, operation string, err error) {
	log.Printf("[DB ERROR] %s: %v", operation, err)
	if status, body, ok := reloadRejectedResponse(err); ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(body)
		return
	}
	if status, msg, ok := ClientStatusForDBError(err); ok {
		httpJSONError(w, msg, status)
		return
	}
	httpJSONErrorWithDetails(w, ErrMsgDatabaseError, http.StatusInternalServerError, SafeErrorDetail(err))
}

// validationError returns a validation error with field details
func validationError(c echo.Context, field, message string) error {
	return c.JSON(http.StatusBadRequest, map[string]string{
		"error": scrubbedClientText(field + " " + message),
		"field": field,
	})
}

// conflictError returns a conflict error
func conflictError(c echo.Context, message string) error {
	return c.JSON(http.StatusConflict, map[string]string{
		"error": scrubbedClientText(message),
	})
}

// successMessage returns a success response with a message
func successMessage(c echo.Context, message string) error {
	return c.JSON(http.StatusOK, map[string]string{
		"message": message,
	})
}

// createdResponse returns a 201 Created response with the created resource
func createdResponse(c echo.Context, data interface{}) error {
	return c.JSON(http.StatusCreated, data)
}

// noContentResponse returns a 204 No Content response
func noContentResponse(c echo.Context) error {
	return c.NoContent(http.StatusNoContent)
}

// reloadRejectedResponse answers a save whose files nginx -t accepted but the
// running nginx refused (nginx.ErrReloadRejected) with 409 rather than 500:
// the change is stored and on disk, and what the operator must do (restart
// nginx, or free a port) is in the message. 503 is not used because the UI
// shows its own "server unavailable" text for 502-504.
func reloadRejectedResponse(err error) (int, ErrorResponse, bool) {
	var rejected *nginx.ReloadRejectedError
	if !errors.As(err, &rejected) {
		return 0, ErrorResponse{}, false
	}
	return http.StatusConflict, ErrorResponse{
		Error:   rejected.Error(),
		Details: rejected.Detail,
		Code:    "nginx_reload_rejected",
	}, true
}
