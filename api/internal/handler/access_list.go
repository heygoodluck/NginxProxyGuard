package handler

import (
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

type AccessListHandler struct {
	repo       *repository.AccessListRepository
	proxyHosts *service.ProxyHostService
	audit      *service.AuditService
}

func NewAccessListHandler(repo *repository.AccessListRepository, proxyHosts *service.ProxyHostService, audit *service.AuditService) *AccessListHandler {
	return &AccessListHandler{repo: repo, proxyHosts: proxyHosts, audit: audit}
}

// List returns a paginated list of access lists.
// Query parameters: page (default: 1), per_page (default: 20, max: 100)
func (h *AccessListHandler) List(c echo.Context) error {
	page, perPage := ParsePaginationParams(c)

	lists, total, err := h.repo.List(c.Request().Context(), page, perPage)
	if err != nil {
		return databaseError(c, "list access lists", err)
	}

	return c.JSON(http.StatusOK, model.AccessListListResponse{
		Data:       lists,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: CalculateTotalPages(total, perPage),
	})
}

// Create creates a new access list.
func (h *AccessListHandler) Create(c echo.Context) error {
	var req model.CreateAccessListRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	// Validate required fields
	if err := ValidateRequired(req.Name, "name"); err != nil {
		return validationError(c, "name", "is required")
	}

	// Validate field lengths
	if err := ValidateStringLength(req.Name, MaxNameLength, "name"); err != nil {
		return validationError(c, "name", err.(*ValidationError).Message)
	}

	// The rules become allow/deny lines in each host's config, and the
	// name and rule descriptions comments beside them.
	if err := model.ValidateCreateAccessListRequest(&req); err != nil {
		return badRequestError(c, trimInvalidInputPrefix(err))
	}

	list, err := h.repo.Create(c.Request().Context(), &req)
	if err != nil {
		return databaseError(c, "create access list", err)
	}

	h.audit.LogAccessListCreated(service.ContextWithAudit(c.Request().Context(), c), list.Name)
	return createdResponse(c, list)
}

// Get retrieves an access list by ID.
func (h *AccessListHandler) Get(c echo.Context) error {
	id := c.Param("id")
	list, err := h.repo.GetByID(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "get access list", err)
	}
	if list == nil {
		return notFoundError(c, "Access list")
	}
	return c.JSON(http.StatusOK, list)
}

// Update updates an existing access list.
func (h *AccessListHandler) Update(c echo.Context) error {
	id := c.Param("id")
	var req model.UpdateAccessListRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	// Validate field lengths if name is provided
	if req.Name != nil && *req.Name != "" {
		if err := ValidateStringLength(*req.Name, MaxNameLength, "name"); err != nil {
			return validationError(c, "name", err.(*ValidationError).Message)
		}
	}
	if err := model.ValidateUpdateAccessListRequest(&req); err != nil {
		return badRequestError(c, trimInvalidInputPrefix(err))
	}

	before, err := h.repo.GetByID(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "get access list", err)
	}
	if before == nil {
		return notFoundError(c, "Access list")
	}

	list, err := h.repo.Update(c.Request().Context(), id, &req)
	if err != nil {
		return databaseError(c, "update access list", err)
	}
	if list == nil {
		return notFoundError(c, "Access list")
	}
	// Recorded before the nginx regeneration: the change is saved even if
	// applying it to nginx fails below.
	h.audit.LogAccessListUpdated(service.ContextWithAudit(c.Request().Context(), c), list.Name, accessListChanges(before, list))

	// Access list rules are rendered statically into each dependent host's
	// nginx config, so the edit must fan out to every referencing host —
	// otherwise nginx silently keeps enforcing the stale allow/deny rules.
	if err := h.proxyHosts.RegenerateConfigsForAccessList(c.Request().Context(), id); err != nil {
		return internalError(c, "apply access list changes to nginx", err)
	}

	return c.JSON(http.StatusOK, list)
}

// Delete removes an access list by ID.
func (h *AccessListHandler) Delete(c echo.Context) error {
	id := c.Param("id")
	ctx := c.Request().Context()

	existing, err := h.repo.GetByID(ctx, id)
	if err != nil {
		return databaseError(c, "get access list", err)
	}
	if existing == nil {
		return notFoundError(c, "Access list")
	}

	// Capture dependents BEFORE the delete detaches them (the repo clears
	// proxy_hosts.access_list_id in the same transaction).
	hostIDs, err := h.proxyHosts.GetHostIDsByAccessList(ctx, id)
	if err != nil {
		return databaseError(c, "list access list dependents", err)
	}

	if err := h.repo.Delete(ctx, id); err != nil {
		return databaseError(c, "delete access list", err)
	}
	h.audit.LogAccessListDeleted(service.ContextWithAudit(ctx, c), existing.Name)

	// Regenerate dependent host configs so the deleted allow/deny rules stop
	// being enforced by the running nginx.
	if len(hostIDs) > 0 {
		if err := h.proxyHosts.RegenerateConfigsForHostIDs(ctx, hostIDs); err != nil {
			return internalError(c, "apply access list deletion to nginx", err)
		}
	}

	return noContentResponse(c)
}

// accessListChanges describes an access list update for the audit log: the
// rules added and removed ("allow 192.0.2.0/24") and, when they changed, the
// name (as "renamed") and satisfy_any as [before, after]. The audit service
// fills the entry's "name" with the list's current name, so a rename under
// that key would lose the old name.
func accessListChanges(before, after *model.AccessList) map[string]interface{} {
	details := map[string]interface{}{}
	rule := func(it model.AccessListItem) string { return it.Directive + " " + it.Address }
	left := map[string]int{}
	for _, it := range before.Items {
		left[rule(it)]++
	}
	var added []string
	for _, it := range after.Items {
		if left[rule(it)] > 0 {
			left[rule(it)]--
			continue
		}
		added = append(added, rule(it))
	}
	var removed []string
	for _, it := range before.Items {
		if left[rule(it)] > 0 {
			left[rule(it)]--
			removed = append(removed, rule(it))
		}
	}
	if len(added) > 0 {
		details["added"] = added
	}
	if len(removed) > 0 {
		details["removed"] = removed
	}
	if before.Name != after.Name {
		details["renamed"] = []string{before.Name, after.Name}
	}
	if before.SatisfyAny != after.SatisfyAny {
		details["satisfy_any"] = []bool{before.SatisfyAny, after.SatisfyAny}
	}
	return details
}
