package user

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/httpx"
	"github.com/Hesham127/flwnBackend/internal/platform/secure"
)

type handler struct {
	svc *Service
}

// self parses :user_id and allows only the caller's own account.
func self(c *gin.Context) (uuid.UUID, bool) {
	id, ok := httpx.PathUUID(c, "user_id")
	if !ok {
		return uuid.Nil, false
	}
	if id != secure.PrincipalFrom(c).UserID {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "not_your_account"})
		return uuid.Nil, false
	}
	return id, true
}

func (h *handler) get(c *gin.Context) {
	id, ok := self(c)
	if !ok {
		return
	}
	out, err := h.svc.Get(c.Request.Context(), id)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *handler) update(c *gin.Context) {
	id, ok := self(c)
	if !ok {
		return
	}
	// Email is the login identity: it changes only through the verified /auth/email flow.
	raw, _ := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	var probe map[string]json.RawMessage
	if json.Unmarshal(raw, &probe) == nil {
		if _, has := probe["email"]; has {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "email_changes_use_auth_email"})
			return
		}
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	var in Update
	if !httpx.BindJSON(c, &in) {
		return
	}
	out, err := h.svc.Update(c.Request.Context(), id, in)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}
