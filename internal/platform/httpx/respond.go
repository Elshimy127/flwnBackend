// Package httpx holds the Gin helpers every domain handler shares.
package httpx

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
)

// Error writes err as a JSON response.
//
// Engine 4xx answers are about the caller's input (not found, duplicate, invalid field), so their
// status and detail pass through. A 401/403 from the engine means our service key is wrong, and a
// 5xx or transport failure means the engine is down; neither is the caller's fault, so both
// become 502.
func Error(c *gin.Context, err error) {
	var apiErr *dataengine.APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusForbidden:
			log.Printf("data engine rejected the service key: %v", err)
		case apiErr.Status >= 500:
			log.Printf("data engine error: %v", err)
		default:
			c.JSON(apiErr.Status, gin.H{"detail": apiErr.Detail})
			return
		}
	} else {
		log.Printf("data engine unreachable: %v", err)
	}
	c.JSON(http.StatusBadGateway, gin.H{"detail": "data engine unavailable"})
}

func badRequest(c *gin.Context, detail string) {
	c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"detail": detail})
}

// BindJSON decodes the body into v. It writes a 400 and returns false on failure.
func BindJSON(c *gin.Context, v any) bool {
	if err := c.ShouldBindJSON(v); err != nil {
		badRequest(c, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// PathUUID parses a UUID path param. It writes a 400 and returns false on failure.
func PathUUID(c *gin.Context, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param(name))
	if err != nil {
		badRequest(c, name+" must be a UUID")
		return uuid.Nil, false
	}
	return id, true
}

// QueryUUID parses an optional UUID query param; nil when absent.
func QueryUUID(c *gin.Context, name string) (*uuid.UUID, bool) {
	raw, ok := c.GetQuery(name)
	if !ok {
		return nil, true
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		badRequest(c, name+" must be a UUID")
		return nil, false
	}
	return &id, true
}

// QueryInt parses an optional integer query param; nil when absent.
func QueryInt(c *gin.Context, name string) (*int, bool) {
	raw, ok := c.GetQuery(name)
	if !ok {
		return nil, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		badRequest(c, name+" must be an integer")
		return nil, false
	}
	return &n, true
}

// QueryBool parses an optional boolean query param; nil when absent.
func QueryBool(c *gin.Context, name string) (*bool, bool) {
	raw, ok := c.GetQuery(name)
	if !ok {
		return nil, true
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		badRequest(c, name+" must be true or false")
		return nil, false
	}
	return &b, true
}

// QueryString returns an optional query param; nil when absent.
func QueryString(c *gin.Context, name string) *string {
	if raw, ok := c.GetQuery(name); ok {
		return &raw
	}
	return nil
}

// QueryPage reads limit and offset. Range checks are left to the engine.
func QueryPage(c *gin.Context) (dataengine.Page, bool) {
	limit, ok := QueryInt(c, "limit")
	if !ok {
		return dataengine.Page{}, false
	}
	offset, ok := QueryInt(c, "offset")
	if !ok {
		return dataengine.Page{}, false
	}
	return dataengine.Page{Limit: limit, Offset: offset}, true
}
