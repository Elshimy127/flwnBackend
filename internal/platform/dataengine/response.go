package dataengine

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// APIError is a non-success answer from the engine. Detail is the engine's `detail` field:
// usually a string, a list of field errors for request validation.
type APIError struct {
	Status int
	Detail json.RawMessage
}

func (e *APIError) Error() string {
	return fmt.Sprintf("data engine: %d %s", e.Status, e.Detail)
}

// Decode reads a JSON engine response into T, or returns an *APIError for a non-2xx status.
// It takes the (response, error) pair a generated Client method returns, so a call reads
// `return dataengine.Decode[Task](s.engine.GetTask...(ctx, ...))`.
//
// We don't use the generated ...WithResponse wrappers: they decode error bodies with the
// spec's types, and the engine sometimes sends a string detail where the spec promises a list,
// which makes them fail and lose the status code.
func Decode[T any](res *http.Response, err error) (*T, error) {
	if err := check(res, err); err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var out T
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("data engine: decode %T: %w", out, err)
	}
	return &out, nil
}

// NoContent is Decode for endpoints that return no body, such as DELETE.
func NoContent(res *http.Response, err error) error {
	if err := check(res, err); err != nil {
		return err
	}
	return res.Body.Close()
}

func check(res *http.Response, err error) error {
	if err != nil {
		return err
	}
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return nil
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	var payload struct {
		Detail json.RawMessage `json:"detail"`
	}
	if json.Unmarshal(body, &payload) != nil || len(payload.Detail) == 0 {
		payload.Detail, _ = json.Marshal(http.StatusText(res.StatusCode))
	}
	return &APIError{Status: res.StatusCode, Detail: payload.Detail}
}
