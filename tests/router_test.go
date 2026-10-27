package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const taskJSON = `{
	"id": "11111111-1111-1111-1111-111111111111",
	"workspace_id": "22222222-2222-2222-2222-222222222222",
	"project_id": "33333333-3333-3333-3333-333333333333",
	"work_item_id": "44444444-4444-4444-4444-444444444444",
	"sprint_id": null, "milestone_id": null, "parent_task_id": null,
	"number": 1, "identifier": "DATA-1", "title": "Add approval endpoint",
	"description": null, "requirements": null, "acceptance_criteria": null,
	"priority": "high", "status": "todo", "estimate": 3, "due_date": null,
	"started_at": null, "completed_at": null, "sort_order": 0,
	"assignee_id": null, "created_by": null,
	"created_at": "2026-10-27T10:00:00Z", "updated_at": "2026-10-27T10:00:00Z"
}`

func do(t *testing.T, f *fakeEngine, method, path, body string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.router(t).ServeHTTP(w, req)
	return w
}

func tasksPath(ws, project uuid.UUID) string {
	return "/api/v1/workspaces/" + ws.String() + "/projects/" + project.String() + "/tasks"
}

func TestCreateTaskForwardsBodyAndActor(t *testing.T) {
	f := newFakeEngine(t)
	f.respond(http.StatusCreated, taskJSON)
	ws, project, member := uuid.New(), uuid.New(), uuid.New()

	w := do(t, f, http.MethodPost, tasksPath(ws, project),
		`{"work_item_id": "44444444-4444-4444-4444-444444444444", "title": "Add approval endpoint", "priority": "high"}`,
		map[string]string{"X-Member-Id": member.String()})

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	got := f.lastRequest()
	if got.Method != http.MethodPost || got.Path != "/workspaces/"+ws.String()+"/projects/"+project.String()+"/tasks" {
		t.Errorf("engine got %s %s", got.Method, got.Path)
	}
	if got.Header.Get("X-Acting-Member-Id") != member.String() {
		t.Errorf("acting member not forwarded: %v", got.Header)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out["identifier"] != "DATA-1" {
		t.Errorf("response = %s", w.Body)
	}
}

// PATCH must tell "absent" (don't touch) apart from null (clear).
func TestUpdateTaskKeepsNullApartFromAbsent(t *testing.T) {
	f := newFakeEngine(t)
	f.respond(http.StatusOK, taskJSON)
	ws, project, id := uuid.New(), uuid.New(), uuid.New()
	path := tasksPath(ws, project) + "/" + id.String()

	do(t, f, http.MethodPatch, path, `{"sprint_id": null}`, nil)
	var sent map[string]json.RawMessage
	if err := json.Unmarshal([]byte(f.lastRequest().Body), &sent); err != nil {
		t.Fatal(err)
	}
	if v, ok := sent["sprint_id"]; !ok || string(v) != "null" {
		t.Errorf("null sprint_id not forwarded: %s", f.lastRequest().Body)
	}

	do(t, f, http.MethodPatch, path, `{"title": "Renamed"}`, nil)
	sent = nil
	if err := json.Unmarshal([]byte(f.lastRequest().Body), &sent); err != nil {
		t.Fatal(err)
	}
	if _, ok := sent["sprint_id"]; ok {
		t.Errorf("absent sprint_id was sent: %s", f.lastRequest().Body)
	}
}

func TestListTasksForwardsFilters(t *testing.T) {
	f := newFakeEngine(t)
	f.respond(http.StatusOK, `{"items": [], "limit": 10, "offset": 20, "has_more": false}`)
	ws, project := uuid.New(), uuid.New()

	w := do(t, f, http.MethodGet, tasksPath(ws, project)+"?status=todo&backlog=true&limit=10&offset=20", "", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	q := f.lastRequest().Query
	for _, want := range []string{"status=todo", "backlog=true", "limit=10", "offset=20"} {
		if !strings.Contains(q, want) {
			t.Errorf("query %q missing %q", q, want)
		}
	}
}

func TestDeleteReturnsNoContent(t *testing.T) {
	f := newFakeEngine(t)
	f.respond(http.StatusNoContent, ``)

	w := do(t, f, http.MethodDelete, "/api/v1/workspaces/"+uuid.NewString(), "", nil)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, body = %s", w.Code, w.Body)
	}
}

func TestEngineErrors(t *testing.T) {
	cases := []struct {
		name         string
		engineStatus int
		engineBody   string
		wantStatus   int
	}{
		{"not found passes through", http.StatusNotFound, `{"detail": "assignee not found"}`, http.StatusNotFound},
		{"conflict passes through", http.StatusConflict, `{"detail": "slug taken"}`, http.StatusConflict},
		{"validation passes through", http.StatusUnprocessableEntity, `{"detail": [{"loc": ["body","title"], "msg": "required", "type": "missing"}]}`, http.StatusUnprocessableEntity},
		{"bad service key is our problem", http.StatusUnauthorized, `{"detail": "Invalid data API key"}`, http.StatusBadGateway},
		{"engine crash", http.StatusInternalServerError, `oops`, http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeEngine(t)
			f.respond(tc.engineStatus, tc.engineBody)

			w := do(t, f, http.MethodGet, "/api/v1/workspaces/"+uuid.NewString(), "", nil)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", w.Code, tc.wantStatus, w.Body)
			}
			if tc.wantStatus == http.StatusBadGateway && strings.Contains(w.Body.String(), "API key") {
				t.Errorf("engine auth detail leaked: %s", w.Body)
			}
		})
	}
}

func TestBadInputIsRejectedBeforeEngine(t *testing.T) {
	f := newFakeEngine(t)
	cases := []struct{ name, method, path, body string }{
		{"bad path uuid", http.MethodGet, "/api/v1/workspaces/not-a-uuid", ""},
		{"bad limit", http.MethodGet, "/api/v1/workspaces?limit=ten", ""},
		{"bad json", http.MethodPost, "/api/v1/workspaces", "{"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := do(t, f, tc.method, tc.path, tc.body, nil)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body %s)", w.Code, w.Body)
			}
			if f.lastRequest().Method != "" {
				t.Errorf("engine was called: %+v", f.lastRequest())
			}
		})
	}

	w := do(t, f, http.MethodGet, "/api/v1/workspaces", "", map[string]string{"X-Member-Id": "nope"})
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad X-Member-Id: status = %d", w.Code)
	}
}
