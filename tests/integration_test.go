//go:build integration

// Runs the full business flow through our HTTP API against a real data engine:
// user → workspace → members → team → project → work item → tasks → sprint.
//
//	DATA_API_KEY=<engine key> go test -tags integration ./tests/ -run Integration -v
package tests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
	"github.com/Hesham127/flwnBackend/internal/server"
)

type obj = map[string]any

type api struct {
	t   *testing.T
	url string
}

// call sends a request to our backend as actor (uuid.Nil = no actor) and fails unless the
// status is want. It returns the decoded JSON body, if any.
func (a api) call(method, path string, body any, actor uuid.UUID, want int) obj {
	a.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, a.url+"/api/v1"+path, r)
	req.Header.Set("Content-Type", "application/json")
	if actor != uuid.Nil {
		req.Header.Set("X-Member-Id", actor.String())
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != want {
		a.t.Fatalf("%s %s: status %d, want %d: %s", method, path, res.StatusCode, want, raw)
	}
	out := obj{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			a.t.Fatalf("%s %s: bad JSON %s", method, path, raw)
		}
	}
	return out
}

func id(o obj) string { return o["id"].(string) }

func ids(page obj) []string {
	var out []string
	for _, it := range page["items"].([]any) {
		out = append(out, it.(obj)["id"].(string))
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func TestIntegrationFullFlow(t *testing.T) {
	key := os.Getenv("DATA_API_KEY")
	if key == "" {
		t.Skip("DATA_API_KEY not set")
	}
	engineURL := os.Getenv("DATA_ENGINE_URL")
	if engineURL == "" {
		engineURL = "http://127.0.0.1:8002"
	}
	engine, err := dataengine.New(engineURL, key)
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	srv := httptest.NewServer(server.NewRouter(engine))
	t.Cleanup(srv.Close) // registered first, so it runs after the data cleanups below
	a := api{t: t, url: srv.URL}

	s := strings.Split(uuid.NewString(), "-")[0]
	ownerEmail := "owner-" + s + "@example.com"

	// --- Users ---------------------------------------------------------------
	t.Log("users")
	user := a.call("POST", "/users", obj{"email": ownerEmail, "name": "Sara Ali"}, uuid.Nil, 201)
	t.Cleanup(func() { a.call("DELETE", "/users/"+id(user), nil, uuid.Nil, 204) })
	found := a.call("GET", "/users?email="+ownerEmail, nil, uuid.Nil, 200)
	if !contains(ids(found), id(user)) {
		t.Errorf("user not found by email: %v", found)
	}
	a.call("PATCH", "/users/"+id(user), obj{"name": "Sara A."}, uuid.Nil, 200)
	a.call("POST", "/users", obj{"email": ownerEmail, "name": "Dup"}, uuid.Nil, 409)

	// --- Workspace (organization) ------------------------------------------
	t.Log("workspace")
	ws := a.call("POST", "/workspaces", obj{"name": "Acme " + s, "slug": "acme-" + s, "description": "Acme product team"}, uuid.Nil, 201)
	t.Cleanup(func() { a.call("DELETE", "/workspaces/"+id(ws), nil, uuid.Nil, 204) })
	a.call("POST", "/workspaces", obj{"name": "Other", "slug": "acme-" + s}, uuid.Nil, 409)
	a.call("PATCH", "/workspaces/"+id(ws), obj{"description": nil}, uuid.Nil, 200)
	wsPath := "/workspaces/" + id(ws)

	// --- Members -------------------------------------------------------------
	t.Log("members")
	owner := a.call("POST", wsPath+"/members", obj{"type": "HUMAN", "role": "owner", "name": "Sara Ali", "email": ownerEmail}, uuid.Nil, 201)
	if owner["user_id"] != id(user) {
		t.Errorf("owner should reuse the existing user: user_id=%v, want %s", owner["user_id"], id(user))
	}
	ownerID := uuid.MustParse(id(owner))
	dev := a.call("POST", wsPath+"/members", obj{"type": "HUMAN", "role": "member", "name": "Omar Dev", "email": "dev-" + s + "@example.com"}, ownerID, 201)
	if dev["user_id"] == nil {
		t.Error("dev member should get a freshly created user")
	} else {
		t.Cleanup(func() { a.call("DELETE", "/users/"+dev["user_id"].(string), nil, uuid.Nil, 204) })
	}
	bot := a.call("POST", wsPath+"/members", obj{"type": "AI", "name": "Atom", "agent_kind": "atom"}, ownerID, 201)
	a.call("POST", wsPath+"/members", obj{"type": "HUMAN", "name": "Sara again", "email": ownerEmail}, ownerID, 409)
	if got := ids(a.call("GET", wsPath+"/members", nil, ownerID, 200)); len(got) != 3 {
		t.Errorf("members = %d, want 3", len(got))
	}
	a.call("PATCH", wsPath+"/members/"+id(dev), obj{"role": "admin"}, ownerID, 200)
	a.call("GET", wsPath+"/members/"+uuid.NewString(), nil, ownerID, 404)

	// --- Team ----------------------------------------------------------------
	t.Log("team")
	team := a.call("POST", wsPath+"/teams", obj{"key": "core", "name": "Core", "visibility": "private"}, ownerID, 201)
	a.call("PUT", wsPath+"/teams/"+id(team)+"/members", obj{"member_ids": []string{id(owner), id(dev)}}, ownerID, 200)
	// The engine answers 422 with a string detail here, not the 404 the guide implies.
	a.call("PUT", wsPath+"/teams/"+id(team)+"/members", obj{"member_ids": []string{uuid.NewString()}}, ownerID, 422)
	a.call("PATCH", wsPath+"/teams/"+id(team), obj{"name": "Core Platform"}, ownerID, 200)
	if !contains(ids(a.call("GET", wsPath+"/teams", nil, ownerID, 200)), id(team)) {
		t.Error("team missing from list")
	}

	// --- Project ---------------------------------------------------------------
	t.Log("project")
	proj := a.call("POST", wsPath+"/projects", obj{"key": "DATA", "name": "Data Engine", "status": "planned", "team_id": id(team), "lead_id": id(owner)}, ownerID, 201)
	projPath := wsPath + "/projects/" + id(proj)
	a.call("POST", wsPath+"/projects", obj{"key": "bad key", "name": "x"}, ownerID, 422)
	if !contains(ids(a.call("GET", wsPath+"/members/"+id(dev)+"/projects", nil, ownerID, 200)), id(proj)) {
		t.Error("dev should see the project through the team")
	}

	// --- Work item ---------------------------------------------------------------
	t.Log("work item")
	wi := a.call("POST", projPath+"/work-items", obj{"title": "Atom approvals", "type": "FEATURE", "priority": "high", "status": "todo"}, ownerID, 201)
	a.call("PATCH", projPath+"/work-items/"+id(wi), obj{"status": "in_progress"}, ownerID, 200)

	// --- Tasks -------------------------------------------------------------------
	t.Log("tasks")
	task1 := a.call("POST", projPath+"/tasks", obj{"work_item_id": id(wi), "title": "Add approval endpoint", "priority": "high", "status": "todo", "estimate": 3, "assignee_id": id(dev)}, ownerID, 201)
	task2 := a.call("POST", projPath+"/tasks", obj{"work_item_id": id(wi), "title": "Write tests", "assignee_id": id(bot)}, ownerID, 201)
	if task1["identifier"] != "DATA-1" || task2["identifier"] != "DATA-2" {
		t.Errorf("identifiers = %v, %v; want DATA-1, DATA-2", task1["identifier"], task2["identifier"])
	}
	if task1["created_by"] != id(owner) {
		t.Errorf("created_by = %v, want acting member %s", task1["created_by"], id(owner))
	}
	a.call("POST", projPath+"/tasks", obj{"work_item_id": id(wi), "title": "x", "assignee_id": uuid.NewString()}, ownerID, 404)
	// A missing required UUID decodes to the zero UUID, so the engine reports "not found", not 422.
	a.call("POST", projPath+"/tasks", obj{"title": "no work item"}, ownerID, 404)
	if got := a.call("GET", wsPath+"/tasks/by-key/DATA-1", nil, ownerID, 200); id(got) != id(task1) {
		t.Errorf("by-key returned %s", id(got))
	}
	if got := ids(a.call("GET", wsPath+"/members/"+id(dev)+"/tasks", nil, ownerID, 200)); len(got) != 1 || got[0] != id(task1) {
		t.Errorf("dev tasks = %v", got)
	}
	if got := ids(a.call("GET", projPath+"/tasks?assignee_id="+id(bot), nil, ownerID, 200)); len(got) != 1 || got[0] != id(task2) {
		t.Errorf("filter by assignee = %v", got)
	}

	// --- Sprint ------------------------------------------------------------------
	t.Log("sprint")
	sp := a.call("POST", projPath+"/sprints", obj{"name": "Sprint 1", "goal": "Ship approvals", "start_date": "2026-11-01", "end_date": "2026-11-14"}, ownerID, 201)
	moved := a.call("PATCH", projPath+"/tasks/"+id(task1), obj{"sprint_id": id(sp), "status": "in_progress"}, ownerID, 200)
	if moved["sprint_id"] != id(sp) {
		t.Errorf("sprint_id = %v", moved["sprint_id"])
	}
	if got := ids(a.call("GET", projPath+"/tasks?sprint_id="+id(sp), nil, ownerID, 200)); len(got) != 1 {
		t.Errorf("sprint tasks = %v", got)
	}
	if got := ids(a.call("GET", projPath+"/tasks?backlog=true", nil, ownerID, 200)); len(got) != 1 || got[0] != id(task2) {
		t.Errorf("backlog = %v", got)
	}
	// Omitting sprint_id must leave it alone; sending null must clear it.
	if got := a.call("PATCH", projPath+"/tasks/"+id(task1), obj{"title": "Add approval API"}, ownerID, 200); got["sprint_id"] != id(sp) {
		t.Errorf("absent sprint_id changed the sprint: %v", got["sprint_id"])
	}
	if got := a.call("PATCH", projPath+"/tasks/"+id(task1), obj{"sprint_id": nil}, ownerID, 200); got["sprint_id"] != nil {
		t.Errorf("null sprint_id did not clear: %v", got["sprint_id"])
	}
	a.call("PATCH", projPath+"/tasks/"+id(task1), obj{"sprint_id": id(sp)}, ownerID, 200)
	a.call("DELETE", projPath+"/sprints/"+id(sp), nil, ownerID, 204)
	if got := a.call("GET", projPath+"/tasks/"+id(task1), nil, ownerID, 200); got["sprint_id"] != nil {
		t.Errorf("deleting the sprint should send the task to backlog: %v", got["sprint_id"])
	}

	// --- Known engine exception: inactive members can't be assigned ---------------
	a.call("PATCH", wsPath+"/members/"+id(dev), obj{"status": "suspended"}, ownerID, 200)
	a.call("PATCH", projPath+"/tasks/"+id(task2), obj{"assignee_id": id(dev)}, ownerID, 404)

	// --- Teardown order checks ----------------------------------------------------
	t.Log("deletes")
	a.call("DELETE", projPath+"/tasks/"+id(task2), nil, ownerID, 204)
	a.call("GET", projPath+"/tasks/"+id(task2), nil, ownerID, 404)
	a.call("DELETE", projPath+"/tasks/"+id(task1), nil, ownerID, 204)
	a.call("DELETE", projPath+"/work-items/"+id(wi), nil, ownerID, 204)
	a.call("DELETE", projPath, nil, ownerID, 204)
	a.call("DELETE", wsPath+"/teams/"+id(team), nil, ownerID, 204)
	a.call("DELETE", wsPath+"/members/"+id(bot), nil, ownerID, 204)
}
