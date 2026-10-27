// Package member is the member domain: a person or AI agent inside one workspace.
package member

import "github.com/Hesham127/flwnBackend/internal/platform/dataengine"

type (
	Member = dataengine.MemberOut
	Create = dataengine.MemberCreate
	Update = dataengine.MemberUpdate
	Page   = dataengine.MemberPage
)

type Type string

const (
	TypeHuman Type = "HUMAN" // needs email and name
	TypeAI    Type = "AI"    // needs agent_kind
)

type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
)

type Status string

const (
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended" // loses access at once
)
