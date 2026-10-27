// Package dataengine is the typed client for the flwn data engine's business API.
//
// To pick up a new contract, copy the engine's docs/postman/flwn-business.openapi.json
// (or GET /openapi/business.json) over api/dataengine/business.openapi.json and run
// `go generate ./...`.
package dataengine

//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../../../api/dataengine/business.openapi.json
