// Package mail sends account emails. DevMailer prints links to stdout for local development;
// a provider-backed Mailer replaces it in production.
package mail

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type DevMailer struct{ BaseURL string }

func (m DevMailer) link(path, token string) string {
	return strings.TrimRight(m.BaseURL, "/") + path + "?token=" + url.QueryEscape(token)
}

func (m DevMailer) out(to, subject, body string) error {
	// Written to stdout only, not the request log, and only in development.
	_, err := fmt.Fprintf(os.Stdout, "[dev-mail] to=%s subject=%q\n%s\n", to, subject, body)
	return err
}

func (m DevMailer) SendVerification(_ context.Context, to, token string) error {
	return m.out(to, "Verify your email", m.link("/verify-email", token))
}

func (m DevMailer) SendSignupOnExisting(_ context.Context, to string) error {
	return m.out(to, "Sign-up attempt", "Someone tried to create an account with this email. If it was you, sign in or reset your password.")
}

func (m DevMailer) SendPasswordReset(_ context.Context, to, token string) error {
	return m.out(to, "Reset your password", m.link("/reset-password", token))
}

func (m DevMailer) SendEmailChange(_ context.Context, to, token string) error {
	return m.out(to, "Confirm your new email", m.link("/confirm-email", token))
}

func (m DevMailer) SendEmailChangedNotice(_ context.Context, to string) error {
	return m.out(to, "Your email was changed", "The email on your Flwn account was changed. If this wasn't you, contact support.")
}
