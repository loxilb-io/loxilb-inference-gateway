/*
 * Copyright (c) 2026 NetLOX Inc
 * SPDX-License-Identifier: Apache-2.0
 */

package guard

import (
	"errors"
	"testing"
	"time"
)

type fakeArgs struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

func mustBind(t *testing.T, tool, target string, args any) Binding {
	t.Helper()
	b, err := BindArgs(tool, target, args)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// T4: happy path — issue then redeem once with the identical binding.
func TestConfirmRedeemHappyPath(t *testing.T) {
	c := NewConfirmer(0)
	b := mustBind(t, "lb_delete", "t1", fakeArgs{Name: "a", Port: 80})
	tok, err := c.Issue(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 32 {
		t.Fatalf("token %q not 16 random bytes hex", tok)
	}
	if err := c.Redeem(tok, mustBind(t, "lb_delete", "t1", fakeArgs{Name: "a", Port: 80})); err != nil {
		t.Fatalf("redeem with identical binding: %v", err)
	}
}

// T4: swapped args, tool, or target must be rejected — and burn the token.
func TestConfirmRejectsSwappedBinding(t *testing.T) {
	cases := []struct {
		name         string
		tool, target string
		args         fakeArgs
	}{
		{"args swapped", "lb_delete", "t1", fakeArgs{Name: "b", Port: 80}},
		{"port swapped", "lb_delete", "t1", fakeArgs{Name: "a", Port: 81}},
		{"tool swapped", "fw_delete", "t1", fakeArgs{Name: "a", Port: 80}},
		{"target swapped", "lb_delete", "t2", fakeArgs{Name: "a", Port: 80}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewConfirmer(0)
			tok, err := c.Issue(mustBind(t, "lb_delete", "t1", fakeArgs{Name: "a", Port: 80}))
			if err != nil {
				t.Fatal(err)
			}
			err = c.Redeem(tok, mustBind(t, tc.tool, tc.target, tc.args))
			if !errors.Is(err, ErrConfirmMismatch) {
				t.Fatalf("want ErrConfirmMismatch, got %v", err)
			}
			// Mismatch burns the token: the original binding no longer redeems.
			err = c.Redeem(tok, mustBind(t, "lb_delete", "t1", fakeArgs{Name: "a", Port: 80}))
			if !errors.Is(err, ErrConfirmUnknown) {
				t.Fatalf("token not burned after mismatch: %v", err)
			}
		})
	}
}

// T4: a redeemed token must not redeem again (single-use).
func TestConfirmSingleUse(t *testing.T) {
	c := NewConfirmer(0)
	b := mustBind(t, "lb_delete", "t1", fakeArgs{Name: "a", Port: 80})
	tok, _ := c.Issue(b)
	if err := c.Redeem(tok, b); err != nil {
		t.Fatal(err)
	}
	if err := c.Redeem(tok, b); !errors.Is(err, ErrConfirmUnknown) {
		t.Fatalf("second redeem: want ErrConfirmUnknown, got %v", err)
	}
}

// T4: tokens expire after the TTL.
func TestConfirmTTLExpiry(t *testing.T) {
	c := NewConfirmer(0)
	now := time.Now()
	c.SetClock(func() time.Time { return now })
	b := mustBind(t, "lb_delete", "t1", fakeArgs{Name: "a", Port: 80})
	tok, _ := c.Issue(b)

	now = now.Add(DefaultConfirmTTL - time.Second)
	if err := c.Redeem(tok, b); err != nil {
		t.Fatalf("redeem within TTL: %v", err)
	}

	tok, _ = c.Issue(b)
	now = now.Add(DefaultConfirmTTL + time.Second)
	if err := c.Redeem(tok, b); !errors.Is(err, ErrConfirmUnknown) {
		t.Fatalf("redeem after TTL: want ErrConfirmUnknown, got %v", err)
	}
	if c.Pending() != 0 {
		t.Fatalf("expired token not swept: %d pending", c.Pending())
	}
}

// Unknown or garbage tokens never redeem.
func TestConfirmUnknownToken(t *testing.T) {
	c := NewConfirmer(0)
	b := mustBind(t, "lb_delete", "t1", fakeArgs{})
	if err := c.Redeem("deadbeefdeadbeefdeadbeefdeadbeef", b); !errors.Is(err, ErrConfirmUnknown) {
		t.Fatalf("want ErrConfirmUnknown, got %v", err)
	}
}

func TestRedactDeep(t *testing.T) {
	in := map[string]any{
		"password": "hunter2",
		"nested": map[string]any{
			"apiKey": "sk-123",
			"list":   []any{map[string]any{"token": "abc", "ok": "keep"}},
		},
		"normal": "keep",
	}
	out := RedactDeep(in).(map[string]any)
	if out["password"] != "[REDACTED]" {
		t.Error("top-level password not masked")
	}
	nested := out["nested"].(map[string]any)
	if nested["apiKey"] != "[REDACTED]" {
		t.Error("nested apiKey not masked")
	}
	item := nested["list"].([]any)[0].(map[string]any)
	if item["token"] != "[REDACTED]" || item["ok"] != "keep" {
		t.Errorf("list item masking wrong: %v", item)
	}
	if out["normal"] != "keep" {
		t.Error("normal field damaged")
	}
}
