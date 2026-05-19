package project

import (
	"errors"
	"strings"
	"testing"

	"github.com/silvance/golantern/internal/scope"
)

func TestModeValid(t *testing.T) {
	for _, m := range []Mode{ModeAssessment, ModeBugBounty, ModeCTF} {
		if !m.Valid() {
			t.Fatalf("%q should be valid", m)
		}
	}
	for _, m := range []Mode{"", "unknown", "ASSESSMENT"} {
		if Mode(m).Valid() {
			t.Fatalf("%q should not be valid", m)
		}
	}
}

func TestValidateOK(t *testing.T) {
	p := &Project{
		Name:         "Acme engagement",
		DefaultScope: scope.KindPassive,
		Mode:         ModeAssessment,
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateFailures(t *testing.T) {
	cases := []struct {
		name string
		p    Project
		want string
	}{
		{
			name: "empty name",
			p:    Project{Name: "  ", DefaultScope: scope.KindPassive, Mode: ModeAssessment},
			want: "name is required",
		},
		{
			name: "name too long",
			p:    Project{Name: strings.Repeat("x", 257), DefaultScope: scope.KindPassive, Mode: ModeAssessment},
			want: "name must be <= 256",
		},
		{
			name: "bad scope kind",
			p:    Project{Name: "ok", DefaultScope: scope.RuleKind("bogus"), Mode: ModeAssessment},
			want: "default_scope",
		},
		{
			name: "bad mode",
			p:    Project{Name: "ok", DefaultScope: scope.KindPassive, Mode: Mode("bogus")},
			want: "mode",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.p.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", c.want)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("not ErrInvalid: %v", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err, c.want)
			}
		})
	}
}
