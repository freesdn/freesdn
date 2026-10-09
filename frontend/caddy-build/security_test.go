package main

import (
	"context"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

type CELSecurityRecord struct {
	Public string `json:"public"`
	Secret string `json:"-"`
}

// Exercise constant matchers (the patched calls), dynamic arguments and errors
// through Caddy's public API, using the same vendored sources as the binary.
func TestCaddyCELMatchers(t *testing.T) {
	for _, tc := range []struct {
		expression string
		want       bool
		invalid    bool
	}{
		{`path('/allowed') && method('GET')`, true, false},
		{`path('/denied') || method('POST')`, false, false},
		{`header({'X-Test': 'accepted'})`, true, false},
		{`path_regexp('^/allowed$')`, true, false},
		{`path({test.target})`, true, false},
		{`path_regexp('[')`, false, true},
		{`unknown_matcher('value')`, false, true},
	} {
		t.Run(tc.expression, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			matcher := caddyhttp.MatchExpression{Expr: tc.expression}
			err := matcher.Provision(ctx)
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid expression was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "https://example.test/allowed", nil)
			req.Header.Set("X-Test", "accepted")
			replacer := caddy.NewReplacer()
			replacer.Set("test.target", "/allowed")
			req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, replacer))
			req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{}))
			got, err := matcher.MatchWithError(req)
			if err != nil || got != tc.want {
				t.Fatalf("match=%v error=%v; want %v", got, err, tc.want)
			}
		})
	}
}

// GHSA-gcjh-h69q-9w9g: dynamic indexing must not reveal JSON-omitted fields.
// The public-field control distinguishes a fix from a broken type registration.
func TestCELJSONHiddenField(t *testing.T) {
	env, err := cel.NewEnv(
		ext.NativeTypes(reflect.TypeFor[CELSecurityRecord](), ext.ParseStructTag("json")),
		cel.Variable("record", cel.DynType),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		expression string
		hidden     bool
	}{
		{`dyn(record)["public"]`, false},
		{`dyn(record)["-"]`, true},
		{`dyn(record).Secret`, true},
	} {
		t.Run(tc.expression, func(t *testing.T) {
			ast, issues := env.Compile(tc.expression)
			if issues.Err() != nil {
				t.Fatal(issues.Err())
			}
			program, err := env.Program(ast)
			if err != nil {
				t.Fatal(err)
			}
			value, _, err := program.Eval(map[string]any{
				"record": CELSecurityRecord{Public: "visible", Secret: "test-secret"},
			})
			if tc.hidden {
				if err == nil {
					t.Fatalf("hidden field was accessible: %v", value)
				}
			} else if err != nil || value.Value() != "visible" {
				t.Fatalf("public field failed: value=%v error=%v", value, err)
			}
		})
	}
}
