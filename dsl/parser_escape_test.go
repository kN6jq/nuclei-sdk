package dsl

import "testing"

func TestParseStringEscapes(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want string
	}{
		{"double quote", `"\"feature\":\"magictext\""`, `"feature":"magictext"`},
		{"single quote", `'a\'b'`, `a'b`},
		{"backslash", `"c:\\path"`, `c:\path`},
		{"newline", `"a\nb"`, "a\nb"},
		{"carriage return", `"a\rb"`, "a\rb"},
		{"tab", `"a\tb"`, "a\tb"},
		{"unknown escape", `"a\qb"`, `a\qb`},
		{"double quote in single-quoted string", `'say "hi"'`, `say "hi"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EvaluateDSL(tc.expr, map[string]interface{}{})
			if err != nil {
				t.Fatalf("parse %q: %v", tc.expr, err)
			}
			s, _ := got.(string)
			if s != tc.want {
				t.Fatalf("got %q, want %q", s, tc.want)
			}
		})
	}
}

func TestEscapedNeedleDoesNotMatchBackslashOnly(t *testing.T) {
	expr := `contains(body, "\"feature\":\"magictext\"")`
	if EvaluateDSLBool(expr, map[string]interface{}{"body": `a\b`}) {
		t.Fatal("body with backslash but without magictext must not match")
	}
	if !EvaluateDSLBool(expr, map[string]interface{}{"body": `"feature":"magictext"`}) {
		t.Fatal("body with real magictext evidence must match")
	}
}
