package template

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// startMultiPathServer /login 命中关键词, / 无关 — 模板路径顺序为先 /login 后 /
func startMultiPathServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><title>Welcome</title>nginx works</html>"))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><title>Sign in - Grafana</title><h1>Grafana</h1><script>window.grafanaBootData={}</script></html>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

const grafanaTemplate = `id: grafana-detect
info:
  name: Grafana Detection
  author: test
  severity: info
  tags: grafana,tech,discovery
http:
  - method: GET
    path:
      - "{{BaseURL}}/login"
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "Grafana"
          - "grafana-app"
        condition: or
`

// TestMultiPathMatcherAnyRequest 验证多路径模板的官方语义:
// 匹配器逐请求评估, 任一请求命中即模板命中。
// 修复前仅评估最后一个请求的响应, 先命中后未命中的路径顺序永远不匹配。
func TestMultiPathMatcherAnyRequest(t *testing.T) {
	srv := startMultiPathServer(t)
	tmpl, err := Parse([]byte(grafanaTemplate))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := tmpl.Execute(srv.URL)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !res.Matched {
		t.Fatalf("multi-path template must match on the /login request")
	}
	if !strings.Contains(res.Request, "/login") {
		t.Errorf("matched request should be /login, got: %s", firstLine(res.Request))
	}
}

// TestSinglePathStillWorks 回归: 单路径模板行为不变。
func TestSinglePathStillWorks(t *testing.T) {
	srv := startMultiPathServer(t)
	raw := `id: test-single-path
info:
  name: Single Path Test
  severity: info
  tags: tech
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: body
        words:
          - "Welcome"
`
	tmpl, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := tmpl.Execute(srv.URL)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !res.Matched {
		t.Fatal("single-path template must still match")
	}
}

// TestNoMatchOnLastPathOnly 反向用例: 仅最后路径命中时同样要匹配
// (旧实现对"先未命中后命中"的顺序恰好是正确的, 该用例保证修复未破坏它)。
func TestNoMatchOnLastPathOnly(t *testing.T) {
	srv := startMultiPathServer(t)
	raw := `id: test-reverse-order
info:
  name: Reverse Order Test
  severity: info
  tags: tech
http:
  - method: GET
    path:
      - "{{BaseURL}}/nonexistent-404"
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: body
        words:
          - "Welcome"
`
	tmpl, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := tmpl.Execute(srv.URL)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !res.Matched {
		t.Fatal("template matching on the last path must still match")
	}
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
