package template

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/kN6jq/nuclei-sdk/extractor"
	"github.com/kN6jq/nuclei-sdk/http"
	"github.com/kN6jq/nuclei-sdk/matcher"
	"github.com/kN6jq/nuclei-sdk/variables"
)

// Info holds template metadata.
type Info struct {
	Name           string            `yaml:"name"`
	Author         string            `yaml:"author,omitempty"`
	Severity       string            `yaml:"severity,omitempty"`
	Description    string            `yaml:"description,omitempty"`
	Tags           string            `yaml:"tags,omitempty"`
	Reference      []string          `yaml:"reference,omitempty"`
	Metadata       map[string]string `yaml:"metadata,omitempty"`
	Classification *Classification   `yaml:"classification,omitempty"`
}

// Classification holds CVE/CVSS metadata.
type Classification struct {
	CWEID       string  `yaml:"cwe-id,omitempty"`
	CVSSMetrics string  `yaml:"cvss-metrics,omitempty"`
	CVSSScore   float64 `yaml:"cvss-score,omitempty"`
	CPE         string  `yaml:"cpe,omitempty"`
}

// Template represents a nuclei-compatible HTTP template.
type Template struct {
	Id        string            `yaml:"id"`
	Info      Info              `yaml:"info"`
	Variables map[string]string `yaml:"variables,omitempty"`
	Flow      string            `yaml:"flow,omitempty"`
	HTTP      []*Request        `yaml:"http,omitempty"`

	randStr    string
	compiled   bool
	flowTree   *flowNode
	respData   *http.ResponseData
	allResp    map[int]*http.ResponseData
	dynValues  map[string][]string
}

// Request represents a single http request block in a nuclei template.
type Request struct {
	// Structured mode
	Method  string            `yaml:"method,omitempty"`
	Path    []string          `yaml:"path,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty"`

	// Raw mode
	Raw []string `yaml:"raw,omitempty"`

	// Options
	SelfContained    bool `yaml:"self-contained,omitempty"`
	HostRedirects    bool `yaml:"host-redirects,omitempty"`
	MaxRedirects     int  `yaml:"max-redirects,omitempty"`
	StopAtFirstMatch bool `yaml:"stop-at-first-match,omitempty"`
	CookieReuse      bool `yaml:"cookie-reuse,omitempty"`

	// Operators
	MatchersCondition string            `yaml:"matchers-condition,omitempty"`
	Matchers          []*matcher.Matcher `yaml:"matchers,omitempty"`
	Extractors        []*extractor.Extractor `yaml:"extractors,omitempty"`
}

// Result holds the execution result of a template against a target.
type Result struct {
	Matched       bool
	TemplateID    string
	TemplateName  string
	Severity      string
	Extracts      map[string][]string
	DynamicValues map[string][]string
	PayloadValues map[string]string
	Data          map[string]interface{}
}

// Parse unmarshals YAML data into a Template.
func Parse(data []byte) (*Template, error) {
	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("yaml unmarshal: %w", err)
	}
	if tmpl.Id == "" {
		return nil, fmt.Errorf("template has no id")
	}
	return &tmpl, nil
}

// Compile prepares the template for execution.
// Compiles regex matchers, generates random string, parses flow expressions.
func (t *Template) Compile() error {
	if t.compiled {
		return nil
	}

	t.randStr = randString(8)

	// Compile matchers and extractors
	for _, req := range t.HTTP {
		for _, m := range req.Matchers {
			if err := m.Compile(); err != nil {
				return fmt.Errorf("matcher compile error in %s: %w", t.Id, err)
			}
		}
		for _, e := range req.Extractors {
			if err := e.Compile(); err != nil {
				return fmt.Errorf("extractor compile error in %s: %w", t.Id, err)
			}
		}
	}

	// Parse flow expression
	if t.Flow != "" {
		tree, err := parseFlow(t.Flow)
		if err != nil {
			return fmt.Errorf("flow parse error in %s: %w", t.Id, err)
		}
		t.flowTree = tree
	}

	t.compiled = true
	return nil
}

func randString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// Execute runs the template against a target URL.
func (t *Template) Execute(targetURL string) (*Result, error) {
	return t.ExecuteWithClient(targetURL, nil)
}

// ExecuteWithClient runs the template with an optional custom HTTP client.
func (t *Template) ExecuteWithClient(targetURL string, _ interface{}) (*Result, error) {
	if !t.compiled {
		if err := t.Compile(); err != nil {
			return nil, err
		}
	}

	targetURL = resolveTargetURL(targetURL)
	vars := variables.BuildVariableContext(targetURL, t.Variables, t.randStr)

	// Flow-based execution
	if t.flowTree != nil {
		result, err := evaluateFlow(t.flowTree, t.HTTP, targetURL, vars)
		if err != nil {
			return nil, err
		}
		t.populateResultMeta(result)
		return result, nil
	}

	// Default sequential execution: try each request block
	for _, req := range t.HTTP {
		result, err := executeRequestBlock(req, targetURL, vars)
		if err != nil {
			continue
		}
		if result.Matched {
			t.populateResultMeta(result)
			return result, nil
		}
	}

	return &Result{
		Matched:      false,
		TemplateID:   t.Id,
		TemplateName: t.Info.Name,
		Severity:     t.Info.Severity,
	}, nil
}

func (t *Template) populateResultMeta(r *Result) {
	r.TemplateID = t.Id
	r.TemplateName = t.Info.Name
	r.Severity = t.Info.Severity
}