package nuclei

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Template represents a nuclei-compatible HTTP template.
type Template struct {
	Id        string            `yaml:"id"`
	Info      Info              `yaml:"info"`
	Variables map[string]string `yaml:"variables,omitempty"`
	Flow      string            `yaml:"flow,omitempty"`
	HTTP      []*Request        `yaml:"http,omitempty"`

	randStr  string
	compiled bool
	flowTree *flowNode
}

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
			if err := m.compile(); err != nil {
				return fmt.Errorf("matcher compile error in %s: %w", t.Id, err)
			}
		}
		for _, e := range req.Extractors {
			if err := e.compile(); err != nil {
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
	vars := BuildVariableContext(targetURL, t.Variables, t.randStr)

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

// LoadFromDir loads all .yaml/.yml templates from a directory (recursive).
func LoadFromDir(dir string) ([]*Template, error) {
	var templates []*Template
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		tmpl, err := Parse(raw)
		if err != nil {
			return nil
		}
		if err := tmpl.Compile(); err != nil {
			return nil
		}
		templates = append(templates, tmpl)
		return nil
	})
	return templates, err
}

// LoadFromFS loads all .yaml/.yml templates from an fs.FS.
func LoadFromFS(fsys fs.FS, root string) ([]*Template, error) {
	var templates []*Template
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}

		raw, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil
		}

		tmpl, err := Parse(raw)
		if err != nil {
			return nil
		}
		if err := tmpl.Compile(); err != nil {
			return nil
		}
		templates = append(templates, tmpl)
		return nil
	})
	return templates, err
}

// --- Matcher compile ---

func (m *Matcher) compile() error {
	for _, pattern := range m.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("regex compile %q: %w", pattern, err)
		}
		m.regexCompiled = append(m.regexCompiled, re)
	}
	return nil
}

// --- Utility ---

func randString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}
