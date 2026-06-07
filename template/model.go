package template

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/kN6jq/nuclei-sdk/extractor"
	"github.com/kN6jq/nuclei-sdk/http"
	"github.com/kN6jq/nuclei-sdk/interactsh"
	"github.com/kN6jq/nuclei-sdk/matcher"
	"github.com/kN6jq/nuclei-sdk/variables"
)

// ExecuteOptions holds optional execution context for template execution.
type ExecuteOptions struct {
	// InteractshClient is an optional OOB client for interactsh URL generation
	// and interaction tracking. When set, {{interactsh-url}} markers in
	// template requests are replaced with real URLs.
	InteractshClient *interactsh.Client
}

// ExecutionContext holds per-execution runtime state that needs to survive
// across multiple request blocks within a single Execute call.
type ExecutionContext struct {
	// InteractshURLs tracks all interactsh URLs generated during this execution.
	InteractshURLs []string
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

// UnmarshalYAML implements custom YAML unmarshaling for Info.
// Handles scalar string form for Reference (e.g. `reference: https://...`).
func (i *Info) UnmarshalYAML(value *yaml.Node) error {
	type rawInfo struct {
		Name           string            `yaml:"name"`
		Author         string            `yaml:"author,omitempty"`
		Severity       string            `yaml:"severity,omitempty"`
		Description    string            `yaml:"description,omitempty"`
		Tags           string            `yaml:"tags,omitempty"`
		Reference      interface{}       `yaml:"reference,omitempty"`
		Metadata       map[string]string `yaml:"metadata,omitempty"`
		Classification *Classification   `yaml:"classification,omitempty"`
	}
	var raw rawInfo
	if err := value.Decode(&raw); err != nil {
		return err
	}
	i.Name = raw.Name
	i.Author = raw.Author
	i.Severity = raw.Severity
	i.Description = raw.Description
	i.Tags = raw.Tags
	i.Reference = ifaceToStringSlice(raw.Reference)
	i.Metadata = raw.Metadata
	i.Classification = raw.Classification
	return nil
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

// UnmarshalYAML implements custom YAML unmarshaling for Request.
// Handles scalar string forms for Path and Raw fields.
func (r *Request) UnmarshalYAML(value *yaml.Node) error {
	type rawRequest struct {
		Method           string                      `yaml:"method,omitempty"`
		Path             interface{}                 `yaml:"path,omitempty"`
		Headers          map[string]string           `yaml:"headers,omitempty"`
		Body             string                      `yaml:"body,omitempty"`
		Raw              interface{}                 `yaml:"raw,omitempty"`
		SelfContained    bool                        `yaml:"self-contained,omitempty"`
		HostRedirects    bool                        `yaml:"host-redirects,omitempty"`
		MaxRedirects     int                         `yaml:"max-redirects,omitempty"`
		StopAtFirstMatch bool                        `yaml:"stop-at-first-match,omitempty"`
		CookieReuse      bool                        `yaml:"cookie-reuse,omitempty"`
		MatchersCondition string                     `yaml:"matchers-condition,omitempty"`
		Matchers         []*matcher.Matcher          `yaml:"matchers,omitempty"`
		Extractors       []*extractor.Extractor      `yaml:"extractors,omitempty"`
	}
	var raw rawRequest
	if err := value.Decode(&raw); err != nil {
		return err
	}
	r.Method = raw.Method
	r.Path = ifaceToStringSlice(raw.Path)
	r.Headers = raw.Headers
	r.Body = raw.Body
	r.Raw = ifaceToStringSlice(raw.Raw)
	r.SelfContained = raw.SelfContained
	r.HostRedirects = raw.HostRedirects
	r.MaxRedirects = raw.MaxRedirects
	r.StopAtFirstMatch = raw.StopAtFirstMatch
	r.CookieReuse = raw.CookieReuse
	r.MatchersCondition = raw.MatchersCondition
	r.Matchers = raw.Matchers
	r.Extractors = raw.Extractors
	return nil
}

// ifaceToStringSlice converts a YAML-decoded interface{} to []string.
func ifaceToStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		if val == "" {
			return nil
		}
		return []string{val}
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			result = append(result, fmt.Sprintf("%v", item))
		}
		if len(result) == 0 {
			return nil
		}
		return result
	case []string:
		if len(val) == 0 {
			return nil
		}
		return val
	default:
		return []string{fmt.Sprintf("%v", v)}
	}
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
	// Request holds the formatted HTTP request string
	Request string
	// Response holds the formatted HTTP response string
	Response string
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
	return t.ExecuteWithOptions(targetURL, nil)
}

// ExecuteWithClient runs the template with an optional custom HTTP client.
func (t *Template) ExecuteWithClient(targetURL string, _ interface{}) (*Result, error) {
	return t.ExecuteWithOptions(targetURL, nil)
}

// ExecuteWithOptions runs the template with optional execution options,
// including an interactsh OOB client for blind vulnerability detection.
func (t *Template) ExecuteWithOptions(targetURL string, opts *ExecuteOptions) (*Result, error) {
	if !t.compiled {
		if err := t.Compile(); err != nil {
			return nil, err
		}
	}

	targetURL = resolveTargetURL(targetURL)

	// Prepare extra variables for interactsh
	var extraVars map[string]string
	var ec *ExecutionContext

	if opts != nil && opts.InteractshClient != nil && opts.InteractshClient.IsInitialized() {
		ec = &ExecutionContext{}

		// Check if any request uses interactsh markers
		usesInteractsh := t.usesInteractshMarkers()

		if usesInteractsh {
			// Generate interactsh URL and set in vars
			url, err := opts.InteractshClient.URL()
			if err == nil {
				extraVars = map[string]string{
					"interactsh-url": url,
				}
				ec.InteractshURLs = append(ec.InteractshURLs, url)
			}
		}
	}

	vars := variables.BuildVariableContext(targetURL, t.Variables, t.randStr, extraVars)

	// Flow-based execution
	if t.flowTree != nil {
		result, err := evaluateFlow(t.flowTree, t.HTTP, targetURL, vars, ec)
		if err != nil {
			return nil, err
		}
		t.populateResultMeta(result)

		// Track with interactsh client if URLs were generated
		if ec != nil && len(ec.InteractshURLs) > 0 && opts != nil && opts.InteractshClient != nil {
			t.trackInteractsh(opts.InteractshClient, ec.InteractshURLs, targetURL, result)
		}

		return result, nil
	}

	// Default sequential execution: try each request block
	for _, req := range t.HTTP {
		result, err := executeRequestBlock(req, targetURL, vars, ec)
		if err != nil {
			continue
		}
		if result.Matched {
			t.populateResultMeta(result)

			// Track with interactsh client if URLs were generated
			if ec != nil && len(ec.InteractshURLs) > 0 && opts != nil && opts.InteractshClient != nil {
				t.trackInteractsh(opts.InteractshClient, ec.InteractshURLs, targetURL, result)
			}

			return result, nil
		}
	}

	// Even if no HTTP match, track for OOB-only templates (blind vulnerabilities)
	if ec != nil && len(ec.InteractshURLs) > 0 && opts != nil && opts.InteractshClient != nil {
		result := &Result{
			Matched:      false,
			TemplateID:   t.Id,
			TemplateName: t.Info.Name,
			Severity:     t.Info.Severity,
		}
		t.trackInteractsh(opts.InteractshClient, ec.InteractshURLs, targetURL, result)
		return result, nil
	}

	return &Result{
		Matched:      false,
		TemplateID:   t.Id,
		TemplateName: t.Info.Name,
		Severity:     t.Info.Severity,
	}, nil
}

// usesInteractshMarkers checks if any request in the template contains interactsh URL markers.
func (t *Template) usesInteractshMarkers() bool {
	for _, req := range t.HTTP {
		for _, raw := range req.Raw {
			if interactsh.HasMarkers(raw) {
				return true
			}
		}
		for _, path := range req.Path {
			if interactsh.HasMarkers(path) {
				return true
			}
		}
		if interactsh.HasMarkers(req.Body) {
			return true
		}
		for _, v := range req.Headers {
			if interactsh.HasMarkers(v) {
				return true
			}
		}
	}
	return false
}

// trackInteractsh registers the executed template with the interactsh client
// so that incoming OOB interactions can be matched against its matchers.
func (t *Template) trackInteractsh(client *interactsh.Client, urls []string, target string, result *Result) {
	if client == nil || !client.IsInitialized() {
		return
	}

	// Collect all matchers from all request blocks
	var allMatchers []*matcher.Matcher
	var matchersCond string
	for _, req := range t.HTTP {
		allMatchers = append(allMatchers, req.Matchers...)
		if req.MatchersCondition != "" {
			matchersCond = req.MatchersCondition
		}
	}

	// Check if any matchers are interactsh-specific
	if !interactsh.HasMatchers(allMatchers) && len(allMatchers) > 0 {
		// If there are matchers but none are interactsh-specific,
		// still track for confirmation-based OOB (interaction arrival = match)
	}

	for _, url := range urls {
		entry := &interactsh.TrackedEntry{
			TemplateID:   t.Id,
			TemplateName: t.Info.Name,
			Severity:     t.Info.Severity,
			Target:       target,
			Matchers:     allMatchers,
			MatchersCond: matchersCond,
			URL:          url,
		}
		client.Track(entry)
	}
}

func (t *Template) populateResultMeta(r *Result) {
	r.TemplateID = t.Id
	r.TemplateName = t.Info.Name
	r.Severity = t.Info.Severity
}