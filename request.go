package nuclei

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var timeoutAnnotationRe = regexp.MustCompile(`@timeout:\s*(\d+)(ms|s|m)`)

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
	SelfContained    bool   `yaml:"self-contained,omitempty"`
	HostRedirects    bool   `yaml:"host-redirects,omitempty"`
	MaxRedirects     int    `yaml:"max-redirects,omitempty"`
	StopAtFirstMatch bool   `yaml:"stop-at-first-match,omitempty"`
	CookieReuse      bool   `yaml:"cookie-reuse,omitempty"`

	// Operators
	MatchersCondition string      `yaml:"matchers-condition,omitempty"`
	Matchers          []*Matcher  `yaml:"matchers,omitempty"`
	Extractors        []*Extractor `yaml:"extractors,omitempty"`
}

// parseRawRequest parses a raw HTTP request text into its components.
func parseRawRequest(raw, baseURL string) (method, reqPath string, headers map[string]string, body string, timeout time.Duration, err error) {
	// Extract and remove @timeout annotation
	if m := timeoutAnnotationRe.FindStringSubmatch(raw); len(m) == 3 {
		val, _ := strconv.Atoi(m[1])
		switch m[2] {
		case "ms":
			timeout = time.Duration(val) * time.Millisecond
		case "s":
			timeout = time.Duration(val) * time.Second
		case "m":
			timeout = time.Duration(val) * time.Minute
		}
		raw = timeoutAnnotationRe.ReplaceAllString(raw, "")
	}

	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 65536), 65536)

	// Skip empty lines and annotations
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "@") {
			continue
		}
		parts := strings.SplitN(trimmed, " ", 3)
		if len(parts) < 2 {
			continue
		}
		method = parts[0]
		reqPath = parts[1]
		break
	}

	headers = make(map[string]string)

	// Parse headers
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			break
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		headers[key] = val
	}

	// Remaining is body
	var bodyLines []string
	for scanner.Scan() {
		bodyLines = append(bodyLines, scanner.Text())
	}
	body = strings.Join(bodyLines, "\n")

	if method == "" {
		err = fmt.Errorf("no request line found in raw request")
	}

	return
}

// buildRawHTTPURL combines baseURL with the path from raw request.
func buildRawHTTPURL(baseURL, rawPath string) string {
	if strings.HasPrefix(rawPath, "http://") || strings.HasPrefix(rawPath, "https://") {
		return rawPath
	}
	return strings.TrimRight(baseURL, "/") + rawPath
}
