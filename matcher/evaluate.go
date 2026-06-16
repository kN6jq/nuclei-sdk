package matcher

import (
	"fmt"
	"strings"

	"github.com/kN6jq/nuclei-sdk/dsl"
	"github.com/kN6jq/nuclei-sdk/http"
)

// ResponseData is an alias for http.ResponseData.
type ResponseData = http.ResponseData

// evaluateMatchers evaluates all matchers in a request against response data.
// Returns true if matched (respecting matchers-condition).
func EvaluateMatchers(matchers []*Matcher, condition string, resp *ResponseData, allResponses map[int]*ResponseData, dynamicValues map[string][]string) bool {
	if len(matchers) == 0 {
		// 无 matcher 视为匹配（对齐 nuclei 官方语义）：
		// 纯 extractor 型模板（如指纹/技术识别）提取到数据即视为命中。
		return true
	}

	if condition == "" {
		condition = "or"
	}

	results := make([]bool, len(matchers))
	for i, m := range matchers {
		if m.Internal {
			// Internal matchers are used for flow control, always evaluate but track separately
			results[i] = m.evaluate(resp, allResponses, dynamicValues)
			continue
		}
		results[i] = m.evaluate(resp, allResponses, dynamicValues)
	}

	switch condition {
	case "and":
		for _, r := range results {
			if !r {
				return false
			}
		}
		return true
	default: // "or"
		for _, r := range results {
			if r {
				return true
			}
		}
		return false
	}
}

func (m *Matcher) evaluate(resp *ResponseData, allResponses map[int]*ResponseData, dynamicValues map[string][]string) bool {
	var result bool

	switch m.Type {
	case MatcherWord:
		result = m.matchWord(resp, allResponses)
	case MatcherRegex:
		result = m.matchRegex(resp, allResponses)
	case MatcherStatus:
		result = m.matchStatus(resp, allResponses)
	case MatcherDSL:
		result = m.matchDSL(resp, allResponses, dynamicValues)
	}

	if m.Negative {
		return !result
	}
	return result
}

func (m *Matcher) matchWord(resp *ResponseData, allResponses map[int]*ResponseData) bool {
	corpuses := m.getCorpus(resp, allResponses)

	var results []bool
	for _, corpus := range corpuses {
		matched := true
		if m.Condition == "and" {
			for _, word := range m.Words {
				if !strings.Contains(corpus, word) {
					matched = false
					break
				}
			}
		} else {
			matched = false
			for _, word := range m.Words {
				if strings.Contains(corpus, word) {
					matched = true
					break
				}
			}
		}
		results = append(results, matched)
	}

	// If we got results from multiple indexed responses, use OR
	for _, r := range results {
		if r {
			return true
		}
	}
	return false
}

func (m *Matcher) matchRegex(resp *ResponseData, allResponses map[int]*ResponseData) bool {
	corpuses := m.getCorpus(resp, allResponses)

	for _, corpus := range corpuses {
		if m.Condition == "and" {
			allMatch := true
			for _, re := range m.RegexCompiled {
				if !re.MatchString(corpus) {
					allMatch = false
					break
				}
			}
			if allMatch {
				return true
			}
		} else {
			for _, re := range m.RegexCompiled {
				if re.MatchString(corpus) {
					return true
				}
			}
		}
	}
	return false
}

func (m *Matcher) matchStatus(resp *ResponseData, allResponses map[int]*ResponseData) bool {
	statuses := m.getStatuses(resp, allResponses)
	for _, s := range statuses {
		for _, expected := range m.Status {
			if s == expected {
				return true
			}
		}
	}
	return false
}

func (m *Matcher) matchDSL(resp *ResponseData, allResponses map[int]*ResponseData, dynamicValues map[string][]string) bool {
	ctx := BuildDSLContext(resp, 0, allResponses, dynamicValues)

	if m.Condition == "and" {
		for _, expr := range m.DSL {
			if !dsl.EvaluateDSLBool(expr, ctx) {
				return false
			}
		}
		return true
	}

	for _, expr := range m.DSL {
		if dsl.EvaluateDSLBool(expr, ctx) {
			return true
		}
	}
	return false
}

// getCorpus extracts the relevant response part(s) for matching.
// Returns one string per indexed response if part contains an index.
func (m *Matcher) getCorpus(resp *ResponseData, allResponses map[int]*ResponseData) []string {
	// Check if part has an index like body_1, header_2
	if idx := extractPartIndex(m.Part); idx > 0 {
		if r, ok := allResponses[idx]; ok {
			part := stripPartIndex(m.Part)
			return []string{GetPartData(part, r)}
		}
		return nil
	}

	// Current response
	return []string{GetPartData(m.Part, resp)}
}

func (m *Matcher) getStatuses(resp *ResponseData, allResponses map[int]*ResponseData) []int {
	if idx := extractPartIndex(m.Part); idx > 0 {
		if r, ok := allResponses[idx]; ok {
			return []int{r.StatusCode}
		}
		return nil
	}
	return []int{resp.StatusCode}
}

// GetPartData extracts the relevant response part as a string.
func GetPartData(part string, resp *ResponseData) string {
	switch part {
	case "body", "":
		return resp.Body
	case "header":
		return resp.Headers
	case "all":
		return resp.All
	case "content_type":
		return resp.ContentType
	case "title":
		return resp.Title
	case "cookie":
		return resp.Cookies
	case "interactsh_protocol":
		return ""
	default:
		return resp.Body
	}
}

// extractPartIndex extracts the index from parts like "body_1", "header_2".
// Returns 0 if no index found.
func extractPartIndex(part string) int {
	i := strings.LastIndex(part, "_")
	if i < 0 {
		return 0
	}
	idx := 0
	for _, c := range part[i+1:] {
		if c >= '0' && c <= '9' {
			idx = idx*10 + int(c-'0')
		} else {
			return 0
		}
	}
	return idx
}

func stripPartIndex(part string) string {
	i := strings.LastIndex(part, "_")
	if i < 0 {
		return part
	}
	// Verify suffix is all digits
	for _, c := range part[i+1:] {
		if c < '0' || c > '9' {
			return part
		}
	}
	return part[:i]
}

// BuildDSLContext creates a context map for DSL evaluation from response data.
func BuildDSLContext(resp *ResponseData, idx int, allResponses map[int]*ResponseData, dynamicValues map[string][]string) map[string]interface{} {
	ctx := map[string]interface{}{
		"status_code":  resp.StatusCode,
		"body":         resp.Body,
		"header":       resp.Headers,
		"content_type": resp.ContentType,
		"duration":     resp.Duration,
		"title":        resp.Title,
		"cookie":       resp.Cookies,
		"all":          resp.All,
	}

	// Add indexed versions for current response
	if idx > 0 {
		ctx[fmt.Sprintf("status_code_%d", idx)] = resp.StatusCode
		ctx[fmt.Sprintf("body_%d", idx)] = resp.Body
		ctx[fmt.Sprintf("header_%d", idx)] = resp.Headers
		ctx[fmt.Sprintf("content_type_%d", idx)] = resp.ContentType
		ctx[fmt.Sprintf("duration_%d", idx)] = resp.Duration
	}

	// Add all indexed responses
	for i, r := range allResponses {
		ctx[fmt.Sprintf("status_code_%d", i)] = r.StatusCode
		ctx[fmt.Sprintf("body_%d", i)] = r.Body
		ctx[fmt.Sprintf("header_%d", i)] = r.Headers
		ctx[fmt.Sprintf("content_type_%d", i)] = r.ContentType
		ctx[fmt.Sprintf("duration_%d", i)] = r.Duration
	}

	// Add dynamic values from extractors
	for k, v := range dynamicValues {
		if len(v) == 1 {
			ctx[k] = v[0]
		} else if len(v) > 1 {
			ctx[k] = v
		}
	}

	return ctx
}