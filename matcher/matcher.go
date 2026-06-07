package matcher

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

// MatcherType constants
const (
	MatcherWord   = "word"
	MatcherRegex  = "regex"
	MatcherStatus = "status"
	MatcherDSL    = "dsl"
)

// Matcher represents a condition to check against HTTP response data.
type Matcher struct {
	Type      string   `yaml:"type"`
	Condition string   `yaml:"condition,omitempty"`
	Part      string   `yaml:"part,omitempty"`
	Negative  bool     `yaml:"negative,omitempty"`
	Internal  bool     `yaml:"internal,omitempty"`
	Words     []string `yaml:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Status    []int    `yaml:"status,omitempty"`
	DSL       []string `yaml:"dsl,omitempty"`

	RegexCompiled []*regexp.Regexp
}

// UnmarshalYAML implements custom YAML unmarshaling for Matcher.
// Nuclei templates commonly write scalar values where slices are expected,
// e.g. `status: 200` instead of `status: [200]`.
// This method normalizes both forms into the slice fields.
func (m *Matcher) UnmarshalYAML(value *yaml.Node) error {
	type rawMatcher struct {
		Type      string      `yaml:"type"`
		Condition string      `yaml:"condition,omitempty"`
		Part      string      `yaml:"part,omitempty"`
		Negative  bool        `yaml:"negative,omitempty"`
		Internal  bool        `yaml:"internal,omitempty"`
		Words     interface{} `yaml:"words,omitempty"`
		Regex     interface{} `yaml:"regex,omitempty"`
		Status    interface{} `yaml:"status,omitempty"`
		DSL       interface{} `yaml:"dsl,omitempty"`
	}
	var raw rawMatcher
	if err := value.Decode(&raw); err != nil {
		return err
	}
	m.Type = raw.Type
	m.Condition = raw.Condition
	m.Part = raw.Part
	m.Negative = raw.Negative
	m.Internal = raw.Internal
	m.Words = ifaceToStringSlice(raw.Words)
	m.Regex = ifaceToStringSlice(raw.Regex)
	m.Status = ifaceToIntSlice(raw.Status)
	m.DSL = ifaceToStringSlice(raw.DSL)
	return nil
}

// ifaceToStringSlice converts a YAML-decoded interface{} to []string.
// Handles scalar string, []interface{}, and []string forms.
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

// ifaceToIntSlice converts a YAML-decoded interface{} to []int.
// Handles scalar int/int64/float64 and []interface{} forms.
func ifaceToIntSlice(v interface{}) []int {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case int:
		return []int{val}
	case int64:
		return []int{int(val)}
	case float64:
		return []int{int(val)}
	case []interface{}:
		result := make([]int, 0, len(val))
		for _, item := range val {
			switch n := item.(type) {
			case int:
				result = append(result, n)
			case int64:
				result = append(result, int(n))
			case float64:
				result = append(result, int(n))
			default:
				result = append(result, 0)
			}
		}
		if len(result) == 0 {
			return nil
		}
		return result
	case []int:
		if len(val) == 0 {
			return nil
		}
		return val
	default:
		return nil
	}
}

// Compile compiles regex patterns in the matcher.
func (m *Matcher) Compile() error {
	for _, pattern := range m.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		m.RegexCompiled = append(m.RegexCompiled, re)
	}
	return nil
}