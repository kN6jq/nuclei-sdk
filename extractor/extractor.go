package extractor

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Extractor represents a data extractor from HTTP response.
type Extractor struct {
	Type           string   `yaml:"type"`                      // regex|kval|dsl|json
	Part           string   `yaml:"part,omitempty"`             // body|header|all
	Name           string   `yaml:"name,omitempty"`             // name for dynamic values
	Group          int      `yaml:"group,omitempty"`            // regex capture group
	Regex          []string `yaml:"regex,omitempty"`
	KVal           []string `yaml:"kval,omitempty"`
	DSL            []string `yaml:"dsl,omitempty"`
	JSON           []string `yaml:"json,omitempty"`
	Internal       bool     `yaml:"internal,omitempty"`         // pass to next request, don't report
	CaseInsensitive bool    `yaml:"case-insensitive,omitempty"`

	RegexCompiled []*regexp.Regexp
}

// UnmarshalYAML implements custom YAML unmarshaling for Extractor.
// Nuclei templates commonly write scalar values where slices are expected,
// e.g. `regex: "pattern"` instead of `regex: ["pattern"]`.
func (e *Extractor) UnmarshalYAML(value *yaml.Node) error {
	type rawExtractor struct {
		Type            string      `yaml:"type"`
		Part            string      `yaml:"part,omitempty"`
		Name            string      `yaml:"name,omitempty"`
		Group           int         `yaml:"group,omitempty"`
		Regex           interface{} `yaml:"regex,omitempty"`
		KVal            interface{} `yaml:"kval,omitempty"`
		DSL             interface{} `yaml:"dsl,omitempty"`
		JSON            interface{} `yaml:"json,omitempty"`
		Internal        bool        `yaml:"internal,omitempty"`
		CaseInsensitive bool        `yaml:"case-insensitive,omitempty"`
	}
	var raw rawExtractor
	if err := value.Decode(&raw); err != nil {
		return err
	}
	e.Type = raw.Type
	e.Part = raw.Part
	e.Name = raw.Name
	e.Group = raw.Group
	e.Regex = ifaceToStringSlice(raw.Regex)
	e.KVal = ifaceToStringSlice(raw.KVal)
	e.DSL = ifaceToStringSlice(raw.DSL)
	e.JSON = ifaceToStringSlice(raw.JSON)
	e.Internal = raw.Internal
	e.CaseInsensitive = raw.CaseInsensitive
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

// Compile compiles regex patterns in the extractor.
func (e *Extractor) Compile() error {
	for _, pattern := range e.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		e.RegexCompiled = append(e.RegexCompiled, re)
	}
	return nil
}