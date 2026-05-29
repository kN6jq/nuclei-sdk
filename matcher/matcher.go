package matcher

import (
	"regexp"
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