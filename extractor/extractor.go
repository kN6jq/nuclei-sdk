package extractor

import (
	"regexp"
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