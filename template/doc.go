// Package template provides the core Template type and execution logic for nuclei templates.
//
// A Template represents a nuclei-compatible HTTP vulnerability template.
// Parse YAML data into a Template, compile it (which prepares matchers and extractors),
// then execute it against target URLs.
//
// Example usage:
//
//	tmpl, _ := nuclei.Parse(data)
//	tmpl.Compile()
//	result, _ := tmpl.Execute("http://example.com")
//	if result.Matched { ... }
package template