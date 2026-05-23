// Package nuclei provides a lightweight nuclei-compatible HTTP template engine.
//
// It parses and executes nuclei YAML templates for POC scanning and active
// fingerprint detection. Only HTTP-type templates are supported.
//
// Basic usage:
//
//	tmpl, _ := nuclei.Parse(yamlData)
//	tmpl.Compile()
//	result, _ := tmpl.Execute("http://192.168.1.1:8080")
//	if result.Matched { ... }
package nuclei
