// Package nuclei provides a lightweight, standalone SDK for executing nuclei-compatible
// HTTP vulnerability templates.
//
// This is a trimmed version of nuclei that only supports HTTP-based templates.
// It provides template parsing, compilation, and execution against target URLs.
//
// Basic usage:
//
//	tmpl, _ := nuclei.Parse(data)
//	tmpl.Compile()
//	result, _ := tmpl.Execute("http://192.168.1.1:8080")
//	if result.Matched { ... }
//
// Loading templates from a directory:
//
//	templates, _ := nuclei.LoadFromDir("./nuclei-templates")
//	for _, tmpl := range templates {
//	    result, _ := tmpl.Execute("http://example.com")
//	}
//
// The SDK exports types and functions re-exported from internal packages for
// backward compatibility.
package nuclei