// Package variables provides variable substitution and context building for nuclei templates.
//
// Template variables are defined in YAML templates and can be substituted
// into requests using {{variable}} syntax. Variables can also use functions
// like {{md5(value)}} or {{base64(value)}}.
//
// BuildVariableContext creates a context map from a target URL and template variables.
// Substitute performs the actual replacement of {{key}} and {{func(arg)}} patterns.
package variables