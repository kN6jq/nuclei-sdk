// Package matcher provides response matching logic for nuclei templates.
//
// Matchers check HTTP responses against conditions defined in templates.
// Supported matcher types: word, regex, status, dsl.
//
// Matchers can be combined with conditions (and/or) and can be negated.
package matcher