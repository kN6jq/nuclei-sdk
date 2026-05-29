// Package extractor provides data extraction from HTTP responses for nuclei templates.
//
// Extractors can pull data from responses using regex, key-value pairs, JSON paths,
// or DSL expressions. Extracted data is passed to subsequent requests or returned
// in the template result.
package extractor