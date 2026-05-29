// Package dsl provides a recursive descent parser and evaluator for nuclei DSL expressions.
//
// DSL expressions support comparison operators (==, !=, >, <, >=, <=),
// logical operators (&&, ||, !), string functions, and math functions.
//
// Example expression: 'contains(body, "admin") && status_code == 200'
//
// Available functions:
//   - contains(s, substr), contains_all(s, substr1, substr2, ...), contains_any(s, substr1, ...)
//   - to_lower(s), to_upper(s), len(s)
//   - md5(s), base64(s), base64_decode(s)
//   - url_encode(s), url_decode(s), hex_encode(s)
//   - rand_text_alpha(n), rand_text_alphanumeric(n), rand_base(n)
//   - regex(pattern, text)
package dsl