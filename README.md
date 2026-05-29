# nuclei-sdk

A lightweight, standalone Go SDK for executing nuclei-compatible HTTP vulnerability templates.

## Features

- Parse and execute nuclei YAML templates
- HTTP-based vulnerability scanning
- DSL expressions for complex matching and extraction
- Flow-based request orchestration
- Variable substitution with built-in functions
- Only HTTP templates supported (trimmed from full nuclei)

## Installation

```bash
go get github.com/kN6jq/nuclei-sdk
```

## Quick Start

```go
package main

import (
    "fmt"
    "os"
    nuclei "github.com/kN6jq/nuclei-sdk/nuclei"
)

func main() {
    data, _ := os.ReadFile("template.yaml")
    tmpl, _ := nuclei.Parse(data)
    tmpl.Compile()

    result, _ := tmpl.Execute("http://example.com")
    if result.Matched {
        fmt.Printf("Vulnerability detected: %s\n", result.TemplateName)
    }
}
```

## Loading Multiple Templates

```go
package main

import (
    "fmt"
    nuclei "github.com/kN6jq/nuclei-sdk/nuclei"
)

func main() {
    templates, _ := nuclei.LoadFromDir("./nuclei-templates")
    for _, tmpl := range templates {
        result, _ := tmpl.Execute("http://example.com")
        if result.Matched {
            fmt.Printf("Matched: %s\n", result.TemplateName)
        }
    }
}
```

## Template Format

nuclei-sdk supports a subset of nuclei YAML template format:

```yaml
id: example-vulnerability
info:
  name: Example Vulnerability
  author: yourname
  severity: high

http:
  - raw:
      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        words:
          - "Welcome Admin"
        part: body
```

## API Reference

### nuclei package

Main entry point for parsing and executing templates.

```go
tmpl, err := nuclei.Parse(data)           // Parse YAML into Template
tmpl.Compile()                             // Prepare template (compile regex, etc)
result, err := tmpl.Execute(url)           // Execute against target
templates, err := nuclei.LoadFromDir(dir) // Load templates from directory
```

### Types

- `Template` - parsed template with Execute method
- `Result` - execution result with Matched, Extracts, DynamicValues
- `Matcher` - condition checker (word/regex/status/dsl)
- `Extractor` - data extractor (regex/kval/json/dsl)
- `Info` - template metadata (Name, Author, Severity, etc.)
- `ResponseData` - HTTP response data (StatusCode, Body, Headers, etc.)

### DSL Package

Evaluate DSL expressions programmatically:

```go
ctx := map[string]interface{}{
    "status_code": 200,
    "body":        "admin panel",
}
result := dsl.EvaluateDSLBool(`contains(body, "admin") && status_code == 200`, ctx)
```

Available DSL functions:
- `contains(s, substr)`, `contains_all(s, substr...)`, `contains_any(s, substr...)`
- `to_lower(s)`, `to_upper(s)`, `len(s)`
- `md5(s)`, `base64(s)`, `base64_decode(s)`
- `url_encode(s)`, `url_decode(s)`, `hex_encode(s)`
- `rand_text_alpha(n)`, `rand_text_alphanumeric(n)`, `rand_base(n)`
- `regex(pattern, text)`

### Variables Package

Build variable context and substitute template variables:

```go
vars := variables.BuildVariableContext(targetURL, templateVars, randStr)
substituted := variables.Substitute(requestRaw, vars)
```

## Examples

- `examples/basic/main.go` - Single template execution
- `examples/batch/main.go` - Execute multiple templates
- `examples/custom-client/main.go` - Custom HTTP client

Run an example:

```bash
cd examples/basic
go run main.go <template.yaml> <target-url>
```

## Package Structure

```
nuclei-sdk/
├── nuclei/      # Main package with Parse, LoadFromDir, type exports
├── http/        # HTTP client and response handling
├── template/    # Template model, compile, execute logic
├── matcher/     # Response matching (word, regex, status, dsl)
├── extractor/    # Data extraction (regex, kval, json, dsl)
├── dsl/          # DSL expression parser and evaluator
├── variables/    # Variable substitution and context building
└── examples/     # Usage examples
```

## Limitations

- Only HTTP protocol templates supported (no TCP, DNS, SSL, etc.)
- No workflows or multi-protocol orchestration
- No nuclei-cloud integration
- No output formatters (JSON, HTML, etc.)

## License

MIT