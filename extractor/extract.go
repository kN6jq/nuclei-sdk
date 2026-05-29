package extractor

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kN6jq/nuclei-sdk/dsl"
	"github.com/kN6jq/nuclei-sdk/matcher"
)

// ResponseData is an alias for the shared response data type.
type ResponseData = matcher.ResponseData

// RunExtractors executes all extractors on the response data.
func RunExtractors(extractors []*Extractor, resp *ResponseData, allResponses map[int]*ResponseData, dynamicValues map[string][]string) {
	for _, ext := range extractors {
		results := ext.extract(resp, allResponses)
		if ext.Name != "" && len(results) > 0 {
			dynamicValues[ext.Name] = results
		}
	}
}

func (e *Extractor) extract(resp *ResponseData, allResponses map[int]*ResponseData) []string {
	corpus := matcher.GetPartData(e.Part, resp)
	if corpus == "" {
		corpus = resp.Body
	}

	switch e.Type {
	case "regex":
		return e.extractRegex(corpus)
	case "kval":
		return e.extractKVal(resp)
	case "dsl":
		return e.extractDSL(resp, allResponses)
	case "json":
		return e.extractJSON(corpus)
	}
	return nil
}

func (e *Extractor) extractRegex(corpus string) []string {
	var results []string
	for _, re := range e.RegexCompiled {
		matches := re.FindAllStringSubmatch(corpus, -1)
		for _, match := range matches {
			if e.Group < len(match) {
				results = append(results, match[e.Group])
			} else if len(match) > 1 {
				results = append(results, match[1:]...)
			} else {
				results = append(results, match[0])
			}
		}
	}
	return results
}

func (e *Extractor) extractKVal(resp *ResponseData) []string {
	var results []string
	for _, key := range e.KVal {
		searchKey := key
		if e.CaseInsensitive {
			searchKey = strings.ToLower(key)
		}

		// Search in headers
		for _, line := range strings.Split(resp.Headers, "\n") {
			kv := strings.SplitN(line, ":", 2)
			if len(kv) != 2 {
				continue
			}
			hdrKey := strings.TrimSpace(kv[0])
			if e.CaseInsensitive {
				hdrKey = strings.ToLower(hdrKey)
			}
			if hdrKey == searchKey {
				results = append(results, strings.TrimSpace(kv[1]))
			}
		}

		// Search in cookies
		for _, part := range strings.Split(resp.Cookies, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) != 2 {
				continue
			}
			ckKey := kv[0]
			if e.CaseInsensitive {
				ckKey = strings.ToLower(ckKey)
			}
			if ckKey == searchKey {
				results = append(results, kv[1])
			}
		}
	}
	return results
}

func (e *Extractor) extractDSL(resp *ResponseData, allResponses map[int]*ResponseData) []string {
	ctx := matcher.BuildDSLContext(resp, 0, allResponses, nil)
	var results []string
	for _, expr := range e.DSL {
		val, err := dsl.EvaluateDSL(expr, ctx)
		if err == nil && val != nil {
			results = append(results, fmt.Sprintf("%v", val))
		}
	}
	return results
}

func (e *Extractor) extractJSON(corpus string) []string {
	var data interface{}
	if err := json.Unmarshal([]byte(corpus), &data); err != nil {
		return nil
	}

	var results []string
	for _, query := range e.JSON {
		val := queryJSON(data, query)
		if val != nil {
			results = append(results, fmt.Sprintf("%v", val))
		}
	}
	return results
}

// queryJSON performs simple dot-notation JSON queries like ".id", ".data.name".
func queryJSON(data interface{}, query string) interface{} {
	query = strings.TrimPrefix(query, ".")
	parts := strings.Split(query, ".")

	current := data
	for _, part := range parts {
		if part == "" {
			continue
		}
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		case []interface{}:
			idx := 0
			for _, c := range part {
				if c >= '0' && c <= '9' {
					idx = idx*10 + int(c-'0')
				} else {
					return nil
				}
			}
			if idx < len(v) {
				current = v[idx]
			} else {
				return nil
			}
		default:
			return nil
		}
	}
	return current
}