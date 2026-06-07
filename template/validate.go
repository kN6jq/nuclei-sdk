package template

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kN6jq/nuclei-sdk/extractor"
	"github.com/kN6jq/nuclei-sdk/matcher"
)

// ValidationResult holds the result of template validation.
type ValidationResult struct {
	Valid    bool     // Whether the template passed all checks
	Errors   []string // Hard errors that must be fixed
	Warnings []string // Soft warnings that are not fatal
}

// Valid matcher types
var validMatcherTypes = map[string]bool{
	"word": true, "regex": true, "status": true, "dsl": true,
}

// Valid extractor types
var validExtractorTypes = map[string]bool{
	"regex": true, "kval": true, "dsl": true, "json": true,
}

// Valid severity levels
var validSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

// Valid matcher parts
var validMatcherParts = map[string]bool{
	"": true, "body": true, "header": true, "all": true,
	"content_type": true, "title": true, "cookie": true,
}

// Valid extractor parts
var validExtractorParts = map[string]bool{
	"": true, "body": true, "header": true, "all": true,
}

// Template ID format: lowercase letters, digits, hyphens, underscores, dots
var reTemplateID = regexp.MustCompile(`^[a-z0-9][a-z0-9_\-\.]*$`)

// Validate performs comprehensive validation on a parsed Template.
// It checks structural correctness, field validity, and compile-time issues.
func (t *Template) Validate() *ValidationResult {
	result := &ValidationResult{Valid: true}

	// --- Template ID ---
	if t.Id == "" {
		result.addError("模板 ID 不能为空")
	} else if !reTemplateID.MatchString(t.Id) {
		result.addError("模板 ID 格式无效 '%s'，只允许小写字母、数字、连字符、下划线和点", t.Id)
	}

	// --- Info block ---
	t.validateInfo(result)

	// --- HTTP requests ---
	if len(t.HTTP) == 0 {
		result.addError("模板必须包含至少一个 http 请求块")
	}
	for i, req := range t.HTTP {
		t.validateRequest(i, req, result)
	}

	// --- Flow expression ---
	if t.Flow != "" {
		if _, err := parseFlow(t.Flow); err != nil {
			result.addError("flow 表达式语法错误: %s", err.Error())
		}
	}

	// --- Variables ---
	for k := range t.Variables {
		if strings.TrimSpace(k) == "" {
			result.addError("变量名不能为空")
		}
	}

	return result
}

func (t *Template) validateInfo(result *ValidationResult) {
	info := t.Info

	if strings.TrimSpace(info.Name) == "" {
		result.addError("info.name 不能为空")
	}

	if strings.TrimSpace(info.Author) == "" {
		result.addWarning("info.author 建议填写作者信息")
	}

	if info.Severity != "" && !validSeverities[strings.ToLower(info.Severity)] {
		result.addError("info.severity 值无效 '%s'，允许: info, low, medium, high, critical", info.Severity)
	}

	if info.Classification != nil {
		cls := info.Classification
		if cls.CVSSScore < 0 || cls.CVSSScore > 10 {
			result.addError("classification.cvss-score 必须在 0-10 之间，当前值: %.1f", cls.CVSSScore)
		}
	}
}

func (t *Template) validateRequest(idx int, req *Request, result *ValidationResult) {
	prefix := fmt.Sprintf("http[%d]", idx)

	// Must have path or raw (unless self-contained)
	if !req.SelfContained {
		if len(req.Path) == 0 && len(req.Raw) == 0 {
			result.addError("%s: 请求必须包含 path 或 raw 字段", prefix)
		}
	}

	// Cannot have both path and raw
	if len(req.Path) > 0 && len(req.Raw) > 0 {
		result.addError("%s: path 和 raw 不能同时使用", prefix)
	}

	// Validate matchers-condition
	if req.MatchersCondition != "" {
		mc := strings.ToLower(req.MatchersCondition)
		if mc != "and" && mc != "or" {
			result.addError("%s: matchers-condition 值无效 '%s'，允许: and, or", prefix, req.MatchersCondition)
		}
	}

	// Validate matchers
	for mi, m := range req.Matchers {
		validateMatcher(prefix, mi, m, result)
	}

	// Validate extractors
	for ei, e := range req.Extractors {
		validateExtractor(prefix, ei, e, result)
	}
}

func validateMatcher(prefix string, idx int, m *matcher.Matcher, result *ValidationResult) {
	mp := fmt.Sprintf("%s.matcher[%d]", prefix, idx)

	// Type is required
	if m.Type == "" {
		result.addError("%s: type 不能为空", mp)
		return
	}
	mType := strings.ToLower(m.Type)
	if !validMatcherTypes[mType] {
		result.addError("%s: 未知的 matcher type '%s'，允许: word, regex, status, dsl", mp, m.Type)
		return
	}

	// Part validation
	if m.Part != "" && !validMatcherParts[strings.ToLower(m.Part)] {
		result.addError("%s: 未知的 part '%s'，允许: body, header, all, content_type, title, cookie", mp, m.Part)
	}

	// Condition validation
	if m.Condition != "" {
		c := strings.ToLower(m.Condition)
		if c != "and" && c != "or" {
			result.addError("%s: condition 值无效 '%s'，允许: and, or", mp, m.Condition)
		}
	}

	// Type-specific field validation
	switch mType {
	case "word":
		if len(m.Words) == 0 {
			result.addError("%s: word 类型 matcher 必须包含 words 字段", mp)
		}
	case "regex":
		if len(m.Regex) == 0 {
			result.addError("%s: regex 类型 matcher 必须包含 regex 字段", mp)
		}
		for ri, pattern := range m.Regex {
			if _, err := regexp.Compile(pattern); err != nil {
				result.addError("%s: regex[%d] 编译失败: %s", mp, ri, err.Error())
			}
		}
	case "status":
		if len(m.Status) == 0 {
			result.addError("%s: status 类型 matcher 必须包含 status 字段", mp)
		}
		for _, code := range m.Status {
			if code < 100 || code > 599 {
				result.addError("%s: status code 无效: %d (必须在 100-599 之间)", mp, code)
			}
		}
	case "dsl":
		if len(m.DSL) == 0 {
			result.addError("%s: dsl 类型 matcher 必须包含 dsl 字段", mp)
		}
	}
}

func validateExtractor(prefix string, idx int, e *extractor.Extractor, result *ValidationResult) {
	ep := fmt.Sprintf("%s.extractor[%d]", prefix, idx)

	// Type is required
	if e.Type == "" {
		result.addError("%s: type 不能为空", ep)
		return
	}
	eType := strings.ToLower(e.Type)
	if !validExtractorTypes[eType] {
		result.addError("%s: 未知的 extractor type '%s'，允许: regex, kval, dsl, json", ep, e.Type)
		return
	}

	// Part validation
	if e.Part != "" && !validExtractorParts[strings.ToLower(e.Part)] {
		result.addError("%s: 未知的 part '%s'，允许: body, header, all", ep, e.Part)
	}

	// Type-specific field validation
	switch eType {
	case "regex":
		if len(e.Regex) == 0 {
			result.addError("%s: regex 类型 extractor 必须包含 regex 字段", ep)
		}
		for ri, pattern := range e.Regex {
			if _, err := regexp.Compile(pattern); err != nil {
				result.addError("%s: regex[%d] 编译失败: %s", ep, ri, err.Error())
			}
		}
		if e.Group < 0 {
			result.addError("%s: group 必须大于等于 0", ep)
		}
	case "kval":
		if len(e.KVal) == 0 {
			result.addError("%s: kval 类型 extractor 必须包含 kval 字段", ep)
		}
	case "dsl":
		if len(e.DSL) == 0 {
			result.addError("%s: dsl 类型 extractor 必须包含 dsl 字段", ep)
		}
	case "json":
		if len(e.JSON) == 0 {
			result.addError("%s: json 类型 extractor 必须包含 json 字段", ep)
		}
	}
}

// ValidateYAML validates a YAML string by parsing it and running Validate.
// This is a convenience function that combines Parse + Validate.
func ValidateYAML(data []byte) *ValidationResult {
	tmpl, err := Parse(data)
	if err != nil {
		result := &ValidationResult{Valid: false}
		result.addError("YAML 解析失败: %s", err.Error())
		return result
	}
	return tmpl.Validate()
}

func (r *ValidationResult) addError(format string, args ...interface{}) {
	r.Valid = false
	r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
}

func (r *ValidationResult) addWarning(format string, args ...interface{}) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}
