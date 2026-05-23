package nuclei

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// EvaluateDSL evaluates a DSL expression against a context map.
// Returns the result as an interface{} (bool, float64, or string).
func EvaluateDSL(expr string, ctx map[string]interface{}) (interface{}, error) {
	p := newParser(strings.TrimSpace(expr), ctx)
	return p.parseExpression()
}

// EvaluateDSLBool evaluates a DSL expression and returns a boolean.
func EvaluateDSLBool(expr string, ctx map[string]interface{}) bool {
	result, err := EvaluateDSL(expr, ctx)
	if err != nil {
		return false
	}
	return toBool(result)
}

type parser struct {
	input string
	pos   int
	ctx   map[string]interface{}
}

func newParser(input string, ctx map[string]interface{}) *parser {
	return &parser{input: input, pos: 0, ctx: ctx}
}

func (p *parser) peek() rune {
	if p.pos >= len(p.input) {
		return 0
	}
	return rune(p.input[p.pos])
}

func (p *parser) advance() rune {
	if p.pos >= len(p.input) {
		return 0
	}
	ch := rune(p.input[p.pos])
	p.pos++
	return ch
}

func (p *parser) skipWhitespace() {
	for p.pos < len(p.input) && unicode.IsSpace(rune(p.input[p.pos])) {
		p.pos++
	}
}

func (p *parser) parseExpression() (interface{}, error) {
	return p.parseOr()
}

func (p *parser) parseOr() (interface{}, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		p.skipWhitespace()
		if p.match("||") {
			right, err := p.parseAnd()
			if err != nil {
				return nil, err
			}
			left = toBool(left) || toBool(right)
		} else {
			break
		}
	}
	return left, nil
}

func (p *parser) parseAnd() (interface{}, error) {
	left, err := p.parseComparison()
	if err != nil {
		return nil, err
	}
	for {
		p.skipWhitespace()
		if p.match("&&") {
			right, err := p.parseComparison()
			if err != nil {
				return nil, err
			}
			left = toBool(left) && toBool(right)
		} else {
			break
		}
	}
	return left, nil
}

func (p *parser) parseComparison() (interface{}, error) {
	p.skipWhitespace()
	// Handle ! (not) prefix
	if p.pos < len(p.input) && p.input[p.pos] == '!' && (p.pos+1 >= len(p.input) || p.input[p.pos+1] != '=') {
		p.advance()
		val, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		return !toBool(val), nil
	}

	// Handle parenthesized expression
	if p.pos < len(p.input) && p.input[p.pos] == '(' {
		p.advance()
		val, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		p.skipWhitespace()
		if p.pos < len(p.input) && p.input[p.pos] == ')' {
			p.advance()
		}
		return val, nil
	}

	left, err := p.parseValue()
	if err != nil {
		return nil, err
	}

	p.skipWhitespace()

	// Check for comparison operators
	var op string
	switch {
	case p.match("=="):
		op = "=="
	case p.match("!="):
		op = "!="
	case p.match(">="):
		op = ">="
	case p.match("<="):
		op = "<="
	case p.match(">"):
		op = ">"
	case p.match("<"):
		op = "<"
	}

	if op == "" {
		return left, nil
	}

	right, err := p.parseValue()
	if err != nil {
		return nil, err
	}

	return compare(left, op, right), nil
}

func (p *parser) parseValue() (interface{}, error) {
	p.skipWhitespace()

	// String literal
	if p.pos < len(p.input) && (p.input[p.pos] == '\'' || p.input[p.pos] == '"') {
		return p.parseString()
	}

	// Number
	if p.pos < len(p.input) && (p.input[p.pos] == '-' || (p.input[p.pos] >= '0' && p.input[p.pos] <= '9')) {
		return p.parseNumber()
	}

	// Identifier (variable or function call)
	return p.parseIdentOrFunc()
}

func (p *parser) parseString() (interface{}, error) {
	quote := p.advance()
	var sb strings.Builder
	for p.pos < len(p.input) {
		ch := p.advance()
		if ch == quote {
			return sb.String(), nil
		}
		sb.WriteRune(ch)
	}
	return sb.String(), nil
}

func (p *parser) parseNumber() (interface{}, error) {
	start := p.pos
	if p.pos < len(p.input) && p.input[p.pos] == '-' {
		p.pos++
	}
	for p.pos < len(p.input) && (p.input[p.pos] >= '0' && p.input[p.pos] <= '9' || p.input[p.pos] == '.') {
		p.pos++
	}
	numStr := p.input[start:p.pos]
	if strings.Contains(numStr, ".") {
		f, err := strconv.ParseFloat(numStr, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid number: %s", numStr)
		}
		return f, nil
	}
	i, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid number: %s", numStr)
	}
	return float64(i), nil
}

func (p *parser) parseIdentOrFunc() (interface{}, error) {
	ident := p.readIdent()
	if ident == "" {
		return nil, fmt.Errorf("expected identifier at pos %d", p.pos)
	}

	p.skipWhitespace()

	// Function call
	if p.pos < len(p.input) && p.input[p.pos] == '(' {
		p.advance()
		args, err := p.parseArgs()
		if err != nil {
			return nil, err
		}
		return callDSLFunc(ident, args)
	}

	// Variable lookup
	if val, ok := p.ctx[ident]; ok {
		return val, nil
	}
	return nil, nil
}

func (p *parser) readIdent() string {
	start := p.pos
	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' {
			p.pos++
		} else {
			break
		}
	}
	return p.input[start:p.pos]
}

func (p *parser) parseArgs() ([]interface{}, error) {
	var args []interface{}
	p.skipWhitespace()
	if p.pos < len(p.input) && p.input[p.pos] == ')' {
		p.advance()
		return args, nil
	}
	for {
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		args = append(args, val)
		p.skipWhitespace()
		if p.pos < len(p.input) && p.input[p.pos] == ',' {
			p.advance()
			continue
		}
		break
	}
	p.skipWhitespace()
	if p.pos < len(p.input) && p.input[p.pos] == ')' {
		p.advance()
	}
	return args, nil
}

func (p *parser) match(s string) bool {
	if p.pos+len(s) > len(p.input) {
		return false
	}
	if p.input[p.pos:p.pos+len(s)] == s {
		p.pos += len(s)
		return true
	}
	return false
}

func toBool(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	case float64:
		return val != 0
	case string:
		return val != ""
	case nil:
		return false
	default:
		return false
	}
}

func toFloat(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case string:
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return 0
		}
		return f
	case bool:
		if val {
			return 1
		}
		return 0
	default:
		return 0
	}
}

func compare(left interface{}, op string, right interface{}) bool {
	switch op {
	case "==":
		return fmt.Sprintf("%v", left) == fmt.Sprintf("%v", right)
	case "!=":
		return fmt.Sprintf("%v", left) != fmt.Sprintf("%v", right)
	case ">=":
		return toFloat(left) >= toFloat(right)
	case "<=":
		return toFloat(left) <= toFloat(right)
	case ">":
		return toFloat(left) > toFloat(right)
	case "<":
		return toFloat(left) < toFloat(right)
	}
	return false
}

func callDSLFunc(name string, args []interface{}) (interface{}, error) {
	strArgs := make([]string, len(args))
	for i, a := range args {
		strArgs[i] = fmt.Sprintf("%v", a)
	}

	switch name {
	case "contains":
		if len(strArgs) >= 2 {
			return strings.Contains(strArgs[0], strArgs[1]), nil
		}
	case "contains_all":
		if len(strArgs) >= 2 {
			for _, s := range strArgs[1:] {
				if !strings.Contains(strArgs[0], s) {
					return false, nil
				}
			}
			return true, nil
		}
	case "contains_any":
		if len(strArgs) >= 2 {
			for _, s := range strArgs[1:] {
				if strings.Contains(strArgs[0], s) {
					return true, nil
				}
			}
			return false, nil
		}
	case "tolower":
		if len(strArgs) >= 1 {
			return strings.ToLower(strArgs[0]), nil
		}
	case "to_lower":
		if len(strArgs) >= 1 {
			return strings.ToLower(strArgs[0]), nil
		}
	case "to_upper":
		if len(strArgs) >= 1 {
			return strings.ToUpper(strArgs[0]), nil
		}
	case "len":
		if len(strArgs) >= 1 {
			return float64(len(strArgs[0])), nil
		}
	case "md5":
		if len(strArgs) >= 1 {
			return callFunc("md5", strArgs[0]), nil
		}
	case "base64":
		if len(strArgs) >= 1 {
			return base64.StdEncoding.EncodeToString([]byte(strArgs[0])), nil
		}
	case "base64_decode":
		if len(strArgs) >= 1 {
			decoded, err := base64.StdEncoding.DecodeString(strArgs[0])
			if err != nil {
				return "", nil
			}
			return string(decoded), nil
		}
	case "url_encode":
		if len(strArgs) >= 1 {
			return callFunc("url_encode", strArgs[0]), nil
		}
	case "url_decode":
		if len(strArgs) >= 1 {
			return callFunc("url_decode", strArgs[0]), nil
		}
	case "hex_encode":
		if len(strArgs) >= 1 {
			return callFunc("hex_encode", strArgs[0]), nil
		}
	case "rand_text_alpha":
		return randString(8), nil
	case "rand_text_alphanumeric":
		return randString(12), nil
	case "rand_base":
		n := 8
		if len(args) > 0 {
			if f, ok := args[0].(float64); ok {
				n = int(f)
			}
		}
		return randString(n), nil
	case "regex":
		if len(strArgs) >= 2 {
			re, err := regexp.Compile(strArgs[0])
			if err != nil {
				return false, nil
			}
			return re.MatchString(strArgs[1]), nil
		}
	}
	return nil, nil
}
