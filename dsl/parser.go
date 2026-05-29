package dsl

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

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
		return callFunc(ident, args)
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