package template

import (
	"fmt"
	"strings"
	"unicode"
)

// flowNode represents a node in the flow expression tree.
type flowNode struct {
	op    string // "and", "or", "request"
	index int    // 1-based request index for "request" nodes
	left  *flowNode
	right *flowNode
}

// parseFlow parses a flow expression like "http(1) && http(2)" into a tree.
func parseFlow(expr string) (*flowNode, error) {
	p := &flowParser{input: strings.TrimSpace(expr), pos: 0}
	return p.parseOr()
}

type flowParser struct {
	input string
	pos   int
}

func (p *flowParser) peek() byte {
	if p.pos >= len(p.input) {
		return 0
	}
	return p.input[p.pos]
}

func (p *flowParser) advance() byte {
	if p.pos >= len(p.input) {
		return 0
	}
	ch := p.input[p.pos]
	p.pos++
	return ch
}

func (p *flowParser) skipWhitespace() {
	for p.pos < len(p.input) && unicode.IsSpace(rune(p.input[p.pos])) {
		p.pos++
	}
}

func (p *flowParser) match(s string) bool {
	if p.pos+len(s) > len(p.input) {
		return false
	}
	if p.input[p.pos:p.pos+len(s)] == s {
		p.pos += len(s)
		return true
	}
	return false
}

func (p *flowParser) parseOr() (*flowNode, error) {
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
			left = &flowNode{op: "or", left: left, right: right}
		} else {
			break
		}
	}
	return left, nil
}

func (p *flowParser) parseAnd() (*flowNode, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for {
		p.skipWhitespace()
		if p.match("&&") {
			right, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			left = &flowNode{op: "and", left: left, right: right}
		} else {
			break
		}
	}
	return left, nil
}

func (p *flowParser) parsePrimary() (*flowNode, error) {
	p.skipWhitespace()
	if p.peek() == '(' {
		p.advance()
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		p.skipWhitespace()
		if p.peek() == ')' {
			p.advance()
		}
		return node, nil
	}

	// Parse http(N) or any protocol(N)
	ident := p.readIdent()
	if ident == "" {
		return nil, fmt.Errorf("expected identifier in flow at pos %d", p.pos)
	}

	p.skipWhitespace()
	if p.peek() != '(' {
		return nil, fmt.Errorf("expected '(' after %s in flow", ident)
	}
	p.advance()

	p.skipWhitespace()
	idx := p.readNumber()
	if idx <= 0 {
		return nil, fmt.Errorf("expected positive number in %s()", ident)
	}

	p.skipWhitespace()
	if p.peek() == ')' {
		p.advance()
	}

	return &flowNode{op: "request", index: idx}, nil
}

func (p *flowParser) readIdent() string {
	start := p.pos
	for p.pos < len(p.input) && (unicode.IsLetter(rune(p.input[p.pos])) || p.input[p.pos] == '_') {
		p.pos++
	}
	return p.input[start:p.pos]
}

func (p *flowParser) readNumber() int {
	start := p.pos
	for p.pos < len(p.input) && p.input[p.pos] >= '0' && p.input[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == start {
		return 0
	}
	n := 0
	for _, c := range p.input[start:p.pos] {
		n = n*10 + int(c-'0')
	}
	return n
}

// evaluateFlow executes requests according to the flow tree.
// AND: both must match. OR: either must match. Short-circuit evaluation.
func evaluateFlow(node *flowNode, requests []*Request, target string, vars map[string]string, ec *ExecutionContext) (*Result, error) {
	if node == nil {
		return nil, nil
	}

	switch node.op {
	case "request":
		if node.index < 1 || node.index > len(requests) {
			return nil, fmt.Errorf("flow references request %d but only %d requests exist", node.index, len(requests))
		}
		req := requests[node.index-1]
		return executeRequestBlock(req, target, vars, ec)

	case "and":
		left, err := evaluateFlow(node.left, requests, target, vars, ec)
		if err != nil || !left.Matched {
			return &Result{Matched: false}, err
		}
		right, err := evaluateFlow(node.right, requests, target, vars, ec)
		if err != nil {
			return &Result{Matched: false}, err
		}
		return &Result{
			Matched:       left.Matched && right.Matched,
			Extracts:      mergeMaps(left.Extracts, right.Extracts),
			DynamicValues: mergeMaps(left.DynamicValues, right.DynamicValues),
			PayloadValues: mergeStringMaps(left.PayloadValues, right.PayloadValues),
		}, nil

	case "or":
		left, err := evaluateFlow(node.left, requests, target, vars, ec)
		if err == nil && left.Matched {
			return left, nil
		}
		right, err := evaluateFlow(node.right, requests, target, vars, ec)
		if err != nil {
			return &Result{Matched: false}, err
		}
		return right, nil
	}

	return nil, nil
}

func mergeMaps(a, b map[string][]string) map[string][]string {
	result := make(map[string][]string)
	for k, v := range a {
		result[k] = v
	}
	for k, v := range b {
		result[k] = append(result[k], v...)
	}
	return result
}

func mergeStringMaps(a, b map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range a {
		result[k] = v
	}
	for k, v := range b {
		result[k] = v
	}
	return result
}