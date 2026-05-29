package dsl

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// EvaluateDSL evaluates a DSL expression against a context map.
// Returns the result as an interface{} (bool, float64, or string).
func EvaluateDSL(expr string, ctx map[string]interface{}) (interface{}, error) {
	p := newParser(expr, ctx)
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

func callFunc(name string, args []interface{}) (interface{}, error) {
	strArgs := make([]string, len(args))
	for i, a := range args {
		strArgs[i] = fmt.Sprintf("%v", a)
	}

	switch name {
	case "contains":
		if len(strArgs) >= 2 {
			return stringContains(strArgs[0], strArgs[1]), nil
		}
	case "contains_all":
		if len(strArgs) >= 2 {
			for _, s := range strArgs[1:] {
				if !stringContains(strArgs[0], s) {
					return false, nil
				}
			}
			return true, nil
		}
	case "contains_any":
		if len(strArgs) >= 2 {
			for _, s := range strArgs[1:] {
				if stringContains(strArgs[0], s) {
					return true, nil
				}
			}
			return false, nil
		}
	case "tolower":
		if len(strArgs) >= 1 {
			return toLower(strArgs[0]), nil
		}
	case "to_lower":
		if len(strArgs) >= 1 {
			return toLower(strArgs[0]), nil
		}
	case "to_upper":
		if len(strArgs) >= 1 {
			return toUpper(strArgs[0]), nil
		}
	case "len":
		if len(strArgs) >= 1 {
			return float64(len(strArgs[0])), nil
		}
	case "md5":
		if len(strArgs) >= 1 {
			return md5Hash(strArgs[0]), nil
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
			return urlEncode(strArgs[0]), nil
		}
	case "url_decode":
		if len(strArgs) >= 1 {
			return urlDecode(strArgs[0]), nil
		}
	case "hex_encode":
		if len(strArgs) >= 1 {
			return hexEncode(strArgs[0]), nil
		}
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

func stringContains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func toLower(s string) string {
	return strings.ToLower(s)
}

func toUpper(s string) string {
	return strings.ToUpper(s)
}