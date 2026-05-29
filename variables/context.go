package variables

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
)

var funcPattern = regexp.MustCompile(`\{\{(\w+)\(([^)]*)\)\}\}`)

// BuildVariableContext generates the variable substitution map from target URL,
// template variables, and the fixed random string.
func BuildVariableContext(targetURL string, tmplVars map[string]string, randStr string) map[string]string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return map[string]string{"BaseURL": targetURL, "randstr": randStr}
	}

	domain := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	vars := map[string]string{
		"BaseURL":       targetURL,
		"RootURL":       parsed.Scheme + "://" + parsed.Host,
		"Hostname":      parsed.Host,
		"Host":          domain,
		"Port":          port,
		"Path":          path.Dir(parsed.EscapedPath()),
		"Scheme":        parsed.Scheme,
		"Input":         targetURL,
		"randstr":       randStr,
		"interactsh-url": "interactsh.placeholder",
	}

	for k, v := range tmplVars {
		vars[k] = v
	}

	return vars
}

// Substitute replaces all {{key}} patterns in the input string.
// Pass 1: function calls like {{md5(val)}}. Pass 2: key replacement. Pass 3: function calls again (for embedded funcs).
func Substitute(input string, vars map[string]string) string {
	replaceFuncCalls := func(s string) string {
		return funcPattern.ReplaceAllStringFunc(s, func(match string) string {
			sub := funcPattern.FindStringSubmatch(match)
			if len(sub) < 3 {
				return match
			}
			fnName := sub[1]
			fnArg := sub[2]

			// Resolve variable references in arg
			if val, ok := vars[fnArg]; ok {
				fnArg = val
			}

			return callFunc(fnName, fnArg)
		})
	}

	// Pass 1: replace {{func(expr)}} patterns in input
	result := replaceFuncCalls(input)

	// Pass 2: replace {{key}} patterns
	for key, val := range vars {
		result = strings.ReplaceAll(result, "{{"+key+"}}", val)
	}

	// Pass 3: replace {{func(expr)}} patterns that appeared after key substitution
	result = replaceFuncCalls(result)

	return result
}

func callFunc(name, arg string) string {
	switch name {
	case "md5":
		h := md5.Sum([]byte(arg))
		return hex.EncodeToString(h[:])
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(arg))
	case "url_encode":
		return url.QueryEscape(arg)
	case "url_decode":
		decoded, err := url.QueryUnescape(arg)
		if err != nil {
			return arg
		}
		return decoded
	case "to_lower":
		return strings.ToLower(arg)
	case "to_upper":
		return strings.ToUpper(arg)
	case "hex_encode":
		return hex.EncodeToString([]byte(arg))
	case "rand_text_alpha":
		n := 8
		if v, err := strconv.Atoi(arg); err == nil && v > 0 {
			n = v
		}
		return randAlphaString(n)
	case "rand_text_alphanumeric":
		n := 8
		if v, err := strconv.Atoi(arg); err == nil && v > 0 {
			n = v
		}
		return randAlnumString(n)
	case "rand_base":
		n := 8
		if v, err := strconv.Atoi(arg); err == nil && v > 0 {
			n = v
		}
		return randAlnumString(n)
	default:
		return arg
	}
}

const alphaBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const alnumBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randAlphaString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = alphaBytes[int(b[i])%len(alphaBytes)]
	}
	return string(b)
}

func randAlnumString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = alnumBytes[int(b[i])%len(alnumBytes)]
	}
	return string(b)
}