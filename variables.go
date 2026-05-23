package nuclei

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"path"
	"regexp"
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
// First pass: simple key replacement. Second pass: function calls like {{md5(val)}}.
func Substitute(input string, vars map[string]string) string {
	// First pass: replace {{func(expr)}} patterns
	result := funcPattern.ReplaceAllStringFunc(input, func(match string) string {
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

	// Second pass: replace {{key}} patterns
	for key, val := range vars {
		result = strings.ReplaceAll(result, "{{"+key+"}}", val)
	}

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
	default:
		return arg
	}
}
