package template

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	stdhttp "net/http"
	"net/http/cookiejar"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kN6jq/nuclei-sdk/extractor"
	"github.com/kN6jq/nuclei-sdk/http"
	"github.com/kN6jq/nuclei-sdk/matcher"
	"github.com/kN6jq/nuclei-sdk/variables"
)

// ResponseData holds parsed HTTP response data for matcher evaluation.
type ResponseData = http.ResponseData

// defaultTimeout is the default per-request timeout.
const defaultTimeout = 10 * time.Second

// executeRequest sends an HTTP request and returns the response data.
func executeRequest(client *stdhttp.Client, req *stdhttp.Request) (*ResponseData, error) {
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	duration := time.Since(start).Seconds()

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB limit
	if err != nil {
		return nil, err
	}
	body := string(bodyBytes)

	var headerParts []string
	for k, vals := range resp.Header {
		for _, v := range vals {
			headerParts = append(headerParts, fmt.Sprintf("%s: %s", k, v))
		}
	}
	headers := strings.Join(headerParts, "\n")

	contentType := resp.Header.Get("Content-Type")

	// Extract cookies
	var cookieParts []string
	for _, c := range resp.Cookies() {
		cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}
	cookies := strings.Join(cookieParts, "; ")

	// Extract title
	title := extractTitle(body)

	return &ResponseData{
		StatusCode:  resp.StatusCode,
		Body:        body,
		Headers:     headers,
		ContentType: contentType,
		Title:       title,
		Cookies:     cookies,
		Duration:    duration,
		All:         body + "\n" + headers,
	}, nil
}

// parseRawRequest parses a raw HTTP request text into its components.
func parseRawRequest(raw, baseURL string) (method, reqPath string, headers map[string]string, body string, timeout time.Duration, err error) {
	timeoutAnnotationRe := regexp.MustCompile(`@timeout:\s*(\d+)(ms|s|m)`)

	// Extract and remove @timeout annotation
	if m := timeoutAnnotationRe.FindStringSubmatch(raw); len(m) == 3 {
		val, _ := strconv.Atoi(m[1])
		switch m[2] {
		case "ms":
			timeout = time.Duration(val) * time.Millisecond
		case "s":
			timeout = time.Duration(val) * time.Second
		case "m":
			timeout = time.Duration(val) * time.Minute
		}
		raw = timeoutAnnotationRe.ReplaceAllString(raw, "")
	}

	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 65536), 65536)

	// Skip empty lines and annotations
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "@") {
			continue
		}
		parts := strings.SplitN(trimmed, " ", 3)
		if len(parts) < 2 {
			continue
		}
		method = parts[0]
		reqPath = parts[1]
		break
	}

	headers = make(map[string]string)

	// Parse headers
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			break
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		headers[key] = val
	}

	// Remaining is body
	var bodyLines []string
	for scanner.Scan() {
		bodyLines = append(bodyLines, scanner.Text())
	}
	body = strings.Join(bodyLines, "\n")

	if method == "" {
		err = fmt.Errorf("no request line found in raw request")
	}

	return
}

// buildRawHTTPURL combines baseURL with the path from raw request.
func buildRawHTTPURL(baseURL, rawPath string) string {
	if strings.HasPrefix(rawPath, "http://") || strings.HasPrefix(rawPath, "https://") {
		return rawPath
	}
	return strings.TrimRight(baseURL, "/") + rawPath
}

// executeRequestBlock executes all requests in a Request block against a target.
// Returns the final result (matched or not) and any dynamic values extracted.
func executeRequestBlock(req *Request, target string, vars map[string]string, ec *ExecutionContext) (*Result, error) {
	// Build HTTP client with appropriate settings
	client := buildHTTPClient(req)

	// Check if this is a multi-raw-request block needing indexed responses
	allResponses := make(map[int]*ResponseData)
	dynamicValues := make(map[string][]string)

	// Track last request info for result population
	var lastReqMethod, lastReqURL, lastReqBody string
	var lastReqHeaders map[string]string

	// Cookie jar for cookie-reuse
	var jar stdhttp.CookieJar
	if req.CookieReuse {
		jar, _ = cookiejar.New(nil)
		client.Jar = jar
	}

	// Execute based on mode
	if len(req.Raw) > 0 {
		// Raw request mode
		for i, raw := range req.Raw {
			// Inject dynamic values from previous extractors into vars
			for k, v := range dynamicValues {
				if len(v) > 0 {
					vars[k] = v[0]
				}
			}
			raw = variables.Substitute(raw, vars)

			// Replace interactsh markers in raw request and track URLs
			if ec != nil {
				raw, ec.InteractshURLs = replaceInteractshMarkers(raw, ec.InteractshURLs)
			}

			method, rawPath, headers, body, timeoutOverride, err := parseRawRequest(raw, target)
			if err != nil {
				continue
			}

			reqURL := buildRawHTTPURL(target, rawPath)
			lastReqMethod = method
			lastReqURL = reqURL
			lastReqHeaders = headers
			lastReqBody = body

			ctxTimeout := defaultTimeout
			if timeoutOverride > 0 {
				ctxTimeout = timeoutOverride
			}
			ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
			defer cancel()

			httpReq, err := stdhttp.NewRequestWithContext(ctx, method, reqURL, strings.NewReader(body))
			if err != nil {
				continue
			}
			for k, v := range headers {
				httpReq.Header.Set(k, v)
			}

			resp, err := executeRequest(client, httpReq)
			if err != nil {
				allResponses[i+1] = &ResponseData{}
				continue
			}
			allResponses[i+1] = resp

			// Run extractors
			extractor.RunExtractors(req.Extractors, resp, allResponses, dynamicValues)
		}
	} else {
		// Structured request mode
		for i, path := range req.Path {
			path = variables.Substitute(path, vars)

			// Replace interactsh markers in path and track URLs
			if ec != nil {
				path, ec.InteractshURLs = replaceInteractshMarkers(path, ec.InteractshURLs)
			}

			reqURL := buildRawHTTPURL(target, path)

			body := variables.Substitute(req.Body, vars)

			// Replace interactsh markers in body
			if ec != nil && body != "" {
				body, ec.InteractshURLs = replaceInteractshMarkers(body, ec.InteractshURLs)
			}

			method := req.Method
			if method == "" {
				method = "GET"
			}

			lastReqMethod = method
			lastReqURL = reqURL
			lastReqHeaders = req.Headers
			lastReqBody = body

			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			var bodyReader io.Reader
			if body != "" {
				bodyReader = strings.NewReader(body)
			}
			httpReq, err := stdhttp.NewRequestWithContext(ctx, method, reqURL, bodyReader)
			if err != nil {
				continue
			}
			for k, v := range req.Headers {
				httpReq.Header.Set(k, variables.Substitute(v, vars))
			}

			resp, err := executeRequest(client, httpReq)
			if err != nil {
				allResponses[i+1] = &ResponseData{}
				continue
			}
			allResponses[i+1] = resp

			// Run extractors
			extractor.RunExtractors(req.Extractors, resp, allResponses, dynamicValues)

			// For single-response templates, use last response as "current"
			if len(req.Path) == 1 {
				break
			}
		}
	}

	// Evaluate matchers
	// For raw requests with multiple entries, use the last response as "current"
	// but all indexed responses are available
	var currentResp *ResponseData
	if len(allResponses) > 0 {
		// Find the last response
		maxIdx := 0
		for idx := range allResponses {
			if idx > maxIdx {
				maxIdx = idx
			}
		}
		currentResp = allResponses[maxIdx]
	}
	if currentResp == nil {
		return &Result{Matched: false}, nil
	}

	matched := matcher.EvaluateMatchers(req.Matchers, req.MatchersCondition, currentResp, allResponses, dynamicValues)

	result := &Result{
		Matched:       matched,
		Extracts:      make(map[string][]string),
		DynamicValues: dynamicValues,
		PayloadValues: make(map[string]string),
	}

	// Populate Request and Response if matched
	if matched {
		result.Request = formatRequest(lastReqMethod, lastReqURL, lastReqHeaders, lastReqBody)
		result.Response = formatResponse(currentResp)
	}

	return result, nil
}

// replaceInteractshMarkers replaces interactsh URL markers with their
// variable values from vars map. Returns modified string and accumulated URL list.
func replaceInteractshMarkers(input string, urls []string) (string, []string) {
	// The markers have already been substituted by variables.Substitute(),
	// so actual URLs will be in the string. We track them by detecting the
	// interactsh URL pattern (subdomain.oast.pro, etc.)
	// Extract any interactsh URLs that were injected via variable substitution
	re := regexp.MustCompile(`([a-z0-9]{10,33}\.[a-z0-9-]+\.[a-z]{2,})`)
	matches := re.FindAllString(input, -1)
	for _, m := range matches {
		if strings.Contains(m, "oast.") || strings.Contains(m, "interact.") {
			urls = append(urls, m)
		}
	}
	return input, urls
}

func buildHTTPClient(req *Request) *stdhttp.Client {
	maxRedirects := 0
	if req.MaxRedirects > 0 {
		maxRedirects = req.MaxRedirects
	}

	client := &stdhttp.Client{
		Timeout: 30 * time.Second,
		Transport: &stdhttp.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(r *stdhttp.Request, via []*stdhttp.Request) error {
			if !req.HostRedirects {
				return stdhttp.ErrUseLastResponse
			}
			if maxRedirects > 0 && len(via) >= maxRedirects {
				return stdhttp.ErrUseLastResponse
			}
			return nil
		},
	}
	return client
}

// extractTitle extracts the <title> content from HTML body.
func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start < 0 {
		return ""
	}
	start += 7
	end := strings.Index(lower[start:], "</title>")
	if end < 0 {
		return strings.TrimSpace(body[start:])
	}
	return strings.TrimSpace(body[start : start+end])
}

// resolveTargetURL ensures the target URL has a scheme.
func resolveTargetURL(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	return "http://" + target
}

// formatRequest formats an HTTP request into a string representation.
func formatRequest(method, url string, headers map[string]string, body string) string {
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteString(" ")
	sb.WriteString(url)
	sb.WriteString(" HTTP/1.1\r\n")
	for k, v := range headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}
	return sb.String()
}

// formatResponse formats a ResponseData into a string representation.
func formatResponse(resp *ResponseData) string {
	if resp == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 ")
	sb.WriteString(strconv.Itoa(resp.StatusCode))
	sb.WriteString("\r\n")
	sb.WriteString(resp.Headers)
	sb.WriteString("\r\n\r\n")
	sb.WriteString(resp.Body)
	return sb.String()
}