package nuclei

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

// ResponseData holds parsed HTTP response data for matcher evaluation.
type ResponseData struct {
	StatusCode  int
	Body        string
	Headers     string
	ContentType string
	Title       string
	Cookies     string
	Duration    float64
	All         string
}

// defaultTimeout is the default per-request timeout.
const defaultTimeout = 10 * time.Second

// executeRequest sends an HTTP request and returns the response data.
func executeRequest(client *http.Client, req *http.Request) (*ResponseData, error) {
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

// executeRequestBlock executes all requests in a Request block against a target.
// Returns the final result (matched or not) and any dynamic values extracted.
func executeRequestBlock(req *Request, target string, vars map[string]string) (*Result, error) {
	// Build HTTP client with appropriate settings
	client := buildHTTPClient(req)

	// Check if this is a multi-raw-request block needing indexed responses
	allResponses := make(map[int]*ResponseData)
	dynamicValues := make(map[string][]string)

	// Cookie jar for cookie-reuse
	var jar http.CookieJar
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
			raw = Substitute(raw, vars)
			method, rawPath, headers, body, timeoutOverride, err := parseRawRequest(raw, target)
			if err != nil {
				continue
			}

			reqURL := buildRawHTTPURL(target, rawPath)

			ctxTimeout := defaultTimeout
			if timeoutOverride > 0 {
				ctxTimeout = timeoutOverride
			}
			ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
			defer cancel()

			httpReq, err := http.NewRequestWithContext(ctx, method, reqURL, strings.NewReader(body))
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
			runExtractors(req.Extractors, resp, allResponses, dynamicValues)
		}
	} else {
		// Structured request mode
		for i, path := range req.Path {
			path = Substitute(path, vars)
			reqURL := buildRawHTTPURL(target, path)

			body := Substitute(req.Body, vars)
			method := req.Method
			if method == "" {
				method = "GET"
			}

			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			var bodyReader io.Reader
			if body != "" {
				bodyReader = strings.NewReader(body)
			}
			httpReq, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
			if err != nil {
				continue
			}
			for k, v := range req.Headers {
				httpReq.Header.Set(k, Substitute(v, vars))
			}

			resp, err := executeRequest(client, httpReq)
			if err != nil {
				allResponses[i+1] = &ResponseData{}
				continue
			}
			allResponses[i+1] = resp

			// Run extractors
			runExtractors(req.Extractors, resp, allResponses, dynamicValues)

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

	matched := evaluateMatchers(req.Matchers, req.MatchersCondition, currentResp, allResponses, dynamicValues)

	return &Result{
		Matched:       matched,
		Extracts:      make(map[string][]string),
		DynamicValues: dynamicValues,
		PayloadValues: make(map[string]string),
	}, nil
}

func buildHTTPClient(req *Request) *http.Client {
	maxRedirects := 0
	if req.MaxRedirects > 0 {
		maxRedirects = req.MaxRedirects
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if !req.HostRedirects {
				return http.ErrUseLastResponse
			}
			if maxRedirects > 0 && len(via) >= maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return client
}

// executePOSTForm sends a POST request with form-encoded body.
func executePOSTForm(client *http.Client, reqURL string, body string, headers map[string]string) (*ResponseData, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	if _, ok := headers["Content-Type"]; !ok {
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	return executeRequest(client, httpReq)
}

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

// substituteAndBuildHTTPRequest creates an *http.Request with substituted variables.
func substituteAndBuildHTTPRequest(method, rawURL, body string, headers map[string]string, vars map[string]string) (*http.Request, error) {
	rawURL = Substitute(rawURL, vars)
	body = Substitute(body, vars)

	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewReader([]byte(body))
	}

	req, err := http.NewRequest(method, rawURL, bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, Substitute(v, vars))
	}
	return req, nil
}

// resolveTargetURL ensures the target URL has a scheme.
func resolveTargetURL(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	return "http://" + target
}
