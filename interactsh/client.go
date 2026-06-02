package interactsh

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"

	"github.com/kN6jq/nuclei-sdk/matcher"
)

// URLMarkerRegex matches {{interactsh-url}} and {{interactsh-url_1}}, {{interactsh-url_2}} etc.
var URLMarkerRegex = regexp.MustCompile(`(%7[B|b]|\{){2}(interactsh-url(?:_[0-9]+){0,3})(%7[D|d]|\}){2}`)

// interactshURLMarker matches the plain text form for data tracking.
var interactshURLMarkerRegex = regexp.MustCompile(`\{\{interactsh-url(?:_[0-9]+)?\}\}`)

// TrackedEntry records a template request that uses interactsh URLs,
// so that incoming interactions can be matched against the template's matchers.
type TrackedEntry struct {
	TemplateID   string
	TemplateName string
	Severity     string
	Target       string
	Matchers     []*matcher.Matcher
	MatchersCond string
	URL          string
}

// OOBResult holds the result of a confirmed OOB interaction match.
type OOBResult struct {
	TemplateID    string
	TemplateName  string
	Severity      string
	Target        string
	Protocol      string
	RawRequest    string
	RawResponse   string
	RemoteAddress string
	UniqueID      string
	FullID        string
	Timestamp     time.Time
}

// Client is a wrapper around the projectdiscovery/interactsh client
// for OOB vulnerability verification.
type Client struct {
	mu sync.RWMutex

	options *Options

	// interactsh is the underlying client connection.
	interactsh *client.Client

	// tracked maps uniqueID → TrackedEntry for correlating interactions.
	tracked map[string]*TrackedEntry

	// results stores matched OOB results (populated during polling).
	results []*OOBResult

	// hostname caches the interactsh server hostname.
	hostname string

	// generated indicates whether at least one URL has been generated.
	generated atomic.Bool

	// closed indicates whether the client has been closed.
	closed atomic.Bool
}

// New creates a new interactsh client with the given options.
// If opts is nil, DefaultOptions() is used.
func New(opts *Options) (*Client, error) {
	if opts == nil {
		opts = DefaultOptions()
	}

	if opts.NoInteractsh {
		return &Client{options: opts}, nil
	}

	if opts.ServerURL == "" {
		opts.ServerURL = client.DefaultOptions.ServerURL
	}

	c := &Client{
		options: opts,
		tracked: make(map[string]*TrackedEntry),
	}

	interactClient, err := client.New(&client.Options{
		ServerURL:           opts.ServerURL,
		Token:               opts.Token,
		DisableHTTPFallback: opts.DisableHTTPFallback,
	})
	if err != nil {
		return nil, fmt.Errorf("interactsh: could not create client: %w", err)
	}

	c.interactsh = interactClient

	// Extract hostname from the generated URL
	rawURL := interactClient.URL()
	if idx := strings.Index(rawURL, "."); idx >= 0 {
		c.hostname = rawURL[idx+1:]
	}

	return c, nil
}

// URL returns a unique interactsh URL that can be embedded in template requests.
// On first call, this initializes the connection to the server.
func (c *Client) URL() (string, error) {
	if c.interactsh == nil {
		return "", fmt.Errorf("interactsh: client not initialized")
	}
	c.generated.Store(true)
	return c.interactsh.URL(), nil
}

// Hostname returns the interactsh server domain name.
func (c *Client) Hostname() string {
	return c.hostname
}

// ReplaceMarkers replaces all {{interactsh-url}} / {{interactsh-url_N}} placeholders
// in the input string with real interactsh URLs. Returns the modified string and
// the list of generated URLs.
func (c *Client) ReplaceMarkers(input string) (string, []string) {
	if c.interactsh == nil {
		return input, nil
	}

	var urls []string
	result := interactshURLMarkerRegex.ReplaceAllStringFunc(input, func(marker string) string {
		url, err := c.URL()
		if err != nil {
			return marker
		}
		urls = append(urls, url)
		return url
	})
	return result, urls
}

// Track registers a template execution request with the interactsh client.
// When interactions arrive, the template's matchers will be evaluated against
// the interaction data to confirm vulnerabilities.
func (c *Client) Track(entry *TrackedEntry) {
	if c.interactsh == nil || entry == nil || entry.URL == "" {
		return
	}

	// Extract uniqueID from the URL (everything before the first dot)
	uniqueID := entry.URL
	if idx := strings.Index(entry.URL, "."); idx >= 0 {
		uniqueID = entry.URL[:idx]
	}

	c.mu.Lock()
	c.tracked[uniqueID] = entry
	c.mu.Unlock()
}

// HasMarkers checks whether the input string contains interactsh URL markers.
func HasMarkers(input string) bool {
	return URLMarkerRegex.MatchString(input)
}

// HasMatchers checks whether any matchers reference interactsh parts.
func HasMatchers(matchers []*matcher.Matcher) bool {
	for _, m := range matchers {
		if strings.HasPrefix(strings.ToLower(m.Part), "interactsh") {
			return true
		}
		for _, dsl := range m.DSL {
			if strings.Contains(strings.ToLower(dsl), "interactsh") {
				return true
			}
		}
	}
	return false
}

// PollAndMatch starts polling for interactions and matches them against
// tracked templates. It polls at the configured interval for the configured duration.
// Returns all matched OOB results.
func (c *Client) PollAndMatch(timeout time.Duration) []*OOBResult {
	if c.interactsh == nil || c.closed.Load() {
		return nil
	}

	// Wait for cooldown period before polling
	if c.options.CooldownPeriod > 0 && c.generated.Load() {
		time.Sleep(c.options.CooldownPeriod)
	}

	pollInterval := c.options.PollInterval
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}

	deadline := time.Now().Add(timeout)

	// Start polling
	err := c.interactsh.StartPolling(pollInterval, func(interaction *server.Interaction) {
		c.handleInteraction(interaction)
	})
	if err != nil {
		return nil
	}

	// Wait until deadline, then stop polling
	remaining := time.Until(deadline)
	if remaining > 0 {
		time.Sleep(remaining)
	}
	c.interactsh.StopPolling()

	c.mu.RLock()
	results := make([]*OOBResult, len(c.results))
	copy(results, c.results)
	c.mu.RUnlock()

	return results
}

// handleInteraction processes an incoming interaction from the interactsh server.
func (c *Client) handleInteraction(interaction *server.Interaction) {
	uniqueID := interaction.UniqueID

	c.mu.RLock()
	entry, ok := c.tracked[uniqueID]
	c.mu.RUnlock()

	if !ok || entry == nil {
		return
	}

	// Build interaction data context for matcher evaluation
	interactData := map[string]interface{}{
		"interactsh_protocol": interaction.Protocol,
		"interactsh_request":  interaction.RawRequest,
		"interactsh_response": interaction.RawResponse,
		"interactsh_ip":       interaction.RemoteAddress,
	}

	// DNS requests are lowercased for consistent matching
	if strings.EqualFold(interaction.Protocol, "dns") {
		interactData["interactsh_request"] = strings.ToLower(interaction.RawRequest)
	}

	// Evaluate matchers against interaction data
	matched := evaluateInteractMatchers(entry.Matchers, entry.MatchersCond, interactData)

	if matched {
		result := &OOBResult{
			TemplateID:    entry.TemplateID,
			TemplateName:  entry.TemplateName,
			Severity:      entry.Severity,
			Target:        entry.Target,
			Protocol:      interaction.Protocol,
			RawRequest:    interaction.RawRequest,
			RawResponse:   interaction.RawResponse,
			RemoteAddress: interaction.RemoteAddress,
			UniqueID:      interaction.UniqueID,
			FullID:        interaction.FullId,
			Timestamp:     interaction.Timestamp,
		}

		c.mu.Lock()
		c.results = append(c.results, result)
		// Remove from tracked to avoid duplicate matches
		delete(c.tracked, uniqueID)
		c.mu.Unlock()
	}
}

// evaluateInteractMatchers evaluates template matchers against interaction data.
// This handles the special case where matchers reference interactsh_protocol,
// interactsh_request, interactsh_response parts.
func evaluateInteractMatchers(matchers []*matcher.Matcher, condition string, data map[string]interface{}) bool {
	if len(matchers) == 0 {
		return false
	}

	// Filter to only interactsh-related matchers
	var interactMatchers []*matcher.Matcher
	for _, m := range matchers {
		part := strings.ToLower(m.Part)
		if strings.HasPrefix(part, "interactsh") {
			interactMatchers = append(interactMatchers, m)
			continue
		}
		// Also include DSL matchers that reference interactsh
		for _, dsl := range m.DSL {
			if strings.Contains(strings.ToLower(dsl), "interactsh") {
				interactMatchers = append(interactMatchers, m)
				break
			}
		}
	}

	if len(interactMatchers) == 0 && len(matchers) > 0 {
		// No interactsh-specific matchers: if interaction arrived, consider it a match
		// (template matched on HTTP level but needed OOB for confirmation)
		return true
	}

	if condition == "" {
		condition = "or"
	}

	results := make([]bool, len(interactMatchers))
	for i, m := range interactMatchers {
		results[i] = evaluateSingleInteractMatcher(m, data)
	}

	switch condition {
	case "and":
		for _, r := range results {
			if !r {
				return false
			}
		}
		return true
	default: // "or"
		for _, r := range results {
			if r {
				return true
			}
		}
		return false
	}
}

// evaluateSingleInteractMatcher evaluates a single matcher against interaction data.
func evaluateSingleInteractMatcher(m *matcher.Matcher, data map[string]interface{}) bool {
	var result bool

	// Get the value for the matcher's part from interaction data
	value := getInteractPartValue(m.Part, data)

	switch m.Type {
	case matcher.MatcherWord:
		result = matchWords(m.Words, value, m.Condition)
	case matcher.MatcherRegex:
		result = matchRegex(m.RegexCompiled, value, m.Condition)
	case matcher.MatcherDSL:
		result = matchDSL(m.DSL, data, m.Condition)
	case matcher.MatcherStatus:
		// Status matching doesn't apply to interactsh data
		result = false
	default:
		result = false
	}

	if m.Negative {
		return !result
	}
	return result
}

func getInteractPartValue(part string, data map[string]interface{}) string {
	switch strings.ToLower(part) {
	case "interactsh_protocol":
		if v, ok := data["interactsh_protocol"]; ok {
			return fmt.Sprint(v)
		}
	case "interactsh_request":
		if v, ok := data["interactsh_request"]; ok {
			return fmt.Sprint(v)
		}
	case "interactsh_response":
		if v, ok := data["interactsh_response"]; ok {
			return fmt.Sprint(v)
		}
	}
	return ""
}

func matchWords(words []string, corpus string, condition string) bool {
	if condition == "and" {
		for _, w := range words {
			if !strings.Contains(corpus, w) {
				return false
			}
		}
		return true
	}
	for _, w := range words {
		if strings.Contains(corpus, w) {
			return true
		}
	}
	return false
}

func matchRegex(compiled []*regexp.Regexp, corpus string, condition string) bool {
	if condition == "and" {
		for _, re := range compiled {
			if !re.MatchString(corpus) {
				return false
			}
		}
		return true
	}
	for _, re := range compiled {
		if re.MatchString(corpus) {
			return true
		}
	}
	return false
}

func matchDSL(expressions []string, data map[string]interface{}, condition string) bool {
	// Simple DSL evaluation: check if expression contains keyword
	// For full DSL support, the caller should use dsl.EvaluateDSLBool
	if condition == "and" {
		for _, expr := range expressions {
			if !evaluateSimpleDSL(expr, data) {
				return false
			}
		}
		return true
	}
	for _, expr := range expressions {
		if evaluateSimpleDSL(expr, data) {
			return true
		}
	}
	return false
}

// evaluateSimpleDSL handles common interactsh DSL expressions without
// a full DSL engine. For complex expressions, use dsl.EvaluateDSLBool.
func evaluateSimpleDSL(expr string, data map[string]interface{}) bool {
	expr = strings.TrimSpace(expr)

	// Handle contains(key, 'value')
	if strings.HasPrefix(expr, "contains(") && strings.HasSuffix(expr, ")") {
		inner := expr[9 : len(expr)-1]
		parts := splitDSLArgs(inner)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.Trim(parts[1], "'\"")
			if v, ok := data[key]; ok {
				return strings.Contains(fmt.Sprint(v), val)
			}
		}
	}

	// Handle key == 'value' or key != 'value'
	for key, val := range data {
		strVal := fmt.Sprint(val)
		if expr == fmt.Sprintf("%s == '%s'", key, strVal) ||
			expr == fmt.Sprintf("%s== '%s'", key, strVal) ||
			expr == fmt.Sprintf("%s == \"%s\"", key, strVal) ||
			expr == fmt.Sprintf("%s== \"%s\"", key, strVal) {
			return true
		}
	}

	return false
}

func splitDSLArgs(s string) []string {
	var args []string
	depth := 0
	current := strings.Builder{}
	for _, ch := range s {
		switch ch {
		case '(':
			depth++
			current.WriteRune(ch)
		case ')':
			depth--
			current.WriteRune(ch)
		case ',':
			if depth == 0 {
				args = append(args, current.String())
				current.Reset()
			} else {
				current.WriteRune(ch)
			}
		default:
			current.WriteRune(ch)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

// Close stops polling, waits for cooldown, and closes the interactsh client.
// Returns true if any OOB interactions were matched.
func (c *Client) Close() bool {
	if c.closed.Swap(true) {
		return false
	}

	if c.interactsh == nil {
		return false
	}

	// Additional cooldown wait
	if c.options.CooldownPeriod > 0 && c.generated.Load() {
		time.Sleep(c.options.CooldownPeriod)
	}

	c.interactsh.StopPolling()
	c.interactsh.Close()

	c.mu.RLock()
	matched := len(c.results) > 0
	c.mu.RUnlock()

	return matched
}

// Results returns all accumulated OOB match results.
func (c *Client) Results() []*OOBResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	results := make([]*OOBResult, len(c.results))
	copy(results, c.results)
	return results
}

// IsInitialized returns true if the interactsh client has been successfully initialized.
func (c *Client) IsInitialized() bool {
	return c.interactsh != nil && !c.closed.Load()
}

// ErrNotInitialized is returned when trying to use an uninitialized interactsh client.
var ErrNotInitialized = fmt.Errorf("interactsh client not initialized")
