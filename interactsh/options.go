package interactsh

import (
	"time"

	"github.com/projectdiscovery/interactsh/pkg/client"
)

// Options contains configuration for the interactsh OOB client.
type Options struct {
	// ServerURL is the URL(s) of the interactsh server (comma-separated).
	// Default: "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me"
	ServerURL string

	// Token is the authorization token for the interactsh server.
	Token string

	// DisableHTTPFallback controls HTTP retry in case of HTTPS failure.
	DisableHTTPFallback bool

	// CooldownPeriod is additional time to wait for interactions after
	// all template requests have been sent.
	// Default: 10 seconds
	CooldownPeriod time.Duration

	// PollInterval is the time between each poll to the server.
	// Default: 5 seconds
	PollInterval time.Duration

	// PollDuration is the total time to keep polling for interactions.
	// Default: 60 seconds (0 means use CooldownPeriod)
	PollDuration time.Duration

	// CacheSize is the number of tracked requests to keep at a time.
	// Default: 5000
	CacheSize int

	// Eviction is the period after which tracked requests are automatically discarded.
	// Default: 60 seconds
	Eviction time.Duration

	// NoInteractsh disables the OOB engine entirely.
	NoInteractsh bool
}

// DefaultOptions returns sensible defaults for the interactsh client.
func DefaultOptions() *Options {
	return &Options{
		ServerURL:           client.DefaultOptions.ServerURL,
		CooldownPeriod:      10 * time.Second,
		PollInterval:        5 * time.Second,
		PollDuration:        60 * time.Second,
		CacheSize:           5000,
		Eviction:            60 * time.Second,
		DisableHTTPFallback: true,
	}
}
