// Package interactsh provides a lightweight wrapper around the projectdiscovery/interactsh
// client library for out-of-band (OOB) vulnerability verification.
//
// It handles:
//   - Connection to interactsh servers (public or self-hosted)
//   - Generation of unique interactsh URLs for template injection
//   - Replacement of {{interactsh-url}} markers in template requests
//   - Polling for DNS/HTTP/SMTP/LDAP interactions
//   - Matching interactions against template matchers to confirm blind vulnerabilities
//
// Basic usage:
//
//	client, err := interactsh.New(&interactsh.Options{
//	    ServerURL:   "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me",
//	    CooldownPeriod: 10 * time.Second,
//	})
//	if err != nil { ... }
//	defer client.Close()
//
//	url, err := client.URL()
//	// Use url in template variables as {{interactsh-url}}
//
//	// After all templates executed:
//	results := client.PollAndMatch(15 * time.Second)
package interactsh
