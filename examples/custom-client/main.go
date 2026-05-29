package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"time"

	nuclei "github.com/kN6jq/nuclei-sdk/nuclei"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <template.yaml> <target-url>\n", os.Args[0])
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading template: %v\n", err)
		os.Exit(1)
	}

	tmpl, err := nuclei.Parse(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing template: %v\n", err)
		os.Exit(1)
	}

	if err := tmpl.Compile(); err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling template: %v\n", err)
		os.Exit(1)
	}

	target := os.Args[2]
	fmt.Printf("Template: %s (%s) [%s]\n", tmpl.Info.Name, tmpl.Id, tmpl.Info.Severity)
	fmt.Printf("Executing against: %s\n", target)

	// Create a custom HTTP client with specific settings
	customClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // Verify TLS certificates
			},
		},
	}

	// Optionally add cookie jar for cookie reuse across requests
	jar, _ := cookiejar.New(nil)
	customClient.Jar = jar

	// Execute with our custom client
	// Note: The current SDK Execute method doesn't support custom clients yet,
	// this is a placeholder showing how it would be used in the future.
	result, err := tmpl.Execute(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing: %v\n", err)
		os.Exit(1)
	}

	if result.Matched {
		fmt.Printf("\n** MATCHED **\n")
		fmt.Printf("  Template: %s\n", result.TemplateName)
		fmt.Printf("  Severity: %s\n", result.Severity)
		if len(result.DynamicValues) > 0 {
			fmt.Printf("  Dynamic Values: %v\n", result.DynamicValues)
		}
		if len(result.Extracts) > 0 {
			fmt.Printf("  Extracts: %v\n", result.Extracts)
		}
	} else {
		fmt.Println("\nNot matched.")
	}
}