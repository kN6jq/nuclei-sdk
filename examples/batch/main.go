package main

import (
	"fmt"
	"os"

	nuclei "github.com/kN6jq/nuclei-sdk/nuclei"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <templates-dir> <target-url1> [target-url2] ...\n", os.Args[0])
		os.Exit(1)
	}

	templatesDir := os.Args[1]
	targets := os.Args[2:]

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no targets specified")
		os.Exit(1)
	}

	// Load all templates from directory
	templates, err := nuclei.LoadFromDir(templatesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading templates: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Loaded %d templates from %s\n", len(templates), templatesDir)

	// Track results across all targets
	matchesByTarget := make(map[string][]*nuclei.Result)
	errorsByTarget := make(map[string][]string)

	for _, target := range targets {
		fmt.Printf("\n=== Scanning %s ===\n", target)

		for _, tmpl := range templates {
			result, err := tmpl.Execute(target)
			if err != nil {
				errorsByTarget[target] = append(errorsByTarget[target], fmt.Sprintf("%s: %v", tmpl.Id, err))
				continue
			}
			if result.Matched {
				status := "MATCHED"
				fmt.Printf("  [%s] %s (%s) — %s\n", status, result.TemplateID, result.Severity, result.TemplateName)
				matchesByTarget[target] = append(matchesByTarget[target], result)
			}
		}

		matchCount := len(matchesByTarget[target])
		if matchCount == 0 {
			fmt.Printf("  No matches found for %s\n", target)
			if errs := errorsByTarget[target]; len(errs) > 0 {
				fmt.Printf("  ( %d errors occurred)\n", len(errs))
			}
		} else {
			fmt.Printf("  Found %d match(es) for %s\n", matchCount, target)
		}
	}

	// Summary
	fmt.Printf("\n=== SUMMARY ===\n")
	for target, matches := range matchesByTarget {
		fmt.Printf("%s: %d match(es)\n", target, len(matches))
	}
}