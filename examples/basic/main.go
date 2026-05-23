package main

import (
	"fmt"
	"os"

	nuclei "github.com/projectdiscovery/nuclei-sdk"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <template.yaml> <target-url>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "   Or: %s --dir <templates-dir> <target-url>\n", os.Args[0])
		os.Exit(1)
	}

	target := os.Args[len(os.Args)-1]

	if os.Args[1] == "--dir" {
		templates, err := nuclei.LoadFromDir(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading templates: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Loaded %d templates from %s\n", len(templates), os.Args[2])

		for _, tmpl := range templates {
			result, err := tmpl.Execute(target)
			if err != nil {
				fmt.Printf("  [ERR] %s: %v\n", tmpl.Id, err)
				continue
			}
			status := "not matched"
			if result.Matched {
				status = "MATCHED"
			}
			fmt.Printf("  [%s] %s (%s) — %s\n", status, result.TemplateID, result.Severity, result.TemplateName)
		}
		return
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

	fmt.Printf("Template: %s (%s) [%s]\n", tmpl.Info.Name, tmpl.Id, tmpl.Info.Severity)
	fmt.Printf("Executing against: %s\n", target)

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
