package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	nuclei "github.com/kN6jq/nuclei-sdk"
)

type testCase struct {
	File     string
	ID       string
	Name     string
	Severity string
	Expected bool
	Matched  bool
	Extracts map[string][]string
	Error    string
}

func main() {
	target := "http://127.0.0.1:18080"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	templateDir := filepath.Join(".", "templates")
	entries, err := os.ReadDir(templateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: cannot read templates dir: %v\n", err)
		os.Exit(1)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	var cases []*testCase
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		raw, err := os.ReadFile(filepath.Join(templateDir, name))
		if err != nil {
			cases = append(cases, &testCase{File: name, Error: fmt.Sprintf("read: %v", err)})
			continue
		}

		tmpl, err := nuclei.Parse(raw)
		if err != nil {
			cases = append(cases, &testCase{File: name, Error: fmt.Sprintf("parse: %v", err)})
			continue
		}
		if err := tmpl.Compile(); err != nil {
			cases = append(cases, &testCase{File: name, Error: fmt.Sprintf("compile: %v", err)})
			continue
		}

		res, err := tmpl.Execute(target)
		tc := &testCase{
			File:     name,
			ID:       tmpl.Id,
			Name:     tmpl.Info.Name,
			Severity: tmpl.Info.Severity,
			Expected: !strings.Contains(tmpl.Id, "-neg-"),
		}
		if err != nil {
			tc.Error = fmt.Sprintf("execute: %v", err)
		} else {
			tc.Matched = res.Matched
			tc.Extracts = res.DynamicValues
		}
		cases = append(cases, tc)
	}

	passed := 0
	failed := 0
	errored := 0

	fmt.Println()
	fmt.Println("=== nuclei-sdk Compatibility Test Report ===")
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Templates: %d\n\n", len(cases))

	for i, tc := range cases {
		fmt.Printf("%2d. %-35s", i+1, tc.File)
		if tc.Error != "" {
			fmt.Printf(" [ERROR] %s\n", tc.Error)
			errored++
			continue
		}
		if tc.Matched == tc.Expected {
			fmt.Printf(" [PASS] matched=%v\n", tc.Matched)
			passed++
		} else {
			fmt.Printf(" [FAIL] expected=%v got=%v\n", tc.Expected, tc.Matched)
			failed++
		}
		if len(tc.Extracts) > 0 {
			for k, v := range tc.Extracts {
				fmt.Printf("    extract: %s = %v\n", k, v)
			}
		}
	}

	fmt.Println()
	fmt.Printf("Total: %d | PASS: %d | FAIL: %d | ERROR: %d\n", len(cases), passed, failed, errored)
	fmt.Println()

	if failed > 0 || errored > 0 {
		os.Exit(1)
	}
}
