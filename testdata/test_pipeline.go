package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	nuclei "github.com/kN6jq/nuclei-sdk"
)

func main() {
	target := "http://127.0.0.1:18080"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	fmt.Println("\n=== nuclei-sdk Pipeline Integration Test ===")
	fmt.Printf("Target: %s\n\n", target)

	// --- Test 1: LoadFromDir ---
	fmt.Println("[Test 1] LoadFromDir")
	templateDir := filepath.Join(".", "templates")
	templates, err := nuclei.LoadFromDir(templateDir)
	if err != nil {
		fmt.Printf("  FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  PASS: loaded %d templates\n\n", len(templates))

	// --- Test 2: Execute each and check stats ---
	fmt.Println("[Test 2] Execute All Templates")
	passed := 0
	failed := 0
	negPassed := 0
	type extractInfo struct {
		Name   string
		Values []string
	}
	extracted := map[string][]extractInfo{}

	sort.Slice(templates, func(i, j int) bool {
		return templates[i].Id < templates[j].Id
	})

	for _, tmpl := range templates {
		isNeg := strings.Contains(tmpl.Id, "-neg-")
		res, err := tmpl.Execute(target)
		if err != nil {
			fmt.Printf("  ERROR: %-40s %v\n", tmpl.Id, err)
			failed++
			continue
		}
		expected := !isNeg
		if res.Matched == expected {
			if isNeg {
				negPassed++
			} else {
				passed++
			}
		} else {
			fmt.Printf("  FAIL: %-40s expected=%v got=%v\n", tmpl.Id, expected, res.Matched)
			failed++
		}
		if len(res.DynamicValues) > 0 {
			for k, v := range res.DynamicValues {
				extracted[tmpl.Id] = append(extracted[tmpl.Id], extractInfo{k, v})
			}
		}
	}

	fmt.Printf("\n  Results: PASS=%d NEG-PASS=%d FAIL=%d Total=%d\n", passed, negPassed, failed, len(templates))
	if len(extracted) > 0 {
		fmt.Println("  Extractor outputs:")
		for tmplId, exts := range extracted {
			for _, e := range exts {
				fmt.Printf("    %s → %s = %v\n", tmplId, e.Name, e.Values)
			}
		}
	}
	fmt.Println()

	// --- Test 3: Concurrent execution ---
	fmt.Println("[Test 3] Concurrent Execution (10 templates parallel)")
	start := time.Now()
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			tmpl := templates[idx%len(templates)]
			tmpl.Execute(target)
			done <- true
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	fmt.Printf("  PASS: 10 concurrent executions in %v\n\n", time.Since(start).Round(time.Millisecond))

	// --- Test 4: Result serialization (JSON output) ---
	fmt.Println("[Test 4] Result JSON Serialization")
	tmpl := templates[0] // first template
	res, _ := tmpl.Execute(target)
	if res != nil {
		data, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			fmt.Printf("  FAIL: %v\n", err)
		} else {
			fmt.Printf("  PASS: serialized %d bytes\n", len(data))
		}
	}
	fmt.Println()

	// --- Summary ---
	fmt.Println("=== Summary ===")
	if failed > 0 {
		fmt.Printf("FAILED: %d tests did not pass\n", failed)
		os.Exit(1)
	}
	fmt.Printf("ALL PASS: %d positive + %d negative = %d total\n", passed, negPassed, passed+negPassed)
}
