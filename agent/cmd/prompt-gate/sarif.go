package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
)

// fileResult is one blocked file from a directory scan.
type fileResult struct {
	File        string `json:"file"`
	Blocked     bool   `json:"blocked"`
	PatternName string `json:"pattern_name"`
	Score       int    `json:"score"`
}

// dirScanResult is the JSON shape emitted by --dir (non-SARIF).
type dirScanResult struct {
	Scanned  int          `json:"scanned"`
	Blocked  int          `json:"blocked"`
	Findings []fileResult `json:"findings"`
}

// maxScanFileBytes caps per-file reads during a directory walk so a
// stray large blob doesn't stall the scan.
const maxScanFileBytes = 1 << 20 // 1 MiB

// skipDirs are never descended into during a directory scan.
var skipDirs = map[string]struct{}{
	".git": {}, "node_modules": {}, "vendor": {}, ".hg": {}, ".svn": {},
}

// scanDir recursively scans every text file under root, collects the
// blocked files, and writes either SARIF or a JSON summary. Returns the
// process exit code: 1 if anything is blocked, 0 if clean, 2 on error.
func scanDir(p *dlp.Pipeline, root string, sarif, quiet bool) int {
	var findings []fileResult
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries rather than aborting
		}
		if d.IsDir() {
			if _, skip := skipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 || len(data) > maxScanFileBytes || isBinary(data) {
			return nil
		}
		scanned++
		sr := p.Scan(context.Background(), string(data))
		if sr.Blocked {
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				rel = path
			}
			findings = append(findings, fileResult{
				File: filepath.ToSlash(rel), Blocked: true,
				PatternName: sr.PatternName, Score: sr.Score,
			})
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(stderr, "prompt-gate:", err)
		return 2
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].File < findings[j].File })

	if !quiet {
		if sarif {
			out, _ := json.MarshalIndent(buildSARIF(findings, version), "", "  ")
			fmt.Fprintln(stdout, string(out))
		} else {
			out, _ := json.MarshalIndent(dirScanResult{
				Scanned: scanned, Blocked: len(findings), Findings: emptyIfNil(findings),
			}, "", "  ")
			fmt.Fprintln(stdout, string(out))
		}
	}
	if len(findings) > 0 {
		return 1
	}
	return 0
}

func emptyIfNil(f []fileResult) []fileResult {
	if f == nil {
		return []fileResult{}
	}
	return f
}

// isBinary reports whether data looks non-text (contains a NUL byte in
// the first 8 KiB) — such files are skipped during a directory scan.
func isBinary(data []byte) bool {
	n := len(data)
	if n > 8192 {
		n = 8192
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}

// ---- SARIF 2.1.0 ----

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
	Help             sarifText `json:"help"`
}
type sarifText struct {
	Text string `json:"text"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// buildSARIF maps blocked-file findings to a SARIF 2.1.0 document that
// GitHub Code Scanning ingests natively. The matched value is never
// included (privacy invariant) — only the file, the pattern name as the
// ruleId, and a generic remediation message.
func buildSARIF(findings []fileResult, ver string) sarifReport {
	if ver == "" {
		ver = "dev"
	}
	rulesByID := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		if _, ok := rulesByID[f.PatternName]; !ok {
			rulesByID[f.PatternName] = sarifRule{
				ID:               f.PatternName,
				Name:             f.PatternName,
				ShortDescription: sarifText{Text: f.PatternName + " detected"},
				Help:             sarifText{Text: "Prompt Gate detected a potential secret or sensitive value. Remove or rotate it before committing."},
			}
		}
		results = append(results, sarifResult{
			RuleID:  f.PatternName,
			Level:   sarifLevel(f.Score),
			Message: sarifText{Text: fmt.Sprintf("%s detected in %s", f.PatternName, f.File)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: f.File},
				Region:           sarifRegion{StartLine: 1},
			}}},
		})
	}
	rules := make([]sarifRule, 0, len(rulesByID))
	ids := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rules = append(rules, rulesByID[id])
	}
	return sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Prompt Gate",
				InformationURI: "https://github.com/ShieldNet-360/prompt-gate",
				Version:        ver,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// sarifLevel maps a DLP score to a SARIF severity level.
func sarifLevel(score int) string {
	if score >= 3 {
		return "error"
	}
	return "warning"
}
