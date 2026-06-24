package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// policy-as-code: export / diff / apply the agent's category policies and
// DLP scoring config as a versioned YAML document, so teams can commit
// `prompt-gate-policy.yaml` and gate changes in CI ("terraform plan for
// DLP policy").

type catPolicy struct {
	Category string `json:"category"`
	Action   string `json:"action"`
}

type dlpConfig struct {
	ThresholdCritical int `json:"threshold_critical" yaml:"threshold_critical"`
	ThresholdHigh     int `json:"threshold_high"     yaml:"threshold_high"`
	ThresholdMedium   int `json:"threshold_medium"   yaml:"threshold_medium"`
	ThresholdLow      int `json:"threshold_low"      yaml:"threshold_low"`
	HotwordBoost      int `json:"hotword_boost"      yaml:"hotword_boost"`
	EntropyBoost      int `json:"entropy_boost"      yaml:"entropy_boost"`
	EntropyPenalty    int `json:"entropy_penalty"    yaml:"entropy_penalty"`
	ExclusionPenalty  int `json:"exclusion_penalty"  yaml:"exclusion_penalty"`
	MultiMatchBoost   int `json:"multi_match_boost"  yaml:"multi_match_boost"`
}

// policyDoc is the on-disk YAML schema (versioned from day one).
type policyDoc struct {
	Version    int               `yaml:"version"`
	Categories map[string]string `yaml:"categories"`
	DLP        dlpConfig         `yaml:"dlp"`
}

// actionRank orders policy actions strictest→loosest so diff can flag a
// "relaxation" (a change to a looser action).
var actionRank = map[string]int{"deny": 3, "redact": 2, "allow_with_dlp": 1, "allow": 0}

func cmdPolicy(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "prompt-gate policy: expected 'export', 'diff <file>', or 'apply <file>'")
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apiAddr := fs.String("api-addr", "127.0.0.1:9191", "agent API address")
	token := fs.String("token", "", "agent API bearer token (default: ~/.prompt-gate/api-token)")
	failOnRelax := fs.Bool("fail-on-relaxation", false, "diff: exit 1 only when a category is loosened")

	// Allow the <file> positional to appear before flags (Go's flag
	// package otherwise stops parsing at the first positional). Pull a
	// leading non-flag token out, then parse the remaining flags.
	rest := args[1:]
	posFile := ""
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		posFile, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	file := posFile
	if file == "" {
		file = fs.Arg(0)
	}
	c := &policyClient{base: normalizeAddr(*apiAddr), token: resolveToken(*token), hc: &http.Client{Timeout: 10 * time.Second}}

	switch action {
	case "export":
		return c.export()
	case "diff":
		return c.diff(file, *failOnRelax)
	case "apply":
		return c.apply(file)
	default:
		fmt.Fprintf(stderr, "prompt-gate policy: unknown action %q\n", action)
		return 2
	}
}

func normalizeAddr(addr string) string {
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return strings.TrimRight(addr, "/")
	}
	return "http://" + addr
}

// resolveToken returns the explicit token, else the agent's token file,
// else the well-known local development token.
func resolveToken(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if home, err := os.UserHomeDir(); err == nil {
		if b, err := os.ReadFile(filepath.Join(home, ".prompt-gate", "api-token")); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return "prompt-gate-local-token-2025"
}

type policyClient struct {
	base  string
	token string
	hc    *http.Client
}

func (c *policyClient) do(method, path string, body []byte) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+path, r)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Host", "127.0.0.1")
	req.Host = "127.0.0.1"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data, resp.StatusCode, nil
}

func (c *policyClient) fetch() (policyDoc, error) {
	var doc policyDoc
	doc.Version = 1
	doc.Categories = map[string]string{}

	data, code, err := c.do(http.MethodGet, "/api/policies", nil)
	if err != nil {
		return doc, fmt.Errorf("reach agent at %s: %w", c.base, err)
	}
	if code != 200 {
		return doc, fmt.Errorf("GET /api/policies: status %d", code)
	}
	var pols []catPolicy
	if err := json.Unmarshal(data, &pols); err != nil {
		return doc, fmt.Errorf("decode policies: %w", err)
	}
	for _, p := range pols {
		doc.Categories[p.Category] = p.Action
	}

	data, code, err = c.do(http.MethodGet, "/api/dlp/config", nil)
	if err != nil {
		return doc, err
	}
	if code != 200 {
		return doc, fmt.Errorf("GET /api/dlp/config: status %d", code)
	}
	if err := json.Unmarshal(data, &doc.DLP); err != nil {
		return doc, fmt.Errorf("decode dlp config: %w", err)
	}
	return doc, nil
}

func (c *policyClient) export() int {
	doc, err := c.fetch()
	if err != nil {
		fmt.Fprintln(stderr, "prompt-gate:", err)
		return 2
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		fmt.Fprintln(stderr, "prompt-gate:", err)
		return 2
	}
	fmt.Fprint(stdout, string(out))
	return 0
}

func readDoc(path string) (policyDoc, error) {
	var doc policyDoc
	if path == "" {
		return doc, fmt.Errorf("a policy file path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return doc, err
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return doc, fmt.Errorf("parse %s: %w", path, err)
	}
	return doc, nil
}

func (c *policyClient) diff(path string, failOnRelax bool) int {
	want, err := readDoc(path)
	if err != nil {
		fmt.Fprintln(stderr, "prompt-gate:", err)
		return 2
	}
	cur, err := c.fetch()
	if err != nil {
		fmt.Fprintln(stderr, "prompt-gate:", err)
		return 2
	}

	changed, relaxed := false, false
	cats := make([]string, 0, len(want.Categories))
	for k := range want.Categories {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	for _, cat := range cats {
		w := want.Categories[cat]
		have := cur.Categories[cat]
		if w == have {
			continue
		}
		changed = true
		tag := ""
		if actionRank[w] < actionRank[have] {
			relaxed = true
			tag = "  [RELAXATION]"
		}
		fmt.Fprintf(stdout, "~ category %q: %s -> %s%s\n", cat, orNone(have), w, tag)
	}
	if dlpSpecified(want.DLP) {
		for _, d := range dlpDiffs(cur.DLP, want.DLP) {
			changed = true
			fmt.Fprintln(stdout, d)
		}
	}

	if !changed {
		fmt.Fprintln(stdout, "no changes — policy matches the running agent")
		return 0
	}
	if failOnRelax {
		if relaxed {
			return 1
		}
		return 0
	}
	return 1
}

func (c *policyClient) apply(path string) int {
	want, err := readDoc(path)
	if err != nil {
		fmt.Fprintln(stderr, "prompt-gate:", err)
		return 2
	}
	cur, err := c.fetch()
	if err != nil {
		fmt.Fprintln(stderr, "prompt-gate:", err)
		return 2
	}
	applied := 0
	cats := make([]string, 0, len(want.Categories))
	for k := range want.Categories {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	for _, cat := range cats {
		if want.Categories[cat] == cur.Categories[cat] {
			continue
		}
		body, _ := json.Marshal(map[string]string{"action": want.Categories[cat]})
		_, code, err := c.do(http.MethodPut, "/api/policies/"+cat, body)
		if err != nil {
			fmt.Fprintln(stderr, "prompt-gate:", err)
			return 2
		}
		if code == 403 {
			fmt.Fprintln(stderr, "prompt-gate: policy is locked by an enterprise profile (403)")
			return 1
		}
		if code != 200 {
			fmt.Fprintf(stderr, "prompt-gate: PUT category %q: status %d\n", cat, code)
			return 2
		}
		fmt.Fprintf(stdout, "set %q -> %s\n", cat, want.Categories[cat])
		applied++
	}
	if dlpSpecified(want.DLP) && len(dlpDiffs(cur.DLP, want.DLP)) > 0 {
		body, _ := json.Marshal(want.DLP)
		_, code, err := c.do(http.MethodPut, "/api/dlp/config", body)
		if err != nil {
			fmt.Fprintln(stderr, "prompt-gate:", err)
			return 2
		}
		if code == 403 {
			fmt.Fprintln(stderr, "prompt-gate: DLP config is locked by an enterprise profile (403)")
			return 1
		}
		if code != 200 {
			fmt.Fprintf(stderr, "prompt-gate: PUT dlp config: status %d\n", code)
			return 2
		}
		fmt.Fprintln(stdout, "updated dlp config")
		applied++
	}
	fmt.Fprintf(stdout, "applied %d change(s)\n", applied)
	return 0
}

// dlpSpecified reports whether the YAML included a dlp block (a
// zero-value DLPConfig means it was omitted — thresholds are never 0).
func dlpSpecified(d dlpConfig) bool { return d != dlpConfig{} }

func orNone(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// dlpDiffs returns human-readable lines for each differing DLP field.
func dlpDiffs(cur, want dlpConfig) []string {
	var out []string
	cmp := func(name string, a, b int) {
		if a != b {
			out = append(out, fmt.Sprintf("~ dlp.%s: %d -> %d", name, a, b))
		}
	}
	cmp("threshold_critical", cur.ThresholdCritical, want.ThresholdCritical)
	cmp("threshold_high", cur.ThresholdHigh, want.ThresholdHigh)
	cmp("threshold_medium", cur.ThresholdMedium, want.ThresholdMedium)
	cmp("threshold_low", cur.ThresholdLow, want.ThresholdLow)
	cmp("hotword_boost", cur.HotwordBoost, want.HotwordBoost)
	cmp("entropy_boost", cur.EntropyBoost, want.EntropyBoost)
	cmp("entropy_penalty", cur.EntropyPenalty, want.EntropyPenalty)
	cmp("exclusion_penalty", cur.ExclusionPenalty, want.ExclusionPenalty)
	cmp("multi_match_boost", cur.MultiMatchBoost, want.MultiMatchBoost)
	return out
}
