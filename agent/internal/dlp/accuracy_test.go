// DLP accuracy benchmark.
//
// Builds a corpus of 25 true positives and 25 true negatives covering
// every pattern ecosystem the agent ships rules for, runs the full
// production pipeline (rules/dlp_patterns.json + rules/dlp_exclusions.json)
// against each sample, and asserts the resulting false-positive and
// false-negative rates against the budget below.
//
// Budget:
//   - False positive rate  (benign blocked)            < 10%
//   - False negative rate  (secret missed)             <  5%

package dlp

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
)

type accuracySample struct {
	label   string
	content string
	// expectBlocked is the ground-truth label.
	expectBlocked bool
}

func loadProductionPipeline(t *testing.T) *Pipeline {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	patterns, err := LoadPatterns(filepath.Join(repo, "rules", "dlp_patterns.json"))
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	exclusions, err := LoadExclusions(filepath.Join(repo, "rules", "dlp_exclusions.json"))
	if err != nil {
		t.Fatalf("LoadExclusions: %v", err)
	}
	p := NewPipeline(DefaultScoreWeights(), NewThresholdEngine(DefaultThresholds()))
	p.Rebuild(patterns, exclusions)
	return p
}

func accuracyCorpus() []accuracySample {
	return []accuracySample{
		// ---- True positives (25) -----------------------------------
		{"TP/AWS access key", "aws creds: AKIA" + "9P2QRMZNL5CVXBT4" + " with secret following", true},
		{"TP/GitHub PAT", "GITHUB_TOKEN=" + "ghp_" + "9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e", true},
		{"TP/Slack bot", "SLACK_BOT_TOKEN=" + "xo" + "xb-" + "12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUv", true},
		{"TP/Stripe live", "STRIPE_SECRET=" + "sk_" + "live_" + "AbCdEfGhIjKlMnOpQrStUv12", true},
		{"TP/Google API", "google maps integration: " + "AIza" + "SyD9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3D", true},
		{"TP/Azure storage account", "STORAGE_CONN=" + "DefaultEndpointsProtocol=https;" + "AccountName=prodstore01;" + "AccountKey=" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMn" + "==;EndpointSuffix=core.windows.net", true},
		{"TP/JDBC PostgreSQL", "spring.datasource.url=jdbc:postgresql://db.prod:5432/orders?user=svc&password=Pr0dDbS3rvicePwdAbc", true},
		{"TP/Cargo registry token", "[registry]\ntoken = \"" + "cargo-" + "AbCdEfGhIjKlMnOpQrStUvWxYz01234567894_xy\"\n", true},
		{"TP/REACT_APP env", "REACT_APP_FIREBASE_KEY=AIzaProductionKeyForReactAppDoNotShareAa", true},
		{"TP/Tauri signingKey", "TAURI_SIGNING_PRIVATE_KEY=" + "RWQ" + "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789AbcdefGhijKlmnopRstuvXyz123456789", true},
		{"TP/OpenAI proj key", "OPENAI_API_KEY=" + "sk-" + "proj-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123", true},
		{"TP/Anthropic key", "ANTHROPIC_API_KEY=" + "sk-" + "ant-" + "api03-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123_AbCdEfGhIjKlMnAA", true},
		{"TP/HuggingFace token", "HF_TOKEN=" + "hf_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Abc", true},
		{"TP/APNs .p8 filename", "apns:\n  apple_team_id: 'XYZ1234567'\n  apns_key_path: 'AuthKey_AB12CD34EF.p8'", true},
		{"TP/google-services.json", "// firebase google-services.json project_info\n\"current_key\": \"AIzaProductionKeyForAndroidAppDoNotShareAa-X\"", true},
		{"TP/Expo token", "EXPO_TOKEN=" + "eyJhbGciOiJI" + "UzI1NiJ9expoExtraLongRandomTokenForCI42", true},
		{"TP/MongoDB Atlas SRV", "MONGODB_URI=" + "mongodb+srv://" + "svc:Ub3rH4rdProdSecret42@cluster0.abc.mongodb.net/orders", true},
		{"TP/Cloudflare token", "CLOUDFLARE_API_TOKEN=" + "k9P2qRmZnL5cVxBT4YjHfWoEi" + "UaJdGxRYTUNL_AbCdE", true},
		{"TP/Discord bot", "const DISCORD_TOKEN = '" + "MTEx" + "MjM0NTY3ODkwMTIzNDU2.GabcXY." + "ABCDEFghijklmnopqrSTUVWXYZ0123456789';", true},
		{"TP/Square access", "SQUARE_ACCESS_TOKEN=" + "sq0" + "atp-" + "AbCdEfGhIjKlMnOpQrStUv", true},
		{"TP/Auth0 client secret", "AUTH0_CLIENT_SECRET=K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU0pqK9p2qRmZnL5cVxBT4YjHfWoEiU", true},
		{"TP/Clerk live", "CLERK_SECRET_KEY=" + "sk_" + "live_" + "K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU0pqK9p2qRmZ", true},
		{"TP/Java password literal", "package com.example;\nimport java.util.*;\npublic class Db {\n  String password = \"ProdServiceP4ss42xyz\";\n}", true},
		{"TP/Python SECRET_KEY", "# django settings\nimport os\nSECRET_KEY = \"prodDjangoS3cretKeyForSigningCookies_Q9XmKpL\"", true},
		{"TP/PEM private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f\n-----END RSA PRIVATE KEY-----", true},

		// ---- True negatives (25) -----------------------------------
		{"TN/Doc AWS example", "Example key (do not use): AKIAIOSFODNN7EXAMPLE", false},
		{"TN/Stripe test key in docs", "// example only\n// const stripe = require('stripe')('" + "sk_" + "test_4eC39HqLyjWDarjtT1zdp7dc');", false},
		{"TN/Random prose", "The quick brown fox jumps over the lazy dog. A password is a secret, but this paragraph contains none.", false},
		{"TN/GitHub Actions template", "runs:\n  - run: echo ${{ secrets.GITHUB_TOKEN }}", false},
		{"TN/Reserved domain", "Connect to localhost or example.com for development; no production endpoints.", false},
		{"TN/Pattern doc comment", "// OpenAI keys start with sk-proj- followed by ~64 base62 chars (this is documentation).", false},
		{"TN/Lorem ipsum", "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt.", false},
		{"TN/Placeholder API_KEY", "API_KEY=your-api-key-here", false},
		{"TN/Placeholder INSERT_TOKEN", "DEPLOY_TOKEN=INSERT_TOKEN_HERE", false},
		{"TN/AcmeCorp readme", "# AcmeCorp Internal Tools\nThis README is for AcmeCorp developers.", false},
		{"TN/Test fixture password", "# tests/fixtures/passwords.txt\nstub_password = 'test_password_123'\n", false},
		{"TN/Firebase docs", "```js\nconst firebaseConfig = { apiKey: \"AIzaSyA12345678901234567890123456EXAMPLE\" };\n```", false},
		{"TN/Markdown link", "See [our docs](https://example.com/docs/api-keys) for token formats.", false},
		{"TN/AKIA in middle of word", "the user akiakire@example.com filed a bug.", false},
		{"TN/Code review comment", "/* TODO: rotate the placeholder password here before launch */", false},
		{"TN/Import statement", "import { OAUTH_TOKEN_KEY } from './constants';", false},
		{"TN/JSON config skeleton", `{"client_id":"YOUR_CLIENT_ID","client_secret":"YOUR_CLIENT_SECRET"}`, false},
		{"TN/Manifest API_KEY", `<meta-data android:name="com.google.android.geo.API_KEY" android:value="@string/maps_key"/>`, false},
		{"TN/Repeating zero token", "DUMMY_TOKEN=0000000000000000000000000000000000000000", false},
		{"TN/Markdown heading", "## Security guide\n\nThis section explains how to handle credentials securely.", false},
		{"TN/Acmecorp package", "package com.acmecorp.demo; // dummy code, no secrets here", false},
		{"TN/Username only", "USER=svc_app\n# password lives in vault, not in this file", false},
		{"TN/Public PEM cert", "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8...PUBLIC...\n-----END CERTIFICATE-----", false},
		{"TN/Comment about secrets", "# remember: never paste a real OPENAI_API_KEY here; use 1Password instead.", false},
		{"TN/HTML escape", "&lt;password&gt; placeholder in template syntax", false},
	}
}

// TestDLPAccuracyCorpus measures TP/TN/FP/FN against the production
// rule files and asserts the rates meet the budget (FP < 10%, FN < 5%).
func TestDLPAccuracyCorpus(t *testing.T) {
	p := loadProductionPipeline(t)
	corpus := accuracyCorpus()

	var tp, tn, fp, fn int
	var fpExamples, fnExamples []string
	for _, s := range corpus {
		got := p.Scan(context.Background(), s.content)
		switch {
		case s.expectBlocked && got.Blocked:
			tp++
		case s.expectBlocked && !got.Blocked:
			fn++
			fnExamples = append(fnExamples, s.label)
		case !s.expectBlocked && got.Blocked:
			fp++
			fpExamples = append(fpExamples,
				s.label+" => "+got.PatternName)
		case !s.expectBlocked && !got.Blocked:
			tn++
		}
	}

	total := tp + tn + fp + fn
	positives := 0
	negatives := 0
	for _, s := range corpus {
		if s.expectBlocked {
			positives++
		} else {
			negatives++
		}
	}

	fpRate := float64(fp) / float64(negatives)
	fnRate := float64(fn) / float64(positives)

	t.Logf("corpus=%d positives=%d negatives=%d", total, positives, negatives)
	t.Logf("TP=%d TN=%d FP=%d FN=%d", tp, tn, fp, fn)
	t.Logf("FP rate=%.3f (budget <0.10)  FN rate=%.3f (budget <0.05)", fpRate, fnRate)
	if len(fpExamples) > 0 {
		t.Logf("false positives:")
		for _, e := range fpExamples {
			t.Logf("  - %s", e)
		}
	}
	if len(fnExamples) > 0 {
		t.Logf("false negatives:")
		for _, e := range fnExamples {
			t.Logf("  - %s", e)
		}
	}

	if fpRate >= 0.10 {
		t.Errorf("FP rate %.3f exceeds 10%% budget (fp=%d, negatives=%d)",
			fpRate, fp, negatives)
	}
	if fnRate >= 0.05 {
		t.Errorf("FN rate %.3f exceeds 5%% budget (fn=%d, positives=%d)",
			fnRate, fn, positives)
	}
}
