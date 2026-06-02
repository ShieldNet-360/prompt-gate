// Tests for the extended pattern set (Java / Rust / frontend /
// Electron / Tauri / AI-ML / iOS / Android / Flutter / RN / DB / cloud
// infra / CI-CD / messaging / payment / auth / password-in-code).
//
// Unlike pipeline_test.go (which uses an inline miniature pattern set)
// this file loads the real production rules/dlp_patterns.json and
// rules/dlp_exclusions.json so the assertions exercise the same
// pattern definitions that ship with the agent.

package dlp

import (
"context"
"path/filepath"
"runtime"
"testing"
)

// realPipeline builds a pipeline preloaded from the project's
// production rule files. Tests that need exclusion semantics or
// require_hotword from the real rules use this; tests that only need
// pattern detection without surrounding exclusion logic can still use
// the inline testPipeline.
func realPipeline(t *testing.T) *Pipeline {
t.Helper()
_, thisFile, _, _ := runtime.Caller(0)
// agent/internal/dlp/patterns_extended_test.go → repo root is three
// levels up from the directory of this file.
repo := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
patternsPath := filepath.Join(repo, "rules", "dlp_patterns.json")
exclusionsPath := filepath.Join(repo, "rules", "dlp_exclusions.json")

patterns, err := LoadPatterns(patternsPath)
if err != nil {
t.Fatalf("LoadPatterns(%s): %v", patternsPath, err)
}
exclusions, err := LoadExclusions(exclusionsPath)
if err != nil {
t.Fatalf("LoadExclusions(%s): %v", exclusionsPath, err)
}
p := NewPipeline(DefaultScoreWeights(), NewThresholdEngine(DefaultThresholds()))
p.Rebuild(patterns, exclusions)
return p
}

// extendedPositive describes a "this content must trip pattern X" test.
// allowedPatterns is the set of patterns that are acceptable as the
// top-scoring match — when more than one pattern can plausibly fire
// on the same content (e.g. AKIA inside BasicAWSCredentials hits both
// the broad AWS Access Key and the Java-SDK-specific pattern), we
// just need ONE of them to win.
type extendedPositive struct {
label            string
content          string
allowedPatterns  []string
}

// TestExtendedPatterns_TruePositives is one table-driven test per new
// pattern category. Two cases per category satisfies the brief.
func TestExtendedPatterns_TruePositives(t *testing.T) {
p := realPipeline(t)

cases := []extendedPositive{
// -- Java ecosystem ----------------------------------
{
label: "Java JDBC PostgreSQL with embedded password",
content: "spring.datasource.url=jdbc:postgresql://db.internal:5432/" +
"orders?user=svc&password=S3rv1cE-PgX9mQ72LeapHorsE",
allowedPatterns: []string{
"JDBC PostgreSQL URL with Password",
"Database Connection String",
},
},
{
label: "Java keystore password literal",
content: "keytool -genkeypair -keystore release.jks -storepass " +
"R3leas3Pa$$word_Kp9 -keypass R3leas3Pa$$word_Kp9",
allowedPatterns: []string{"Java Keystore Password"},
},
{
label: "Spring datasource password",
content: "spring.datasource.url=jdbc:mysql://prod/users\n" +
"spring.datasource.password=Ub3rH4rdProdSecret!_42",
allowedPatterns: []string{
"Spring Datasource Password",
"JDBC MySQL URL with Password",
"Database Connection String",
"Password Assignment",
},
},
{
label: "AWS Java SDK BasicAWSCredentials",
content: "new BasicAWSCredentials(\"" + "AKIA" + "9F2D1JK4X8P0QRTM\", \"wJalrXUt" + "nFEMI/K7MDENG/bPxRfiCYE9KZkY5RPL\")",
allowedPatterns: []string{
"AWS Java SDK BasicAWSCredentials",
"AWS Access Key",
},
},

// -- Rust --------------------------------------------
{
label: "Cargo registry token",
content: "# .cargo/credentials.toml for crates.io publish\n" +
"[registry]\ntoken = \"crates_iotokenR4K3piouseRBfGhWXyaC02cZmCJXtVZeV9pQwLhT\"",
allowedPatterns: []string{"Cargo Registry Token"},
},
{
label: "Rocket.toml secret key",
content: "# Rocket.toml\n[production]\nsecret_key = \"GtPWyTw7zb9hUEnzNoRSV3X1aXmJVqHRfWPaTrG0Pc\"",
allowedPatterns: []string{"Rocket.toml Secret Key"},
},

// -- React/Angular/Frontend --------------------------
{
label: "React App env secret",
content: "// in .env for create-react-app\n" +
"REACT_APP_API_KEY=cra-prod-Q7sZ9pXmK3hLrT8nV2fW4yYbXk6E",
allowedPatterns: []string{"React App Environment Secret"},
},
{
label: "Next.js public env secret",
content: "// next.config.js process.env\n" +
"NEXT_PUBLIC_STRIPE_KEY=nxt_pub_GtPWyTw7zb9hUEnzNoRSV3X1",
allowedPatterns: []string{"Next.js Public Environment Secret"},
},
{
label: "Vite env secret",
content: "// vite.config.ts import.meta.env\n" +
"VITE_TOKEN=vit_QzXn9TpMrLb84Vfh6KsCw2YgEa7Hd",
allowedPatterns: []string{"Vite Environment Secret"},
},
{
label: "Firebase web config apiKey",
content: "firebase.initializeApp({\n" +
"  apiKey: \"" + "AIza" + "SyDLwxLO9rNwM5Bt4VuKf7QcJ2DhPmgZ31RJN\",\n" +
"  authDomain: \"my-app.firebaseapp.com\"\n" +
"});",
allowedPatterns: []string{
"Firebase Web Config apiKey",
"Google API Key",
},
},

// -- Electron/Tauri ----------------------------------
{
label: "Tauri signing private key",
content: "TAURI_SIGNING_PRIVATE_KEY=dW50cnVzdGVkIGNvbW1lbnQ6IHJzaWduIGVuY3J5cHRlZCBzZWNyZXQga2V5VeryLongB64SignedBlob01234567890ABCDEFG",
allowedPatterns: []string{"Tauri Signing Private Key"},
},
{
label: "Electron Forge publish token",
content: "// CI env for electron-forge\n" +
"SNAPCRAFT_TOKEN=snap_TK_h5gJ2nP9wXcR4VzMqLaY7DfBoCk6Ut",
allowedPatterns: []string{"Electron Forge Publish Token"},
},

// -- AI/ML platforms ---------------------------------
{
label: "OpenAI project key",
content: "// openai sdk client init\n" +
"OPENAI_API_KEY=" + "sk-" + "proj-" + "7XfBYrqZpKLM3HVeQT5cWN9JuAo2Dx1RtSGwIvZkUbHELONGRANDOMSEG",
allowedPatterns: []string{"OpenAI Project API Key"},
},
{
label: "OpenAI service account key",
content: "OPENAI_API_KEY=" + "sk-" + "svcacct-" + "9PqMxV2cHnB7aZyT5R8XfWLgEoDkUjY1NIvSGwEXTRAseglongRand",
allowedPatterns: []string{"OpenAI Service Account Key"},
},
{
label: "Anthropic API key",
content: "// claude client\n" +
"export ANTHROPIC_API_KEY=" + "sk-" + "ant-" + "api03-" + "V7Xq2HpL4cMt5Rk3GhJ9NbA1ZdYsErWoUiQxBnFvCmTaPyKjLgOsDhFeVcZxMtRpQwErTyUiOpAsDfGhJkLzXcVbNm",
allowedPatterns: []string{"Anthropic API Key"},
},
{
label: "HuggingFace token",
content: "huggingface-cli login --token " + "hf_" + "QrLp9zXk2VtMn7BcYsHfWoEiUaJdGxRYTU",
allowedPatterns: []string{"HuggingFace Access Token"},
},
{
label: "Groq API key",
content: "GROQ_API_KEY=" + "gsk_" + "KqWxRmZ9bV2nLcP7aT5Hjf3DyG6sUoE1IpAQ4HbXBNTrSV8RANDOMTAILLONG",
allowedPatterns: []string{"Groq API Key"},
},
{
label: "Replicate API token",
content: "REPLICATE_API_TOKEN=" + "r8_" + "9Pq2XmL4cVnR7BkTjHgYfWZaSdEoUbI",
allowedPatterns: []string{"Replicate API Token"},
},

// -- iOS native --------------------------------------
{
label: "Apple APNs auth key filename",
content: "// fastlane lane :push do\n" +
"  apns_key_path: 'AuthKey_AB12CD34EF.p8'\n" +
"  apple_team_id: 'XYZ1234567'",
allowedPatterns: []string{"Apple APNs Auth Key Filename"},
},
{
label: "App Store Connect API key id",
content: "# appstore_connect config for fastlane apple asc deploy\n" +
"  issuer_id: a1b2c3d4e5f67890\n" +
"  key_id: 'K9P2QRMZNL'",
allowedPatterns: []string{
"Apple App Store Connect API Key ID",
},
},

// -- Android native ----------------------------------
{
label: "google-services.json current_key",
content: "// firebase google-services.json client project_info\n" +
"\"current_key\": \"" + "AIza" + "SyD1234567ABCDEFqrSTuVwXyzABcDefGhIJ-Y\"",
allowedPatterns: []string{
"Google Services JSON API Key",
"Google API Key",
},
},
{
label: "Android signingConfigs password",
content: `android { signingConfigs { release { storeFile file('release.jks')` +
` storePassword "ProdReleaseStor3Pwd42" keyAlias "release"` +
` keyPassword "ProdReleaseKeyP4ssword42" } } }`,
allowedPatterns: []string{"Android Signing Store Password"},
},

// -- Flutter / React Native --------------------------
{
label: "Expo access token",
content: "// .env for EAS Build\n" +
"EXPO_TOKEN=" + "eyJhbGciOiJI" + "UzI1NiJ9expoExtraLongRandomTokenForCI42",
allowedPatterns: []string{"Expo Access Token"},
},
{
label: "Fastlane Match password",
content: "// .env for fastlane match\n" +
"MATCH_PASSWORD=MatchProdR3p0Pa$$w0rd!42",
allowedPatterns: []string{"Fastlane Match Password"},
},

// -- Database connection strings ---------------------
{
label: "MongoDB Atlas SRV with credentials",
content: "MONGODB_URI=mongodb+srv://service-user:Ub3rH4rdProdSecret42@" +
"cluster0.abcde.mongodb.net/orders",
allowedPatterns: []string{
"MongoDB Atlas SRV Connection",
"Database Connection String",
},
},
{
label: "MSSQL connection string with password",
content: "ConnectionString = \"Server=sql.prod.internal,1433;" +
"Database=Orders;User Id=svc_app;Password=Ub3rH4rdProdSecret42;\"",
allowedPatterns: []string{
"MSSQL Connection String with Password",
"Password Assignment",
},
},

// -- Cloud infra ------------------------------------
{
label: "Cloudflare API token",
content: "// wrangler.toml env\n" +
"CLOUDFLARE_API_TOKEN=" + "k9P2qRmZnL5cVxBT4YjHfWoEi" + "UaJdGxRYTUNL_AbCdE",
allowedPatterns: []string{"Cloudflare API Token"},
},
{
label: "Vercel token",
content: "// .env.production for vercel\n" +
"VERCEL_TOKEN=NXqL9pZmK2cVjRT4HfYbWoEiUaJdGxRY",
allowedPatterns: []string{"Vercel Token"},
},
{
label: "DigitalOcean personal token",
content: "doctl auth init --access-token " + "dop_" + "v1_" +
"9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
allowedPatterns: []string{"DigitalOcean Personal Access Token"},
},
{
label: "Netlify token",
content: "// ntl login session\n" +
"NETLIFY_AUTH_TOKEN=" + "nfp_" + "K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTUN",
allowedPatterns: []string{"Netlify Personal Access Token"},
},
{
label: "Supabase service role key",
content: "// supabase service_role key\n" +
"SUPABASE_SERVICE_ROLE=" + "sbp_" + "K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTUN0Pq2",
allowedPatterns: []string{"Supabase Service Role Key"},
},

// -- CI/CD ------------------------------------------
{
label: "GitLab pipeline trigger token",
content: "# .gitlab-ci.yml pipeline trigger\n" +
"PIPELINE_TRIGGER=" + "glptt-" + "9P2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU0pqAbCd",
allowedPatterns: []string{"GitLab CI Pipeline Trigger Token"},
},
{
label: "Bitbucket Server token",
content: "# bitbucket data center access token\n" +
"Authorization: Bearer " + "BBDC-" + "K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU",
allowedPatterns: []string{"Bitbucket Server Token (BBDC)"},
},

// -- Messaging --------------------------------------
{
label: "Discord bot token",
content: "// discord bot token\n" +
"const DISCORD_TOKEN = '" + "MTEx" + "MjM0NTY3ODkwMTIzNDU2.GabcXY." +
"ABCDEFghijklmnopqrSTUVWXYZ0123456789';",
allowedPatterns: []string{"Discord Bot Token"},
},
{
label: "Telegram bot token",
content: "// telegram botfather bot token\n" +
"TELEGRAM_BOT_TOKEN=" + "8123456789" + ":AAEabcDEFghiJKLmnoPQRstuVWXyzABCDEF",
allowedPatterns: []string{"Telegram Bot Token"},
},

// -- Payment ----------------------------------------
{
label: "Square access token",
content: "// squareup merchant\n" +
"SQUARE_ACCESS_TOKEN=" + "sq0" + "atp-Tk9P2qRmZnL5cVxBT4YjHa",
allowedPatterns: []string{"Square Access Token"},
},
{
label: "Adyen API key",
content: "# adyen payment api key\n" +
"ADYEN_API_KEY=" + "AQEvhmfu" + "XNWTK0Qc+iSHk3yqLEhWN9KZkY5RPLk9P2qRmZnL5cVxBT4YjHfWoEiUaJ",
allowedPatterns: []string{"Adyen API Key"},
},
{
label: "Plaid client secret",
content: "// plaid client_id and banking transactions\n" +
"PLAID_SECRET=9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b",
allowedPatterns: []string{"Plaid Client Secret"},
},

// -- Auth / Identity --------------------------------
{
label: "Auth0 client secret",
content: "# auth0 tenant client_id\n" +
"AUTH0_CLIENT_SECRET=K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU0pqK9p2qRmZnL5cVxBT4YjHfW",
allowedPatterns: []string{
"Auth0 Client Secret",
"Azure AD Client Secret",
},
},
{
label: "Clerk secret key",
content: "// clerk.com backend frontend_api\n" +
"CLERK_SECRET_KEY=" + "sk_" + "live_" + "K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU0pqK9p2qRmZ",
allowedPatterns: []string{
"Clerk Secret Key",
"Stripe Live Secret Key",
},
},

// -- Password-in-code -------------------------------
{
label: "Java password literal",
content: "package com.example;\nimport java.util.*;\npublic class Conf {\n" +
"  String password = \"ProdServiceP4ss42xyz\";\n}",
allowedPatterns: []string{
"Java Password Literal",
"Password Assignment",
// Generic language-agnostic password literals also match
// the bare `password = "..."` shape; map iteration order
// decides which wins so we accept any of them.
"Rust Password Literal",
"Go Password Literal",
"Python Secret Key Literal",
},
},
{
label: "Rust password literal",
content: "use std::env;\nfn main() {\n" +
"  let password: &str = \"ProdServiceP4ss42xyz\";\n}",
allowedPatterns: []string{
"Rust Password Literal",
"Password Assignment",
"Java Password Literal",
"Go Password Literal",
"Python Secret Key Literal",
},
},
{
label: "Go password literal",
content: "package main\nimport \"fmt\"\nfunc main() {\n" +
"  password := \"ProdServiceP4ss42xyz\"\n  fmt.Println(password)\n}",
allowedPatterns: []string{
"Go Password Literal",
"Password Assignment",
"Java Password Literal",
"Rust Password Literal",
"Python Secret Key Literal",
},
},
{
label: "Python secret key literal",
content: "# django settings.py\nimport os\n" +
"SECRET_KEY = \"prodDjangoS3cretKeyForSigningCookies_Q9XmKpL\"",
allowedPatterns: []string{
"Python Secret Key Literal",
"Password Assignment",
},
},

// -- Terraform provider credentials -----------
{
label: "Terraform Cloud user token",
content: "# .terraformrc credentials block for HCP Terraform\n" +
"credentials \"app.terraform.io\" {\n" +
"  token = \"7v4Xw9k2pQz3" + ".atlasv1." +
"ABcdEFghIJklMNopQRstUVwxYZ0123456789AbCdEfGhIjKlMnOpQrStUvWxYz\"\n}",
allowedPatterns: []string{"Terraform Cloud API Token"},
},
{
label: "Spacelift API key secret",
content: "# CI env for Spacelift stack runs\n" +
"export SPACELIFT_API_KEY_ID=01HG2K9P2QRMZNL5CVXBT4YJHF\n" +
"export SPACELIFT_API_KEY_SECRET=\"WoEi" + "UaJdGxRYTUNL_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\"",
allowedPatterns: []string{"Spacelift API Key"},
},
{
label: "env0 API key secret",
content: "# env0 CLI auth via API key\n" +
"export ENV0_API_KEY_ID=11111111-2222-3333-4444-555566667777\n" +
"export ENV0_API_KEY_SECRET=\"K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU\"",
allowedPatterns: []string{
"env0 API Key",
// The generic Heroku API Key pattern matches
// hex/uuid-shaped secrets too; either winning is
// fine for a hard block decision.
"Heroku API Key",
},
},
{
label: "Scalr API token assignment",
content: "# Scalr provider config\n" +
"SCALR_TOKEN=\"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH_-IJKL\"",
allowedPatterns: []string{"Scalr API Token"},
},

// -- Container registry credentials -----------
{
label: "Harbor robot account secret",
content: "# Harbor robot account for the platform project\n" +
"robot$platform+ci-deploy=K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTUNL/+aBcDe",
allowedPatterns: []string{"Harbor Robot Token"},
},
{
label: "Quay.io encrypted password",
content: "# .docker/config.json for Quay\n" +
"QUAY_PASSWORD=\"K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU\"",
allowedPatterns: []string{"Quay.io Encrypted Password"},
},
{
label: "AWS ECR get-login-password output",
content: "# docker login --password-stdin for *.dkr.ecr.us-east-1.amazonaws.com\n" +
"ECR_PASSWORD=" +
"eyJwYXlsb2FkIjoiQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5" +
"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5QUJDREVGR0hJSktM" +
"TU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4" +
"eXowMTIzNDU2Nzg5QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5" +
"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5MA==",
allowedPatterns: []string{"AWS ECR Login Token"},
},
{
label: "GCR JSON service account paste",
content: "// docker login -u _json_key for gcr.io\n" +
"{\n  \"type\": \"service_account\",\n" +
"  \"project_id\": \"my-app\",\n" +
"  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nABCDEF\\n-----END PRIVATE KEY-----\\n\",\n" +
"  \"client_email\": \"gcr-pusher@my-app.iam.gserviceaccount.com\",\n" +
"  \"audience\": \"gcr.io\"\n}",
allowedPatterns: []string{
"GCR JSON Key Paste",
// The pre-existing GCP service account / Firebase
// patterns also fire on this content; any of them
// blocking is correct behaviour.
"GCP Service Account Key",
"Firebase Admin SDK Private Key",
"Private Key Block",
},
},

// -- Secret-manager response pastes -----------
{
label: "AWS Secrets Manager GetSecretValue paste",
content: "# aws secretsmanager get-secret-value output\n" +
"{\n  \"ARN\": \"arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf\",\n" +
"  \"VersionId\": \"AbC123\",\n" +
"  \"SecretId\": \"prod/db\",\n" +
"  \"SecretString\": \"{\\\"username\\\":\\\"svc\\\",\\\"password\\\":\\\"K9p2qRmZnL5cVxBT4YjHfWoEi\\\"}\"\n}",
allowedPatterns: []string{
"AWS Secrets Manager SecretString Paste",
"Password Assignment",
},
},
{
label: "Azure Key Vault GetSecret response",
content: "# az keyvault secret show response\n" +
"{\n  \"id\": \"https://prod-kv.vault.azure.net/secrets/db-password/0123456789abcdef0123456789abcdef\",\n" +
"  \"value\": \"K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU\"\n}",
allowedPatterns: []string{"Azure Key Vault GetSecret Paste"},
},
{
label: "GCP Secret Manager AccessSecretVersion response",
content: "// gcloud secrets versions access response for projects/123/secrets/api-key/versions/1\n" +
"{\n  \"name\": \"projects/123/secrets/api-key/versions/1\",\n" +
"  \"payload\": {\"data\": \"S2RuTGxXMzZacEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFla\"}\n}",
allowedPatterns: []string{"GCP Secret Manager Payload Paste"},
},

// -- OAuth2 / OIDC tokens ---------------------
{
label: "OAuth2 refresh token",
content: "// oauth2 token exchange response\n" +
"grant_type=refresh_token\n" +
"refresh_token=" +
"1//09K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU0pqAbCdEfGhIjKlMnOpQrStUvWxYz_-.0123",
allowedPatterns: []string{"OAuth2 Refresh Token Assignment"},
},
{
label: "OIDC ID token assignment",
content: "// openid-connect id_token from /token endpoint\n" +
"id_token=" + "eyJ" +
"hbGciOiJSUzI1NiIsImtpZCI6IjB1WnpQTVA0In0" + "." +
"eyJ" + "pc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoiYWJjIiwiYXVkIjoibXktY2xpZW50In0" + "." +
"abc123signaturetailpartXYZ0123",
allowedPatterns: []string{
"OIDC ID Token Assignment",
// Generic JWT pattern may win on the eyJ shape.
"JWT Token",
},
},
{
label: "Auth0 management API token",
content: "// auth0 management api bearer\n" +
"AUTH0_DOMAIN=acme.auth0.com\n" +
"AUTH0_MGMT_TOKEN=" + "eyJ" +
"hbGciOiJSUzI1NiIsImtpZCI6Im1nbXQta2lkIn0" +
"." + "eyJ" + "pc3MiOiJodHRwczovL2FjbWUuYXV0aDAuY29tLyIsImF1ZCI6Im1ndC5hcGkifQ.tailpartXYZ0123456789",
allowedPatterns: []string{
"Auth0 Management API Token",
// Generic JWT pattern may legitimately win on score when the
// token shape is a vanilla JWS. Accept either.
"JWT Token",
},
},
{
label: "Keycloak admin-cli token",
content: "// kcadm.sh token\n" +
"KEYCLOAK_TOKEN=" + "eyJ" +
"hbGciOiJSUzI1NiIsImtpZCI6ImFkbWluLWtpZCJ9" +
"." + "eyJ" + "pc3MiOiJodHRwczovL2tjLmV4YW1wbGUiLCJyZWFsbSI6Im1hc3RlciJ9.tailpartXYZ0123456789",
allowedPatterns: []string{
"Keycloak Admin Token",
// Generic JWT token may also fire; both are acceptable.
"JWT Token",
},
},

// -- IaC hardcoded secrets --------------------
{
label: "Ansible vault block",
content: "# group_vars/prod/secrets.yml ansible playbook\n" +
"db_password: !vault |\n" +
"  $ANSIBLE_VAULT;1.1;AES256\n" +
"  6162636465666768696a6b6c6d6e6f70\n" +
"  7172737475767778797a30313233343536373839",
allowedPatterns: []string{"Ansible Vault Block"},
},
{
label: "Puppet Hiera eyaml block",
content: "# hiera.yaml puppet secrets\n" +
"db_password: ENC[PKCS7,MIIBmQYJKoZIhvcNAQcDoIIBijCCAYYCAQAxggE/MIIBOwIBADAjMA8x" +
"DTALBgNVBAMMBHRlc3QCEHcLOmTYRTRMK1tnXKbU2y8wDQYJKoZIhvcNAQEBBQAEggEAYbCdEfGhIjKl]",
allowedPatterns: []string{"Puppet Hiera eyaml Block"},
},
{
label: "Chef encrypted data bag",
content: "# data_bag/credentials/prod.json chef encrypted_data\n" +
"{\n" +
"  \"id\": \"prod\",\n" +
"  \"cipher\": \"aes-256-cbc\",\n" +
"  \"iv\": \"abcdEFghIJklMNop==\",\n" +
"  \"encrypted_data\": \"K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU0pqAbCdEfGhIj=\"\n" +
"}",
allowedPatterns: []string{"Chef Encrypted Data Bag"},
},

// -- Package manager tokens -------------------
{
label: "RubyGems API key",
content: "# ~/.gem/credentials rubygems push\n" +
"---\n:rubygems_api_key: " +
"rubygems_" + "b3e7e9c4a1d052f9c0b7a91e" + "2c4f5a8b9d2e3f4a5b6c7d8e",
allowedPatterns: []string{"RubyGems API Key"},
},
{
label: "Composer Packagist token",
content: "// auth.json for composer install on packagist\n" +
"{\"http-basic\":{\"repo.packagist.com\":{\"username\":\"acme\",\"password\":\"\"}}, " +
"\"packagist-token\":\"K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTUab12cd\"}",
allowedPatterns: []string{"Composer Packagist Token"},
},
{
label: "NuGet API key",
content: "# dotnet nuget push key\n" +
"NUGET_API_KEY=oy2abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnp",
allowedPatterns: []string{
"NuGet API Key",
// Generic API key fallback also fires; either winning
// is fine for a hard block decision.
"Generic API Key",
},
},
{
label: "Hex.pm API key",
content: "# mix hex.config api_key\n" +
"HEX_API_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGH",
allowedPatterns: []string{
"Hex.pm API Key",
// Generic API key fallback also fires on long
// alphanumeric runs.
"Generic API Key",
},
},
{
label: "Pub.dev publish token",
content: "// dart pub token add\n" +
"PUB_DEV_TOKEN=\"K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU.AbCdEfGhIjKlMnOpQ\"",
allowedPatterns: []string{"Pub.dev OAuth Refresh Token"},
},
{
label: "CocoaPods Trunk session cookie",
content: "# ~/.netrc for pod trunk\n" +
"machine trunk.cocoapods.org\n" +
"  _pods_session=K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU0pq%3D",
allowedPatterns: []string{"CocoaPods Trunk Session Cookie"},
},
{
label: "Linear personal API key",
content: "LINEAR_API_KEY=lin_" + "api_" + "Q9mKpL8vR2xT6nY4bC7hJ3sD5fG1wE0uIaZpR5sT",
allowedPatterns: []string{"Linear Personal API Key"},
},
{
label: "Linear OAuth access token",
content: "Authorization: Bearer lin_" + "oauth_" + "A1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1vW2xY3zB4cD5eF6gH7iJ8kL9mN0p",
allowedPatterns: []string{"Linear OAuth Token"},
},
}

for _, tc := range cases {
tc := tc
t.Run(tc.label, func(t *testing.T) {
got := p.Scan(context.Background(), tc.content)
if !got.Blocked {
t.Fatalf("expected block, got %+v", got)
}
if len(tc.allowedPatterns) == 0 {
return
}
for _, p := range tc.allowedPatterns {
if got.PatternName == p {
return
}
}
t.Fatalf("pattern = %q (score=%d), want one of %v",
got.PatternName, got.Score, tc.allowedPatterns)
})
}
}

// TestExtendedPatterns_FalsePositiveRegression asserts known benign
// content does NOT trigger a block, even though it contains
// pattern-like substrings. These cover the new exclusions added in
// rules/dlp_exclusions.json.
func TestExtendedPatterns_FalsePositiveRegression(t *testing.T) {
p := realPipeline(t)

benign := []struct {
label   string
content string
}{
{
"OpenAI key in markdown docs",
"Set `OPENAI_API_KEY=" + "sk-" + "proj-" + "EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE` in your `.env`.",
},
{
"AWS example key in tutorial",
"For example: AKIAIOSFODNN7EXAMPLE — do NOT commit real keys.",
},
{
"Stripe test key in docs",
"Use `" + "sk_" + "test_4242424242424242424242` during local development.",
},
{
"GitHub Actions template secret",
"runs:\n  - run: echo ${{ secrets.GITHUB_TOKEN }}",
},
{
"Discord token placeholder",
"// const token = 'YOUR_DISCORD_BOT_TOKEN'; // replace with your token",
},
{
"Firebase config in docs",
"```js\nconst firebaseConfig = { apiKey: \"" + "AIza" + "SyA12345678901234567890123456EXAMPLE\" };\n```",
},
{
"Test JSON fixture with sk_test",
"const stub = { stripe_key: '" + "sk_" + "test_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE' };",
},
{
"Code comment explaining format",
"// AWS access keys start with AKIA followed by 16 uppercase alphanumerics.",
},
{
"Import statement that looks like a token",
"import { ApiKey } from '@stripe/stripe-node';",
},
{
"Generic placeholders in prose",
"Please set your-api-key-here in CHANGEME.env before running.",
},
{
"Documentation phone numbers",
"Call 555-0100 to reach our example support line.",
},
{
"Mailinator email batch",
"contact: alice@example.com, bob@example.org, carol@test.com, dave@invalid",
},
{
"Reserved subscription id",
"AZURE_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000",
},
{
"Default localhost connection",
"DATABASE_URL=postgres://postgres:postgres@localhost:5432/myapp",
},
{
"Natural language with 'password'",
"Please choose a strong password before signing up; we never store your password in cleartext.",
},
}

for _, tc := range benign {
tc := tc
t.Run(tc.label, func(t *testing.T) {
got := p.Scan(context.Background(), tc.content)
if got.Blocked {
t.Fatalf("benign content blocked as %q (score=%d): %s",
got.PatternName, got.Score, tc.content)
}
})
}
}

// TestExtendedPatterns_PrefixMismatchFix exercises the regex
// alternation branches that were previously unreachable because the
// pattern's Aho-Corasick prefix only covered ONE branch of a
// (?:A|B|C) alternation. For each affected pattern we feed content
// that contains a branch which the original prefix literal did NOT
// cover. Before the fix (prefix=branch_A) these candidates would
// never be emitted by the AC scanner and the regex would never run;
// after the fix (prefix="") every prefix-less pattern is evaluated
// against the full content and the regex matches the previously
// unreachable branch.
//
// One case per pattern is sufficient — the AC bug is binary: either
// the prefix covered the branch or it didn't. If empty-prefix routing
// works for one missed branch, it works for all of them.
func TestExtendedPatterns_PrefixMismatchFix(t *testing.T) {
p := realPipeline(t)

cases := []extendedPositive{
{
// was prefix "SNAPCRAFT_TOKEN"; ELECTRON_GITHUB_TOKEN
// branch was previously unreachable.
label: "Electron Forge: ELECTRON_GITHUB_TOKEN branch",
content: "# .github/workflows/electron-publish.yml env\n" +
"ELECTRON_GITHUB_TOKEN=ghp_K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU",
allowedPatterns: []string{"Electron Forge Publish Token"},
},
{
// was prefix "GH_TOKEN"; BT_TOKEN branch was missed.
label: "Electron Builder: BT_TOKEN branch",
content: "# electron-builder Bintray publish env\n" +
"BT_TOKEN=bt_K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU0pqAbCdEf",
allowedPatterns: []string{"Electron Builder Publish Credentials"},
},
{
// was prefix "Server="; "Data Source=" branch was missed.
label: "MSSQL: Data Source= branch",
content: "ConnectionString = \"Data Source=sql.prod.internal,1433;" +
"Initial Catalog=Orders;UID=svc_app;Password=Ub3rH4rdProdSecret42;\"",
allowedPatterns: []string{
"MSSQL Connection String with Password",
"Password Assignment",
},
},
{
// was prefix "azuredevops"; "ado" branch was missed.
// Regex demands an unbroken [a-z2-7]{52} run after the
// alternation, so we go straight from `ado=` into a
// 52-char base32-flavour token (no intervening
// alphanumerics like _PAT= that would break the run).
label: "Azure DevOps PAT: ado branch",
content: "// azure devops api token for dev.azure.com\n" +
"ado=k7p2qrmznlc5vxbt4yjhfwoeiuajdgxrytunl2abcdefghijklmn",
allowedPatterns: []string{"Azure DevOps PAT"},
},
{
// was prefix "hvs."; hvb. (batch) branch was missed.
label: "HashiCorp Vault: hvb. (batch) branch",
content: "// vault batch token\n" +
"VAULT_TOKEN=hvb.AAAAAQJg2c4yEN9rNwM5Bt4VuKf7QcJ2DhPmgZ31",
allowedPatterns: []string{"HashiCorp Vault Token"},
},
{
// was prefix "dd_api_key"; datadog_api_key branch was missed.
label: "Datadog API Key: datadog_api_key branch",
content: "# datadog agent\n" +
"datadog_api_key=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
allowedPatterns: []string{"Datadog API Key"},
},
{
// was prefix "TAURI_SIGNING"; the dotted "tauri.signing"
// branch was missed.
label: "Tauri Signing: tauri.signing dotted branch",
content: "// tauri.conf.json signing config\n" +
"tauri.signingPRIVATE_KEY=\"dW50cnVzdGVkIGNvbW1lbnQ6IHJzaWduIGVuY3J5cHRlZCBzZWNyZXQga2V5VeryLongB64SignedBlob01234567890ABCDEFG\"",
allowedPatterns: []string{"Tauri Signing Private Key"},
},
{
// was prefix "FIREBASE_TOKEN"; the longer
// FIREBASE_APP_DISTRIBUTION_TOKEN branch was missed
// because "firebase_token" is not a substring of
// "firebase_app_distribution_token".
label: "Firebase App Distribution: long form branch",
content: "# fastlane firebase_app_distribution lane env\n" +
"FIREBASE_APP_DISTRIBUTION_TOKEN=1//09K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU0pq",
allowedPatterns: []string{"Firebase App Distribution Token"},
},
{
// was prefix "flutter"; String.fromEnvironment branch
// was missed. The regex expects the value to follow the
// key within [^A-Za-z0-9]{0,8}, so use positional args
// (no `defaultValue:` keyword that would break the run).
label: "Flutter Dart: String.fromEnvironment branch",
content: "// flutter dart const env\n" +
"const apiKey = String.fromEnvironment('API_KEY', 'cWXyzABCDEFghijklmnoPQRstuVWX');",
allowedPatterns: []string{
"Flutter Dart Environment Secret",
"Dart Password Literal",
},
},
{
// was prefix "CLOUDFLARE"; CF_API_TOKEN branch was missed.
label: "Cloudflare API: CF_API_TOKEN branch",
content: "// wrangler.toml env for cloudflare\n" +
"CF_API_TOKEN=k9P2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTUNL_AbCdE",
allowedPatterns: []string{"Cloudflare API Token"},
},
{
// was prefix "vonage"; nexmo branch was missed.
label: "Vonage Nexmo: nexmo branch",
content: "# nexmo legacy api credentials\n" +
"nexmo_api_secret=abcDEF1234567890",
allowedPatterns: []string{"Vonage Nexmo API Secret"},
},
{
// was prefix "password"; passwd branch was missed.
label: "Password Assignment: passwd branch",
content: "# service account credentials\n" +
"passwd = \"Ub3rH4rdProdSecret42xyz\"",
allowedPatterns: []string{"Password Assignment"},
},
{
// was prefix "password"; apiKey branch was missed.
label: "Go Password Literal: apiKey branch",
content: "package main\nimport \"fmt\"\nfunc main() {\n" +
"  apiKey := \"ProdGoAPIK3y_xyz_Q9_42_LongRand\"\n" +
"  fmt.Println(apiKey)\n}",
allowedPatterns: []string{
"Go Password Literal",
"Password Assignment",
},
},
{
// was prefix "const"; `final` branch was missed.
label: "Dart Password Literal: final branch",
content: "// dart config\n" +
"final apiKey = \"ProdDartAPIK3y_xyz_Q9_42_LongRand\";",
allowedPatterns: []string{
"Dart Password Literal",
"Password Assignment",
},
},
{
// was prefix "SECRET_KEY"; API_KEY branch was missed.
label: "Python Secret Key Literal: API_KEY branch",
content: "# django settings.py\nimport os\n" +
"API_KEY = \"prodPythonAPIK3yForSigningRequests_Q9XmKpLAbcDe\"",
allowedPatterns: []string{
"Python Secret Key Literal",
"Password Assignment",
},
},
}

for _, tc := range cases {
tc := tc
t.Run(tc.label, func(t *testing.T) {
got := p.Scan(context.Background(), tc.content)
if !got.Blocked {
t.Fatalf("expected block on previously-missed AC branch, got %+v", got)
}
if len(tc.allowedPatterns) == 0 {
return
}
for _, name := range tc.allowedPatterns {
if got.PatternName == name {
return
}
}
t.Fatalf("pattern = %q (score=%d), want one of %v",
got.PatternName, got.Score, tc.allowedPatterns)
})
}
}
