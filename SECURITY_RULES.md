# Security Rules Reference

This is a complete reference table of every DLP pattern shipped in
[`rules/dlp_patterns.json`](./rules/dlp_patterns.json), grouped by category.
Use this page to look up whether a given secret format is covered and how the
detector behaves.

For details on the schema and how to author or modify patterns, see
[`docs/dlp-pattern-authoring-guide.md`](./docs/dlp-pattern-authoring-guide.md).

Total patterns: **163** across the **13** JSON categories in `rules/dlp_patterns.json`.
The sub-sections below group patterns by family for readability.

Columns:

- **Pattern** — `name` in the pattern JSON; also what appears in the
  block notification.
- **Severity** — `critical` / `high` / `medium` / `low`.
- **Prefix** — Aho-Corasick literal prefix; `_(none)_` means the pattern
  runs via the full-content fallback path.
- **Hotword required** — `yes` if `require_hotword: true`; the pattern
  does not block unless a hotword fires.

---

## Cloud Providers (15)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| AWS ARN | high | `arn:aws:` | yes |
| AWS Access Key | critical | `AKIA` | no |
| AWS Java SDK BasicAWSCredentials | critical | `BasicAWSCredentials` | no |
| AWS MWS Key | critical | `amzn.mws.` | no |
| AWS Secret Access Key | critical | `secret` | no |
| AWS Session Token | critical | `aws_session_token` | no |
| Azure AD Client Secret | critical | `client_secret` | yes |
| Azure Connection String | critical | `DefaultEndpointsProtocol` | no |
| Azure DevOps PAT | critical | `_(none)_` | no |
| Azure SAS Token | critical | `sig=` | yes |
| Azure Storage Account Key | critical | `AccountKey=` | no |
| Azure Subscription ID | high | `_(none)_` | yes |
| GCP OAuth Client Secret | critical | `GOCSPX-` | no |
| GCP Service Account Key | critical | `service_account` | no |
| Google Services JSON API Key | high | `current_key` | no |

## Cloud Infrastructure (12)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Cloudflare API Token | critical | `_(none)_` | no |
| DigitalOcean OAuth Token | critical | `doo_v1_` | no |
| DigitalOcean Personal Access Token | critical | `dop_v1_` | no |
| Docker Registry Auth | critical | `"auths"` | no |
| Helm Values Password | high | `Password` | yes |
| Kubernetes Secret YAML | high | `kind: Secret` | yes |
| Netlify Personal Access Token | critical | `nfp_` | no |
| Pulumi Stack Config Secret | high | `secure:v1:` | no |
| Supabase JWT Secret | critical | `SUPABASE_JWT_SECRET` | no |
| Supabase Service Role Key | critical | `sbp_` | no |
| Terraform State Sensitive Value | high | `"sensitive"` | yes |
| Vercel Token | critical | `VERCEL_TOKEN` | no |

## Version Control (5)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Bitbucket App Password | critical | `bitbucket` | no |
| Bitbucket Server Token (BBDC) | critical | `BBDC-` | no |
| GitHub Personal Access Token | critical | `ghp_` | no |
| GitLab CI Pipeline Trigger Token | critical | `glptt-` | no |
| GitLab Personal Access Token | critical | `glpat-` | no |

## AI / ML Platforms (13)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Anthropic API Key | critical | `sk-ant-api03-` | no |
| Cohere API Key | critical | `cohere` | yes |
| Groq API Key | critical | `gsk_` | no |
| HuggingFace Access Token | critical | `hf_` | no |
| LangSmith API Key | critical | `lsv2_` | no |
| Mistral API Key | critical | `mistral` | yes |
| OpenAI Project API Key | critical | `sk-proj-` | no |
| OpenAI Service Account Key | critical | `sk-svcacct-` | no |
| OpenAI User API Key | critical | `sk-` | no |
| Pinecone API Key | critical | `pinecone` | yes |
| Replicate API Token | critical | `r8_` | no |
| Together AI API Key | critical | `together` | yes |
| Weights and Biases API Key | critical | `wandb` | no |

## Payment / Financial (9)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Adyen API Key | critical | `AQE` | yes |
| Braintree Access Token | critical | `access_token$production$` | no |
| Coinbase Commerce API Key | critical | `COINBASE` | no |
| PayPal Client Secret | critical | `paypal` | no |
| Plaid Client Secret | critical | `PLAID` | no |
| Square Access Token | critical | `sq0atp-` | no |
| Square OAuth Secret | critical | `sq0csp-` | no |
| Stripe Live Secret Key | critical | `sk_live_` | no |
| Stripe Restricted Key | critical | `rk_live_` | no |

## CI / CD (3)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| CircleCI Personal Token | critical | `circle` | no |
| Jenkins API Token | critical | `jenkins` | no |
| Travis CI Token | critical | `TRAVIS_` | no |

## Messaging / Communication (9)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Discord Bot Token | critical | `MT` | yes |
| Discord Webhook URL | high | `discord` | no |
| Mailchimp API Key | high | `_(none)_` | yes |
| SendGrid API Key | critical | `SG.` | no |
| Slack Token | critical | `xox` | no |
| Telegram Bot Token | critical | `_(none)_` | yes |
| Twilio API Key | critical | `SK` | yes |
| Twilio Account SID | critical | `AC` | yes |
| Vonage Nexmo API Secret | high | `_(none)_` | yes |

## Auth / Identity (7)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Auth0 Client Secret | critical | `AUTH0_CLIENT_SECRET` | no |
| Clerk Publishable Key | low | `pk_` | yes |
| Clerk Secret Key | critical | `sk_` | yes |
| Firebase Admin SDK Private Key | critical | `private_key_id` | no |
| Keycloak Client Secret | high | `KEYCLOAK` | no |
| Okta API Token | critical | `00` | yes |
| OneLogin API Credentials | critical | `ONELOGIN` | no |

## Java Ecosystem (10)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Gradle Repository Credentials | high | `credentials` | yes |
| JDBC MySQL URL with Password | critical | `jdbc:mysql://` | no |
| JDBC Oracle URL with Password | critical | `jdbc:oracle:` | no |
| JDBC PostgreSQL URL with Password | critical | `jdbc:postgresql://` | no |
| JDBC SQL Server URL with Password | critical | `jdbc:sqlserver://` | no |
| Java Keystore Password | critical | `storepass` | yes |
| Java Password Literal | high | `String` | yes |
| Maven Settings Password | high | `<password>` | yes |
| Spring Datasource Password | critical | `spring.datasource.password` | no |
| Spring OAuth2 Client Secret | critical | `spring.security.oauth2` | no |

## Rust Ecosystem (4)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Cargo Registry Token | critical | `[registry]` | no |
| Crates.io API Token | critical | `cio` | yes |
| Rocket.toml Secret Key | high | `secret_key` | yes |
| Rust Password Literal | high | `let` | yes |

## Frontend (React / Angular / Vite) (7)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Angular Environment Secret | high | `environment.` | yes |
| Firebase Web Config apiKey | high | `AIza` | yes |
| Next.js Public Environment Secret | high | `NEXT_PUBLIC_` | no |
| React App Environment Secret | high | `REACT_APP_` | no |
| React Native CodePush Deployment Key | high | `CodePushDeploymentKey` | no |
| Vite Environment Secret | high | `VITE_` | no |
| Webpack DefinePlugin Secret | high | `DefinePlugin` | no |

## Desktop (Electron / Tauri) (3)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Electron Builder Publish Credentials | critical | `_(none)_` | yes |
| Electron Forge Publish Token | critical | `_(none)_` | no |
| Tauri Signing Private Key | critical | `_(none)_` | no |

## iOS Native (5)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Apple APNs Auth Key Filename | high | `AuthKey_` | yes |
| Apple App Store Connect API Key ID | high | `key` | yes |
| Apple Developer Team ID | medium | `team` | yes |
| Cocoapods Trunk Token | critical | `COCOAPODS_TRUNK_TOKEN` | no |
| Xcode Cloud Secret | critical | `XCODE_CLOUD_` | no |

## Android Native (3)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Android Maps API Key in local.properties | high | `MAPS_API_KEY` | no |
| Android Signing Store Password | critical | `Password` | yes |
| Play Console Service Account JSON | critical | `service_account` | yes |

## Flutter / React Native (5)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Dart Password Literal | high | `_(none)_` | yes |
| EAS Build Secret | high | `EAS_` | no |
| Expo Access Token | critical | `EXPO_TOKEN` | no |
| Fastlane Match Password | critical | `MATCH_PASSWORD` | no |
| Flutter Dart Environment Secret | high | `_(none)_` | yes |

## Databases (7)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Cassandra Auth Provider Credentials | high | `PlainTextAuthProvider` | no |
| Database Connection String | critical | `_(none)_` | no |
| Elasticsearch URL with Credentials | high | `https://` | yes |
| MSSQL Connection String with Password | critical | `_(none)_` | no |
| MongoDB Atlas SRV Connection | critical | `mongodb+srv://` | no |
| Redis URL with Password | high | `redis` | no |
| SQLite PRAGMA Encryption Key | high | `PRAGMA` | yes |

## Private Keys / PEM (1)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Private Key Block | critical | `-----BEGIN` | no |

## JWT (1)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| JWT Token | high | `eyJ` | no |

## Password-in-Code (6)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Go Password Literal | high | `_(none)_` | yes |
| Kotlin Password Literal | high | `val` | yes |
| Password Assignment | high | `_(none)_` | yes |
| Python Secret Key Literal | high | `_(none)_` | yes |
| Source Code Imports | low | `_(none)_` | no |
| Swift Password Literal | high | `let` | yes |

## PII (4)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Credit Card Number | critical | `_(none)_` | no |
| Email Addresses (bulk) | medium | `@` | no |
| Phone Numbers (bulk, US) | medium | `_(none)_` | no |
| US Social Security Number | critical | `_(none)_` | no |

## Other / Generic (10)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Datadog API Key | high | `_(none)_` | no |
| Firebase App Distribution Token | critical | `_(none)_` | no |
| Firebase Cloud Messaging Server Key | critical | `AAAA` | no |
| Generic API Key | high | `api` | yes |
| Google API Key | critical | `AIza` | no |
| HashiCorp Vault Token | critical | `_(none)_` | no |
| Heroku API Key | high | `_(none)_` | yes |
| Internal URLs | high | `_(none)_` | no |
| npm Token | critical | `npm_` | no |
| PyPI API Token | critical | `pypi-` | no |

## Additional patterns (24)

These patterns appear under their respective JSON categories in
`rules/dlp_patterns.json` but are listed together here so reviewers
can see them at a glance.

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Terraform Cloud API Token | critical | `.atlasv1.` | no |
| Spacelift API Key | critical | `SPACELIFT_API_KEY` | no |
| env0 API Key | critical | `ENV0_API_KEY` | no |
| Scalr API Token | critical | `SCALR_TOKEN` | no |
| Harbor Robot Token | critical | `robot$` | no |
| Quay.io Encrypted Password | critical | `QUAY_` | no |
| AWS ECR Login Token | critical | `ECR_` | no |
| GCR JSON Key Paste | critical | `service_account` | no |
| AWS Secrets Manager SecretString Paste | critical | `"SecretString"` | yes |
| Azure Key Vault GetSecret Paste | critical | `vault.azure.net/secrets/` | no |
| GCP Secret Manager Payload Paste | critical | `"payload"` | yes |
| OAuth2 Refresh Token Assignment | high | `refresh_token` | yes |
| OIDC ID Token Assignment | high | `id_token` | yes |
| Auth0 Management API Token | critical | `AUTH0_` | yes |
| Keycloak Admin Token | critical | `KEYCLOAK_` | yes |
| Ansible Vault Block | critical | `$ANSIBLE_VAULT` | no |
| Puppet Hiera eyaml Block | critical | `ENC[PKCS7` | no |
| Chef Encrypted Data Bag | critical | `"cipher"` | yes |
| RubyGems API Key | critical | `rubygems_` | no |
| Composer Packagist Token | high | `packagist` | yes |
| NuGet API Key | critical | `oy2` | no |
| Hex.pm API Key | high | `HEX_` | yes |
| Pub.dev OAuth Refresh Token | high | `PUB_DEV_TOKEN` | yes |
| CocoaPods Trunk Session Cookie | high | `_pods_session` | no |

---

## Coverage notes

- **Language & platform expansion** added ~95 patterns spanning Java,
  Rust, frontend (React/Angular/Vite/Next.js), desktop (Electron/Tauri),
  AI/ML platforms (OpenAI/Anthropic/HF/Cohere/Replicate/Pinecone/Mistral/
  W&B/LangSmith/Together/Groq), iOS, Android, Flutter/React Native,
  databases, cloud infrastructure (Cloudflare/DigitalOcean/Vercel/Netlify/
  Supabase/Pulumi/Helm/Terraform/Docker/K8s), CI/CD (CircleCI/Travis/Jenkins/
  Azure DevOps/GitLab/Bitbucket), messaging (Discord/Telegram/Vonage), payment
  (PayPal/Square/Braintree/Adyen/Plaid/Coinbase), and auth/identity (Auth0/
  Okta/OneLogin/Keycloak/Firebase Admin/Supabase JWT/Clerk).
- Patterns whose ambient shape is shared with benign text use
  `require_hotword: true` to keep the FP rate within budget.
- Accuracy is enforced by
  [`agent/internal/dlp/accuracy_test.go`](./agent/internal/dlp/accuracy_test.go)
  with a 50-sample corpus (25 TP + 25 TN). Current budget: **FP < 10%**,
  **FN < 5%**.
