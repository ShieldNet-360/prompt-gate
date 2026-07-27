# Prompt Gate Open-Source Roadmap

**Vision:** To provide the most robust, easy-to-use local Data Loss Prevention (DLP) tool for AI interactions, while building a vibrant community and creating a natural upgrade path for teams and organizations to **Prompt Gate Enterprise**.

---

## 📈 Key Success Metrics (Targets)
To measure the success of the open-source (OSS) funnel, we are targeting the following KPIs over the next 12 months:
- **Community Growth:** Reach **500+** active weekly OSS installations.
- **Enterprise Conversion Rate:** Achieve a **3-5%** conversion rate from OSS power users to Enterprise trials.
- **Performance:** Maintain **<10ms** proxy latency for local inference to ensure zero user friction.

---

## 📅 Development Timeline

### Phase 1: Stabilization & Core User Experience
**Timeline: [Insert Exact Date / Q3 2026]**
*Goal: Ensure the open-source tool is frictionless for individual developers and small teams, creating strong word-of-mouth growth.*

- [ ] **Cross-Browser Auto-Configuration**
  - Implement automatic profile patching for Firefox (`security.enterprise_roots.enabled`) to eliminate manual certificate setups.
- [ ] **Enhanced Local DLP Engine**
  - Expand the baseline open-source pattern library (PII, API keys, crypto wallets).
  - Optimize the Aho-Corasick and regex engines for lower latency on older hardware.
- [ ] **Local Analytics Dashboard**
  - Build a lightweight, local-only SQLite-backed dashboard inside the Electron app to visualize blocked prompts and triggered rules.

### Phase 2: Extensibility & Developer Ecosystem
**Timeline: [Insert Exact Date / Q4 2026]**
*Goal: Empower the community to contribute to the project, making it the industry standard for local AI security.*

- [ ] **Community Rule Registry**
  - Introduce a system for users to easily import and share custom DLP YAML/JSON rules via GitHub.
- [ ] **Local Webhooks & Notifications**
  - Allow users to configure local webhooks (e.g., send an alert to a local Slack app when a high-severity block occurs).
- [ ] **Advanced CLI Tooling**
  - Expand the `prompt-gate-agent` CLI for headless environments, allowing developers to use the proxy in local CI/CD pipelines or automated testing.
  - Support MCP scan
  - Budget control
- [ ] **Multiple LLM Support**
  - Target to support many LLM/hub like openrouter, LiteLLM, Z-Ai.

### Phase 3: Broad Adoption & Enterprise Funnel
**Timeline: [Insert Exact Date / Q1 2027]**
*Goal: Seamlessly bridge the gap between individual power users and organizational deployments, upselling the Enterprise edition.*

- [ ] **Enterprise Feature Teasers in UI**
  - Add locked/grayed-out tabs in the Electron UI for "Fleet Management," "SSO / SAML," and "Centralized SIEM" with clear *Upgrade to Enterprise* CTAs.
- [ ] **Opt-In Telemetry & Update Checks**
  - Introduce lightweight, privacy-respecting telemetry to track active installations and OS versions to better focus development efforts.
- [ ] **Team Trial Pathways**
  - Introduce a 1-click "Start Enterprise Trial" button that allows users to seamlessly connect their local agent to the Prompt Gate Enterprise cloud dashboard.
- [ ] **Export to Enterprise**
  - Allow users to easily export their fine-tuned local rules and allow-lists to an Enterprise tenant when they upgrade.

---

> [!IMPORTANT]
> **Open Source vs. Enterprise Boundary**
> The open-source version must remain a fully-featured standalone tool for **individuals**. Any feature that involves *centralized control, identity management (Active Directory/SSO), compliance reporting, or fleet deployment (MDM)* is strictly reserved for the Enterprise tier. This ensures OSS users never feel "paywalled" out of core functionality, while still driving organizational upgrades.
