# Homebrew cask for Prompt Gate (Apple Silicon).
#
# Install directly:
#   brew install --cask ./packaging/homebrew/prompt-gate.rb
# Or via a tap once published (see packaging/README.md):
#   brew install --cask ShieldNet-360/tap/prompt-gate
#
# NOTE: builds are not yet Apple Developer ID notarized. Until then macOS
# Gatekeeper may block the app; see the caveats below.
cask "prompt-gate" do
  version "1.0.0"
  sha256 "54c3a79493b04aac7f82a72e8916ff694156d2e8c144c1507a9fbd2e9800938d"

  url "https://github.com/ShieldNet-360/prompt-gate/releases/download/v#{version}/Prompt.Gate-#{version}-arm64.dmg",
      verified: "github.com/ShieldNet-360/prompt-gate/"
  name "Prompt Gate"
  desc "Privacy-first, open-source AI Data Leakage Prevention agent"
  homepage "https://github.com/ShieldNet-360/prompt-gate"

  depends_on arch:  :arm64
  depends_on macos: ">= :big_sur"

  app "Prompt Gate.app"

  uninstall quit: "com.shieldnet360.promptgate"

  zap trash: [
    "~/.prompt-gate",
    "~/Library/Application Support/prompt-gate",
  ]

  caveats <<~EOS
    Prompt Gate builds are not yet Apple notarized. If macOS blocks the app
    with "cannot be opened because the developer cannot be verified":

      xattr -cr "/Applications/Prompt Gate.app"

    Verify the download first (recommended):
      gh attestation verify "$(brew --cache)/--prompt-gate--#{version}-arm64.dmg" \\
        --repo ShieldNet-360/prompt-gate
  EOS
end
