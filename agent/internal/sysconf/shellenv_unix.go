//go:build !windows

package sysconf

import (
	"fmt"
	"strings"
)

// zshHook is sourced on every prompt via precmd. It reads the flag
// file and exports/unsets the proxy env vars accordingly.
const zshHook = `# >>> prompt-gate proxy hook >>>
# Managed by Prompt Gate — do not edit this block manually.
_prompt_gate_proxy_hook() {
  local pf="${HOME}/.config/prompt-gate/proxy-env"
  if [[ -r "$pf" ]]; then
    local url
    url="$(<"$pf")"
    if [[ -n "$url" ]]; then
      export http_proxy="$url"
      export https_proxy="$url"
      export HTTP_PROXY="$url"
      export HTTPS_PROXY="$url"
      export no_proxy="localhost,127.0.0.1,::1"
      export NO_PROXY="$no_proxy"
      return
    fi
  fi
  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY
}
if (( ${precmd_functions[(I)_prompt_gate_proxy_hook]} == 0 )); then
  precmd_functions+=(_prompt_gate_proxy_hook)
fi
# <<< prompt-gate proxy hook <<<`

// bashHook uses PROMPT_COMMAND to achieve the same effect in bash.
const bashHook = `# >>> prompt-gate proxy hook >>>
# Managed by Prompt Gate — do not edit this block manually.
_prompt_gate_proxy_hook() {
  local pf="${HOME}/.config/prompt-gate/proxy-env"
  if [[ -r "$pf" ]]; then
    local url
    url="$(cat "$pf")"
    if [[ -n "$url" ]]; then
      export http_proxy="$url"
      export https_proxy="$url"
      export HTTP_PROXY="$url"
      export HTTPS_PROXY="$url"
      export no_proxy="localhost,127.0.0.1,::1"
      export NO_PROXY="$no_proxy"
      return
    fi
  fi
  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY
}
case ";${PROMPT_COMMAND};" in
  *_prompt_gate_proxy_hook*) ;;
  *) PROMPT_COMMAND="_prompt_gate_proxy_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
# <<< prompt-gate proxy hook <<<`

// applyShellHooks installs hooks into ~/.zshrc and ~/.bashrc.
func applyShellHooks(_ string) error {
	var errs []string
	if err := ensureHook(rcPath(".zshrc"), zshHook); err != nil {
		errs = append(errs, err.Error())
	}
	if err := ensureHook(rcPath(".bashrc"), bashHook); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("sysconf: shell hook: %s", strings.Join(errs, "; "))
	}
	return nil
}

// removeShellEnvVars is a no-op on Unix — the flag file deletion is
// sufficient; hooks will unset env vars on the next prompt.
func removeShellEnvVars() error { return nil }

// removeAllShellHooks strips hook blocks from ~/.zshrc and ~/.bashrc.
func removeAllShellHooks() error {
	var errs []string
	if err := stripHook(rcPath(".zshrc")); err != nil {
		errs = append(errs, err.Error())
	}
	if err := stripHook(rcPath(".bashrc")); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("sysconf: remove hook: %s", strings.Join(errs, "; "))
	}
	return nil
}
