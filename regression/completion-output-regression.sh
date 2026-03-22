#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
VFIO_SCRIPT="${PROJECT_ROOT}/vfio.sh"

if [[ ! -f "$VFIO_SCRIPT" ]]; then
  printf 'FAIL: missing vfio.sh at %s\n' "$VFIO_SCRIPT" >&2
  exit 1
fi

fail=0
FAILED_ASSERTIONS=()

record_failure() {
  local name="$1"
  FAILED_ASSERTIONS+=("$name")
  fail=1
}

assert_non_empty() {
  local name="$1" value="$2"
  if [[ -n "$value" ]]; then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (output was empty)\n' "$name" >&2
    record_failure "$name"
  fi
}

assert_contains_text() {
  local name="$1" pattern="$2" haystack="$3"
  if grep -Fq -- "$pattern" <<<"$haystack"; then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (pattern not found: %s)\n' "$name" "$pattern" >&2
    record_failure "$name"
  fi
}

extract_help_long_options() {
  local help_text="$1"
  printf '%s\n' "$help_text" | grep -Eo -- '--[a-z0-9][a-z0-9-]*' | sort -u
}

assert_shell_covers_help_options() {
  local shell_name="$1" completion_text="$2"
  local opt fish_key

  for opt in "${HELP_LONG_OPTS[@]}"; do
    case "$shell_name" in
      fish)
        fish_key="-l ${opt#--}"
        assert_contains_text "fish completion covers ${opt}" "$fish_key" "$completion_text"
        ;;
      bash)
        assert_contains_text "bash completion covers ${opt}" "$opt" "$completion_text"
        ;;
      zsh)
        assert_contains_text "zsh completion covers ${opt}" "$opt" "$completion_text"
        ;;
      *)
        printf 'FAIL: unknown shell for coverage check: %s\n' "$shell_name" >&2
        record_failure "unknown shell for coverage check: ${shell_name}"
        ;;
    esac
  done
}

capture_completion_mode() {
  local mode="$1"
  local out_file err_file
  out_file="$(mktemp)"
  err_file="$(mktemp)"

  if bash "$VFIO_SCRIPT" "$mode" >"$out_file" 2>"$err_file"; then
    printf '%s\n' "$(cat "$out_file")"
  else
    local rc="$?"
    printf 'FAIL: mode %s exited with rc=%s\n' "$mode" "$rc" >&2
    if [[ -s "$err_file" ]]; then
      printf '%s\n' "stderr for ${mode}: $(cat "$err_file")" >&2
    fi
    record_failure "mode ${mode} exits successfully"
    printf '%s\n' ""
  fi

  rm -f "$out_file" "$err_file"
}
help_out="$(bash "$VFIO_SCRIPT" --help 2>/dev/null || true)"
assert_non_empty "help output is non-empty" "$help_out"
mapfile -t HELP_LONG_OPTS < <(extract_help_long_options "$help_out")
if (( ${#HELP_LONG_OPTS[@]} == 0 )); then
  printf 'FAIL: no long options parsed from --help output\n' >&2
  record_failure "long options parsed from --help output"
else
  printf 'PASS: parsed %d long options from --help\n' "${#HELP_LONG_OPTS[@]}"
fi

fish_out="$(capture_completion_mode --print-fish-completion)"
assert_non_empty "fish completion output is non-empty" "$fish_out"
assert_contains_text "fish completion includes helper header" "# fish completion for" "$fish_out"
assert_contains_text "fish completion includes boot-vga-policy value list" "-a 'auto strict'" "$fish_out"
assert_shell_covers_help_options "fish" "$fish_out"

bash_out="$(capture_completion_mode --print-bash-completion)"
assert_non_empty "bash completion output is non-empty" "$bash_out"
assert_contains_text "bash completion includes function wrapper" "_vfio_sh_complete()" "$bash_out"
assert_contains_text "bash completion includes complete binding" "complete -F _vfio_sh_complete" "$bash_out"
assert_contains_text "bash completion includes boot-vga-policy values" "compgen -W \"auto strict\"" "$bash_out"
assert_shell_covers_help_options "bash" "$bash_out"

zsh_out="$(capture_completion_mode --print-zsh-completion)"
assert_non_empty "zsh completion output is non-empty" "$zsh_out"
assert_contains_text "zsh completion includes compdef header" "#compdef" "$zsh_out"
assert_contains_text "zsh completion includes _arguments block" "_arguments \\" "$zsh_out"
assert_contains_text "zsh completion includes boot-vga-policy values" ":policy:(auto strict)" "$zsh_out"
assert_shell_covers_help_options "zsh" "$zsh_out"

if (( fail != 0 )); then
  printf '\nFAIL SUMMARY (%d)\n' "${#FAILED_ASSERTIONS[@]}" >&2
  for failed_assertion in "${FAILED_ASSERTIONS[@]}"; do
    printf ' - %s\n' "$failed_assertion" >&2
  done
  exit 1
fi
printf 'Completion output regression checks passed.\n'
