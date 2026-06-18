#!/usr/bin/env bash
set -euo pipefail

out_file="${1:?missing output file}"
baseline_path="${2:?missing baseline path}"
xdg_cache_home="${XDG_CACHE_HOME:-$HOME/.cache}"

probe_nonempty_dir() {
  local name="$1"
  local path="$2"
  if [ -d "$path" ] && find "$path" -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
    echo "${name}_present=true" >> "$out_file"
  else
    echo "${name}_present=false" >> "$out_file"
  fi
}

probe_nonempty_files() {
  local name="$1"
  shift
  local path
  for path in "$@"; do
    if [ ! -s "$path" ]; then
      echo "${name}_present=false" >> "$out_file"
      return
    fi
  done
  echo "${name}_present=true" >> "$out_file"
}

probe_nonempty_dir "grype" "$xdg_cache_home/grype/db"
probe_nonempty_files "vulnix" "$HOME/.cache/vulnix/Data.fs" "$HOME/.cache/vulnix/Data.fs.index"
probe_nonempty_files "sbomnix" "$xdg_cache_home/sbomnix/http_cache.sqlite"
probe_nonempty_files "baseline" "$baseline_path"
