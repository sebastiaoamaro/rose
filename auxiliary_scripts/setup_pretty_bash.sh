#!/usr/bin/env bash
set -euo pipefail

# Ubuntu bootstrap:
# - Installs: starship, fzf, bash-completion, ble.sh deps
# - Installs ble.sh into ~/.local
# - Sets up ~/.inputrc (menu completion)
# - Enables fzf keybindings + completion, starship, ble.sh in ~/.bashrc
# - Installs Nord dircolors + activates it from ~/.bashrc
# - Copies tmux.conf from /vagrant/auxiliary_scripts/tmux.conf if present
# - Instead of generating starship.toml and bashrc content:
#     uses files located in the SAME FOLDER as this script:
#       ./starship.toml  ->  ~/.config/starship.toml
#       ./bashrc         ->  ~/.bashrc   (backs up existing)

log() { printf '%s\n' "$*" >&2; }

need_cmd() { command -v "$1" >/dev/null 2>&1; }

backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    local ts
    ts="$(date +%Y%m%d-%H%M%S)"
    cp -a "$f" "${f}.bak.${ts}"
    log "Backed up $f -> ${f}.bak.${ts}"
  fi
}

script_dir() {
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1
  pwd -P
}

require_ubuntu_like() {
  [[ -f /etc/os-release ]] || { log "Cannot detect OS. Intended for Ubuntu."; exit 1; }
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" && "${ID_LIKE:-}" != *"debian"* ]]; then
    log "Warning: detected ID=${ID:-?}. Script is intended for Ubuntu/Debian-like."
  fi
}

install_apt_packages() {
  log "Installing apt packages..."
  sudo apt update
  sudo apt install -y \
    curl git build-essential gawk \
    bash-completion fzf
}

install_starship() {
  if need_cmd starship; then
    log "Starship already installed: $(command -v starship)"
    return 0
  fi
  log "Installing Starship..."
  curl -fsSL https://starship.rs/install.sh | sh -s -- -y
  need_cmd starship || { log "Starship installed but not found in PATH."; return 1; }
}

install_blesh() {
  local repo="$HOME/.local/share/ble.sh"
  local prefix="$HOME/.local"

  if [[ -f "$HOME/.local/share/blesh/ble.sh" ]]; then
    log "ble.sh already installed at ~/.local/share/blesh/ble.sh"
    return 0
  fi

  log "Installing ble.sh..."
  mkdir -p "$HOME/.local/share"
  if [[ ! -d "$repo/.git" ]]; then
    git clone --depth=1 https://github.com/akinomyoga/ble.sh.git "$repo"
  else
    git -C "$repo" pull --ff-only
  fi

  make -C "$repo" install PREFIX="$prefix"
  [[ -f "$HOME/.local/share/blesh/ble.sh" ]] || { log "ble.sh install failed (ble.sh not found)."; return 1; }
}

setup_inputrc() {
  local inputrc="$HOME/.inputrc"
  backup_file "$inputrc"

  cat >"$inputrc" <<'EOF'
# ~/.inputrc
# Readline settings (Bash line editing & completion)

# Better completion UX
set show-all-if-ambiguous on
set menu-complete-display-prefix on
set completion-ignore-case on

# Use TAB to cycle through matches
TAB: menu-complete
EOF

  log "Wrote $inputrc"
}

install_nord_dircolors() {
  log "Installing Nord dircolors..."
  mkdir -p "$HOME/.config/dircolors"
  curl -fsSL "https://raw.githubusercontent.com/arcticicestudio/nord-dircolors/develop/src/dir_colors" \
    -o "$HOME/.config/dircolors/dircolors.nord"
  log "Wrote $HOME/.config/dircolors/dircolors.nord"
}

install_starship_toml_from_local() {
  local dir
  dir="$(script_dir)"
  local src="$dir/starship.toml"
  local dst="$HOME/.config/starship.toml"

  if [[ ! -f "$src" ]]; then
    log "ERROR: Expected $src next to this script."
    log "Place your starship.toml in the same folder as the script."
    exit 1
  fi

  mkdir -p "$HOME/.config"
  backup_file "$dst"
  cp "$src" "$dst"
  log "Installed Starship config: $src -> $dst"
}

install_bashrc_from_local() {
  local dir
  dir="$(script_dir)"
  local src="$dir/.bashrc"
  local dst="$HOME/.bashrc"

  if [[ ! -f "$src" ]]; then
    log "ERROR: Expected $src next to this script."
    log "Place your bashrc file in the same folder as the script (named 'bashrc')."
    exit 1
  fi

  backup_file "$dst"
  cp "$src" "$dst"
  log "Installed Bash config: $src -> $dst"
}

install_tmux_config_from_vagrant() {
  log "Installing tmux config and WORKDIR default..."
  local src="/vagrant/auxiliary_scripts/tmux.conf"

  if [[ ! -f "$src" ]]; then
    log "Skipping tmux.conf copy: $src not found."
    return 0
  fi

  backup_file "$HOME/.tmux.conf"
  cp "$src" "$HOME/.tmux.conf"
  log "Copied $src -> $HOME/.tmux.conf"

  if [[ -d /home/vagrant ]]; then
    if [[ "$(id -u)" -eq 0 ]]; then
      backup_file "/home/vagrant/.tmux.conf"
      cp "$src" /home/vagrant/.tmux.conf
      chown vagrant:vagrant /home/vagrant/.tmux.conf 2>/dev/null || true
      log "Copied $src -> /home/vagrant/.tmux.conf"
    elif need_cmd sudo; then
      sudo bash -lc "
        set -e
        if [ -d /home/vagrant ]; then
          if [ -f /home/vagrant/.tmux.conf ]; then cp -a /home/vagrant/.tmux.conf /home/vagrant/.tmux.conf.bak.\$(date +%Y%m%d-%H%M%S); fi
          cp '$src' /home/vagrant/.tmux.conf
          chown vagrant:vagrant /home/vagrant/.tmux.conf || true
        fi
      "
      log "Copied $src -> /home/vagrant/.tmux.conf (via sudo)"
    else
      log "Cannot write /home/vagrant/.tmux.conf (no sudo). Skipping."
    fi
  fi
}

main() {
  require_ubuntu_like

  install_apt_packages
  install_starship
  install_blesh

  setup_inputrc
  install_nord_dircolors

  # Config files from script folder
  install_starship_toml_from_local
  install_bashrc_from_local

  # Your vagrant tmux copy step
  install_tmux_config_from_vagrant

  log ""
  log "Done. Apply changes with:"
  log "  exec bash"
  log "If you're in tmux and changed tmux.conf:"
  log "  tmux source-file ~/.tmux.conf"
}

main "$@"
