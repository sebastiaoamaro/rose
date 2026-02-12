#!/bin/bash
set -euo pipefail

# Prevent interactive prompts (services restarts, config-file questions)
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

log() { echo "[install.sh] $*"; }

# apt/dpkg flags (arrays so args are passed correctly)
APT_YES=(-y)
DPKG_NONINTERACTIVE=(
  -o Dpkg::Use-Pty=0
  -o Dpkg::Options::=--force-confdef
  -o Dpkg::Options::=--force-confold
)

apt_update() {
  sudo -E apt-get update >/dev/null
}

apt_install() {
  # Usage: apt_install pkg1 pkg2 ...
  sudo -E apt-get install "${APT_YES[@]}" "${DPKG_NONINTERACTIVE[@]}" "$@" >/dev/null
}

apt_dist_upgrade() {
  sudo -E apt-get dist-upgrade "${APT_YES[@]}" "${DPKG_NONINTERACTIVE[@]}" >/dev/null
}

###############################################################
#### AFTER RUNNING THIS SCRIPT, PLEASE REBOOT YOUR MACHINE ####
###############################################################

# --- Shell environment quality-of-life ---
log "Installing tmux config and WORKDIR default..."
cp /vagrant/auxiliary_scripts/tmux.conf "$HOME/.tmux.conf"
cp /vagrant/auxiliary_scripts/tmux.conf /home/vagrant/.tmux.conf

if ! grep -q 'export WORKDIR="/vagrant"' "$HOME/.bashrc"; then
  echo -e '\n# Set default working directory\nexport WORKDIR="/vagrant" && [ -d "$WORKDIR" ] && cd "$WORKDIR" || echo "Directory $WORKDIR not found"' >> "$HOME/.bashrc"
fi

# --- Git submodules ---
log "Updating git submodules..."
cd /vagrant/
git submodule update --init --recursive >/dev/null

# --- Base packages ---
log "Updating package list..."
apt_update

log "Installing base dependencies..."
apt_install \
  clang libelf1 libelf-dev zlib1g-dev libc6-dev-i386 autoconf make \
  python3 python3-pip libssl-dev\
  pcp gnuplot gcc pkg-config gcc-14 cmake llvm jq \
  linux-headers-$(uname -r) >/dev/null

#log "dist-upgrade..."
#apt_dist_upgrade

# --- Docker repo + install ---
log "Installing Docker prerequisites..."
apt_install ca-certificates curl gnupg

log "Adding Docker apt repo..."
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# shellcheck disable=SC1091
CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
ARCH="$(dpkg --print-architecture)"

echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${CODENAME} stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

apt_update

log "Installing Docker..."
apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null

log "Sanity-check Docker install (hello-world)..."
sudo docker run hello-world || true

log "Pinning Docker versions (allow downgrades)..."
sudo -E apt-get install "${APT_YES[@]}" "${DPKG_NONINTERACTIVE[@]}" --allow-downgrades \
  docker-ce="5:28.5.2-1~ubuntu.24.04~noble" \
  docker-ce-cli="5:28.5.2-1~ubuntu.24.04~noble" \
  docker-ce-rootless-extras="5:28.5.2-1~ubuntu.24.04~noble" \
  containerd.io \
  docker-buildx-plugin \
  docker-compose-plugin >/dev/null

# --- Rust toolchain ---
log "Installing Rust (rustup)..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

if ! grep -q 'cargo/env' "$HOME/.bashrc"; then
  echo 'source "$HOME/.cargo/env"' >> "$HOME/.bashrc"
fi
# shellcheck disable=SC1091
. "$HOME/.cargo/env"

log "Installing Rust 1.86.0..."
rustup install 1.86.0
rustup override set 1.86.0

# --- Git (explicit) ---
log "Ensuring git is installed..."
apt_install git

# --- libbpf ---
log "Building libbpf..."
cd /vagrant/libbpf/src
make >/dev/null
sudo make install

# --- bpftool ---
log "Setting up bpftool..."
cd /vagrant/bpftool
git reset --hard HEAD
git submodule update --init --recursive >/dev/null

cd libbpf
git checkout master >/dev/null 2>&1 || git checkout -b master >/dev/null
git pull origin master >/dev/null 2>&1 || true

cd src
log "Building libbpf for bpftool..."
make clean >/dev/null
make >/dev/null

cd ../..
cd src
log "Building bpftool..."
make clean >/dev/null
make >/dev/null
sudo make install
export PATH=/usr/local/bin:$PATH

# --- Kernel module deps + dwarves build ---
log "Setting up kernel module dependencies..."
cd /vagrant/executor/kernelmodule
apt_install -qq libdw1 dwarves elfutils libdw-dev pahole libdwarf-dev

sudo cp /sys/kernel/btf/vmlinux "/usr/lib/modules/$(uname -r)/build/"

log "Building dwarves..."
cd dwarves
git config --global --add safe.directory /rose/executor/kernelmodule/dwarves
git submodule update --init --recursive
mkdir -p build
cd build
cmake ..
make
sudo make install
sudo ldconfig

# --- Build vmlinux.h ---
log "Building vmlinux.h..."
cd /vagrant/tracer/src/bpf
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# --- Build tracer ---
log "Building tracer (cargo --release)..."
cd /vagrant/tracer/
cargo build --release

# --- Docker group (non-fatal if already exists) ---
log "Adding user to docker group..."
sudo groupadd docker 2>/dev/null || true
sudo usermod -aG docker "$USER"

log "Done. Reboot recommended."
