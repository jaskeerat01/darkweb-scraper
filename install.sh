#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC} $1" >&2; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1" >&2; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1" >&2; }
log_err()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_step()  { echo -e "\n${BOLD}${BLUE}>>> $1${NC}" >&2; }

check_port() {
    local host="$1"
    local port="$2"
    timeout 2 bash -c "</dev/tcp/${host}/${port}" 2>/dev/null && return 0
    python3 -c "import socket; s = socket.socket(); s.settimeout(2); s.connect(('${host}', int('${port}'))); s.close()" 2>/dev/null && return 0
    return 1
}

if [ "$EUID" -ne 0 ]; then
    log_err "This deployment script must be run as root (use sudo)."
    exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${APP_DIR}/.venv"
SERVICE_USER="${SUDO_USER:-$USER}"

if [ "$SERVICE_USER" = "root" ]; then
    SERVICE_USER="scraper"
    if ! id -u scraper &>/dev/null; then
        log_info "Creating dedicated unprivileged service user 'scraper'..."
        useradd -m -s /bin/bash scraper
    fi
fi

# Ensure data and models folders exist
mkdir -p "${APP_DIR}/data" "${APP_DIR}/models"

# Migrate legacy root files into structured data/ directories if present
[ -f "${APP_DIR}/forum_sites.csv" ] && [ ! -f "${APP_DIR}/data/forum_sites.csv" ] && mv "${APP_DIR}/forum_sites.csv" "${APP_DIR}/data/forum_sites.csv"
[ -f "${APP_DIR}/alerts.db" ] && [ ! -f "${APP_DIR}/data/alerts.db" ] && mv "${APP_DIR}/alerts.db"* "${APP_DIR}/data/" 2>/dev/null || true
[ -f "${APP_DIR}/qwen2.5-1.5b-instruct-q4_k_m.gguf" ] && [ ! -f "${APP_DIR}/models/qwen2.5-1.5b-instruct-q4_k_m.gguf" ] && mv "${APP_DIR}/qwen2.5-1.5b-instruct-q4_k_m.gguf" "${APP_DIR}/models/"

chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}/data" "${APP_DIR}/models"

# ==============================================================================
# STEP 1: Interactive Prompts
# ==============================================================================
echo "" >&2
echo -e "${BOLD}${CYAN}================================================================${NC}" >&2
echo -e "${BOLD}${CYAN}      DARK WEB THREAT INTEL ENGINE                              ${NC}" >&2
echo -e "${BOLD}${CYAN}================================================================${NC}" >&2

read -r -p "Enter Tor Control Password (press ENTER to auto-generate): " USER_TOR_PW
if [ -z "${USER_TOR_PW}" ]; then
    TOR_PASSWORD=$(openssl rand -hex 16)
    log_ok "Auto-generated secure Tor Control Password: ${TOR_PASSWORD}"
else
    TOR_PASSWORD="${USER_TOR_PW}"
    log_ok "Using user-specified Tor Control Password."
fi

read -r -p "Install and start scraper as a systemd background service? [y/N]: " INSTALL_SYSTEMD_INPUT
INSTALL_SYSTEMD_INPUT=${INSTALL_SYSTEMD_INPUT,,}
INSTALL_SYSTEMD="n"
if [[ "${INSTALL_SYSTEMD_INPUT}" =~ ^(y|yes)$ ]]; then
    INSTALL_SYSTEMD="y"
fi

read -r -p "Enter link discovery depth [default: 2]: " DEPTH_INPUT
PAGE_DEPTH=${DEPTH_INPUT:-2}
read -r -p "Enter max pages to scrape per site [default: 50]: " PAGES_INPUT
MAX_PAGES=${PAGES_INPUT:-50}

read -r -p "Enter TELEGRAM_BOT_TOKEN (press ENTER to skip): " TG_TOKEN
read -r -p "Enter TELEGRAM_CHAT_ID (press ENTER to skip): " TG_CHAT_ID

# ==============================================================================
# STEP 2: System Packages & Astral uv Engine
# ==============================================================================
log_step "Installing System Dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
    build-essential cmake curl wget git tor torsocks \
    python3 python3-dev libxml2-dev libxslt1-dev zlib1g-dev \
    libssl-dev libopenblas-dev ufw net-tools jq ca-certificates

if ! command -v uv &>/dev/null; then
    log_info "Installing Astral uv binary..."
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh
fi
export PATH="/usr/local/bin:${PATH}"

# ==============================================================================
# STEP 3: Tor Configuration
# ==============================================================================
log_step "Configuring Tor Daemon Policies (/etc/tor/torrc)"
TOR_PW_HASH=$(tor --hash-password "${TOR_PASSWORD}" | tail -n 1 | tr -d '\r\n')

cat <<EOF > /etc/tor/torrc
User debian-tor
DataDirectory /var/lib/tor
ControlPort 127.0.0.1:9051
SocksPort 127.0.0.1:9050
HashedControlPassword ${TOR_PW_HASH}
CookieAuthentication 0
SocksPolicy accept 127.0.0.1
SocksPolicy reject *
EOF

systemctl restart tor

TOR_BOUND=false
for _ in {1..15}; do
    if check_port "127.0.0.1" "9050" && check_port "127.0.0.1" "9051"; then
        TOR_BOUND=true
        break
    fi
    sleep 1
done

if [ "$TOR_BOUND" = false ]; then
    log_err "Tor daemon failed to bind ports 9050/9051."
    exit 1
fi
log_ok "Tor daemon active and authenticated."

# ==============================================================================
# STEP 4: Firewall (UFW)
# ==============================================================================
log_step "Hardening Host Firewall (UFW)"
SSH_PORT=$(ss -tlnp | grep -oP '(?<=:)\d+(?=\s+.*sshd)' | head -n1 || true)
[ -z "${SSH_PORT}" ] && SSH_PORT=22

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow in on lo
ufw allow "${SSH_PORT}"/tcp comment "SSH"
ufw --force enable
log_ok "UFW active: loopback locked down."

# ==============================================================================
# STEP 5: Circuit Audit
# ==============================================================================
log_step "Auditing Tor Circuit"
TOR_RESP=$(curl -s --max-time 25 --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip || true)
IS_TOR=$(echo "${TOR_RESP}" | grep -o '"IsTor":\s*true' || true)

if [ -z "${IS_TOR}" ]; then
    log_err "CRITICAL FAILURE: Tor SOCKS endpoint failed validation."
    exit 1
fi
log_ok "Tor SOCKS circuit validated: (IsTor: true)."

# ==============================================================================
# STEP 6: Virtualenv & Modular Package Installation
# ==============================================================================
log_step "Installing Python Dependencies via Astral uv"
rm -rf "${VENV_DIR}"
sudo -u "${SERVICE_USER}" uv venv "${VENV_DIR}"
PYTHON_BIN="${VENV_DIR}/bin/python"

HAS_CUDA=false
if command -v nvidia-smi &>/dev/null && nvidia-smi &>/dev/null; then
    HAS_CUDA=true
fi

if [ "$HAS_CUDA" = true ]; then
    export CMAKE_ARGS="-DGGML_CUDA=on"
    export FORCE_CMAKE=1
    sudo -E -u "${SERVICE_USER}" uv pip install --python "${PYTHON_BIN}" "llama-cpp-python>=0.3.0" --upgrade --no-cache
    LLM_LAYERS=33
else
    sudo -u "${SERVICE_USER}" uv pip install --python "${PYTHON_BIN}" "llama-cpp-python>=0.3.0" --upgrade
    LLM_LAYERS=0
fi

# Install the application as an editable package with its dependencies
sudo -u "${SERVICE_USER}" uv pip install --python "${PYTHON_BIN}" -r "${APP_DIR}/requirements.txt"
sudo -u "${SERVICE_USER}" uv pip install --python "${PYTHON_BIN}" -e "${APP_DIR}"
log_ok "Application installed in editable mode."

# ==============================================================================
# STEP 7: GGUF Model Setup
# ==============================================================================
log_step "Verifying Local GGUF LLM Model"
MODEL_FILE="${APP_DIR}/models/qwen2.5-1.5b-instruct-q4_k_m.gguf"
MODEL_URL="https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf"

if [ -f "${MODEL_FILE}" ] && [ "$(head -c 4 "${MODEL_FILE}")" = "GGUF" ]; then
    log_ok "GGUF model binary verified at ${MODEL_FILE}"
else
    log_info "Downloading Qwen2.5-1.5B-Instruct-GGUF to models/ ..."
    sudo -u "${SERVICE_USER}" curl -L -C - --progress-bar -o "${MODEL_FILE}" "${MODEL_URL}"
    if [ "$(head -c 4 "${MODEL_FILE}")" != "GGUF" ]; then
        log_err "Downloaded file failed GGUF validation."
        exit 1
    fi
fi

# ==============================================================================
# STEP 8: Environment Configuration & Data Seeding
# ==============================================================================
log_step "Writing .env Configuration"
ENV_FILE="${APP_DIR}/.env"

cat <<EOF > "${ENV_FILE}"
TOR_HOST=127.0.0.1
TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051
TOR_CONTROL_PASSWORD=${TOR_PASSWORD}
TOR_NEWNYM_MIN_INTERVAL=10

ALLOW_CLEARNET_TARGETS=false
REDACT_URLS_IN_LOGS=false
INCLUDE_SOURCE_URL_IN_ALERTS=true

TELEGRAM_BOT_TOKEN=${TG_TOKEN}
TELEGRAM_CHAT_ID=${TG_CHAT_ID}
TELEGRAM_PROXY=

GGUF_MODEL_PATH=${MODEL_FILE}
LLM_CONTEXT=4096
LLM_THREADS=$(nproc)
LLM_GPU_LAYERS=${LLM_LAYERS}
LLM_TEMPERATURE=0.1
LLM_PREFILTER_KEYWORDS=true
KEYWORDS="data breach,exploit,crypto,leak,0day,ransomware,victim"

DB_PATH=${APP_DIR}/data/alerts.db
CSV_PATH=${APP_DIR}/data/forum_sites.csv
DATA_RETENTION_DAYS=500

MAX_PARALLEL_SITES=3
MAX_PARALLEL_FETCHES=3
MAX_PARALLEL_HEALTH=6
MAX_LLM_WORKERS=1
MAX_FETCHES_PER_DOMAIN=1

PAGE_DISCOVERY_ENABLED=true
MAX_PAGES_PER_SITE=${MAX_PAGES}
PAGE_DISCOVERY_DEPTH=${PAGE_DEPTH}
MAX_LINKS_PER_PAGE=25
MIN_LINK_SCORE=-10
FOLLOW_EXTERNAL_LINKS=false
MAX_EXTERNAL_LINKS_PER_SITE=2
REQUIRE_RELEVANCE=true
THREAD_FIRST_PAGE_ONLY=true
FIRST_POST_ONLY=true
SUMMARIZE_ALERTS=true

HEALTH_TIMEOUT=15
REQUEST_TIMEOUT=60
MAX_FAILURES=2
MAX_RESPONSE_BYTES=5242880
EOF

chown "${SERVICE_USER}:${SERVICE_USER}" "${ENV_FILE}"
chmod 600 "${ENV_FILE}"

CSV_FILE="${APP_DIR}/data/forum_sites.csv"
if [ ! -f "${CSV_FILE}" ]; then
    cat <<EOF > "${CSV_FILE}"
Name,Type,URL,Status,LastScrape,Uptime30,PageTitle
darkforums,market,http://darkfoxaqhfpxkrbt7vxns2z2u2k72sgmqbzeorupaiottw3ecm2wgyd.onion/,online,08-14-26,97,DarkForums
BreachForums,market,http://breached4wtyw5fb45zj7sggnoazgv3aohme2zftkrndhvo76d5q5uad.onion,online,08-14-26,97,BreachForums
RaidForums,market,http://raiddfzn73ir6iyxlf7nwytnujiflddog75yhtyk2y6qr3sbtvds7hqd.onion,online,08-14-26,94,RaidForums
EOF
    chown "${SERVICE_USER}:${SERVICE_USER}" "${CSV_FILE}"
fi

# Run test suite to guarantee regression-free refactoring
log_step "Running Test Suite"
sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/pytest" "${APP_DIR}/tests" -v
log_ok "All unit tests passed successfully."

# ==============================================================================
# STEP 9: Systemd Daemon
# ==============================================================================
if [ "${INSTALL_SYSTEMD}" = "y" ]; then
    log_step "Registering Systemd Daemon"
    SERVICE_UNIT="/etc/systemd/system/darkweb-scraper.service"

    cat <<EOF > "${SERVICE_UNIT}"
[Unit]
Description=Dark Web Threat Intelligence Engine
After=network.target tor.service
Wants=tor.service

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${PYTHON_BIN} -m scraper
Restart=always
RestartSec=15

ProtectSystem=full
ProtectHome=false
NoNewPrivileges=true
PrivateTmp=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable darkweb-scraper.service
    systemctl restart darkweb-scraper.service
    log_ok "Systemd service 'darkweb-scraper' running."
fi

echo "" >&2
echo -e "${BOLD}${GREEN}================================================================${NC}" >&2
echo -e "${BOLD}${GREEN}           DEPLOYMENT COMPLETE                                  ${NC}" >&2
echo -e "${BOLD}${GREEN}================================================================${NC}" >&2
echo -e "Module Entrypoint:     ${CYAN}python3 -m scraper${NC} (or ${CYAN}./main.py${NC})" >&2
echo -e "Database Path:         ${YELLOW}${APP_DIR}/data/alerts.db${NC}" >&2
echo -e "Target CSV:            ${YELLOW}${APP_DIR}/data/forum_sites.csv${NC}" >&2
echo -e "Local Model:           ${YELLOW}${MODEL_FILE}${NC}" >&2
echo -e "${BOLD}${GREEN}================================================================${NC}" >&2