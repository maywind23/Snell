#!/usr/bin/env bash
set -euo pipefail

SNELL_VERSION="v5.1.0"
SNELL_BASE_URL="https://github.com/surge-networks/snell/releases/download"
BASE_DIR="/etc/snell"
USER_DIR="$BASE_DIR/users"
DB_FILE="$BASE_DIR/users.json"
ADMIN_DIR="/opt/snell-admin"
WEB_DIR="$ADMIN_DIR/web"
CGI_DIR="$WEB_DIR/cgi-bin"
ADMIN_CONFIG="$BASE_DIR/admin.conf"
SNELL_BIN="/usr/local/bin/snell-server"
SYSTEMD_TEMPLATE="/etc/systemd/system/snell-server@.service"
HTTPD_SERVICE="/etc/systemd/system/snell-admin.service"
TRACK_CHAIN="SNELL-TRACK"
DEFAULT_ADMIN_PORT=6180

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;36m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${BLUE}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

require_root() {
    if [[ $(id -u) -ne 0 ]]; then
        log_error "This script must be run as root."
        exit 1
    fi
}

ensure_directories() {
    mkdir -p "$USER_DIR" "$CGI_DIR"
    chmod 750 "$BASE_DIR"
}

ensure_db() {
    if [[ ! -f "$DB_FILE" ]]; then
        cat <<'JSON' >"$DB_FILE"
{
  "users": []
}
JSON
    fi
}

random_token() {
    openssl rand -hex 16
}

random_psk() {
    openssl rand -base64 24 | tr -d '\n'
}

validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
        return 0
    fi
    return 1
}

read_config_value() {
    local key="$1"
    [[ -f "$ADMIN_CONFIG" ]] || return 1
    # shellcheck disable=SC1090
    source "$ADMIN_CONFIG"
    local var="${key}"
    printf '%s' "${!var}"
}

write_admin_config() {
    local admin_port="$1"
    local admin_token="$2"
    local server_host="$3"
    cat <<EOF >"$ADMIN_CONFIG"
ADMIN_PORT=${admin_port}
ADMIN_TOKEN=${admin_token}
SERVER_HOST=${server_host}
EOF
}

package_manager() {
    if command -v apt >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    else
        log_error "Unsupported distribution."
        exit 1
    fi
}

install_dependencies() {
    local pkgs=(curl jq unzip openssl iptables)
    if ! command -v busybox >/dev/null 2>&1; then
        pkgs+=(busybox)
    fi
    local pm
    pm=$(package_manager)
    log_info "Installing dependencies (${pkgs[*]})..."
    case "$pm" in
        apt)
            apt update
            DEBIAN_FRONTEND=noninteractive apt install -y "${pkgs[@]}"
            ;;
        dnf)
            dnf install -y "${pkgs[@]}"
            ;;
        yum)
            yum install -y "${pkgs[@]}"
            ;;
    esac
}

detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "aarch64"
            ;;
        armv7l)
            echo "armv7"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

download_snell() {
    local arch
    arch=$(detect_arch)
    local tmpdir
    tmpdir=$(mktemp -d)
    local url="${SNELL_BASE_URL}/${SNELL_VERSION}/snell-server-${SNELL_VERSION}-linux-${arch}.zip"
    log_info "Downloading Snell ${SNELL_VERSION} from ${url}"
    curl -fsSL "$url" -o "$tmpdir/snell.zip"
    unzip -o "$tmpdir/snell.zip" -d "$tmpdir"
    install -m 755 "$tmpdir/snell-server" "$SNELL_BIN"
    rm -rf "$tmpdir"
}

setup_systemd_template() {
    if [[ -f "$SYSTEMD_TEMPLATE" ]]; then
        return
    fi
    cat <<'SERVICE' >"$SYSTEMD_TEMPLATE"
[Unit]
Description=Snell Server instance %i
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snell-server -c /etc/snell/users/%i.conf
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
SERVICE
    systemctl daemon-reload
}

setup_admin_service() {
    local desired_port="${1:-}"
    local admin_port admin_token server_host
    if [[ -n "$desired_port" ]]; then
        if ! validate_port "$desired_port"; then
            log_error "Invalid admin port: $desired_port"
            exit 1
        fi
    fi
    if [[ -f "$ADMIN_CONFIG" ]]; then
        # shellcheck disable=SC1090
        source "$ADMIN_CONFIG"
        admin_port=${ADMIN_PORT:-$DEFAULT_ADMIN_PORT}
        admin_token=${ADMIN_TOKEN:-$(random_token)}
        server_host=${SERVER_HOST:-$(hostname -I | awk '{print $1}')}
    else
        admin_port=$DEFAULT_ADMIN_PORT
        admin_token=$(random_token)
        server_host=$(hostname -I | awk '{print $1}')
    fi
    if [[ -n "$desired_port" ]]; then
        admin_port="$desired_port"
    fi
    admin_port=${admin_port:-$DEFAULT_ADMIN_PORT}
    admin_token=${admin_token:-$(random_token)}
    server_host=${server_host:-$(hostname -I | awk '{print $1}')}
    server_host=${server_host:-127.0.0.1}
    write_admin_config "$admin_port" "$admin_token" "$server_host"
    ADMIN_PORT=$admin_port
    ADMIN_TOKEN=$admin_token

    cat <<'CGI' >"$CGI_DIR/api.sh"
#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/etc/snell"
USER_DIR="$BASE_DIR/users"
DB_FILE="$BASE_DIR/users.json"
ADMIN_CONFIG="$BASE_DIR/admin.conf"
CHAIN="SNELL-TRACK"
TMP_JSON="$(mktemp)"

cleanup() {
    rm -f "$TMP_JSON"
}
trap cleanup EXIT

urldecode() {
    local data="${1//+/ }"
    printf '%b' "${data//%/\\x}"
}

load_config() {
    # shellcheck disable=SC1090
    source "$ADMIN_CONFIG"
    ADMIN_PORT=${ADMIN_PORT:-6180}
    ADMIN_TOKEN=${ADMIN_TOKEN:-}
    SERVER_HOST=${SERVER_HOST:-$(hostname -I | awk '{print $1}')}
}

require_auth() {
    if [[ -z "${HTTP_X_AUTH_TOKEN:-}" ]]; then
        unauthorized
    fi
    if [[ "$HTTP_X_AUTH_TOKEN" != "$ADMIN_TOKEN" ]]; then
        unauthorized
    fi
}

unauthorized() {
    echo "Status: 401 Unauthorized"
    echo "Content-Type: application/json"
    echo
    echo '{"error":"unauthorized"}'
    exit 0
}

bad_request() {
    local message="${1:-invalid_request}"
    echo "Status: 400 Bad Request"
    echo "Content-Type: application/json"
    echo
    printf '{"error":"%s"}' "$message"
    exit 0
}

not_found() {
    echo "Status: 404 Not Found"
    echo "Content-Type: application/json"
    echo
    echo '{"error":"not_found"}'
    exit 0
}

json_response() {
    echo "Content-Type: application/json"
    echo
    cat
}

read_body() {
    if [[ -n "${CONTENT_LENGTH:-}" ]]; then
        dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null
    else
        cat
    fi
}

ensure_db() {
    if [[ ! -f "$DB_FILE" ]]; then
        cat <<'JSON' >"$DB_FILE"
{
  "users": []
}
JSON
    fi
}

usage_json() {
    local usage="{}"
    if command -v iptables-save >/dev/null 2>&1; then
        while read -r username bytes; do
            usage=$(jq --arg u "$username" --argjson b "$bytes" '. + {($u): $b}' <<<"$usage")
        done < <(iptables-save -c 2>/dev/null | awk '/-A SNELL-TRACK/ && /--comment "snell:/ {
            match($0, /--comment "snell:([^"\n]+)"/, comment)
            match($0, /-c ([0-9]+) ([0-9]+)/, counters)
            if (comment[1] != "" && counters[2] != "") {
                printf "%s %s\n", comment[1], counters[2]
            }
        }')
    fi
    echo "$usage"
}

list_users() {
    ensure_db
    local usage
    usage=$(usage_json)
    jq --argjson usage "$usage" '.users // [] | map(.used_bytes = ($usage[.username] // 0))' "$DB_FILE" | json_response
}

available_port() {
    local port
    for port in $(seq 10240 65100); do
        if ! ss -ltn "sport = :$port" >/dev/null 2>&1; then
            echo "$port"
            return
        fi
    done
    echo "" >&2
}

create_user() {
    ensure_db
    local body
    body=$(read_body)
    if [[ -z "$body" ]]; then
        bad_request "empty_body"
    fi
    local username
    username=$(jq -r '.username // empty' <<<"$body")
    if [[ -z "$username" ]]; then
        bad_request "missing_username"
    fi
    if jq -e --arg u "$username" '.users[]? | select(.username == $u)' "$DB_FILE" >/dev/null; then
        bad_request "user_exists"
    fi
    local port
    port=$(jq -r '.port // empty' <<<"$body")
    if [[ -z "$port" || "$port" == "null" ]]; then
        port=$(available_port)
    fi
    if [[ -z "$port" ]]; then
        bad_request "no_free_port"
    fi
    local psk
    psk=$(jq -r '.psk // empty' <<<"$body")
    if [[ -z "$psk" ]]; then
        psk=$(openssl rand -base64 24 | tr -d '\n')
    fi
    local limit_gb obfs ipv6 dns note token
    limit_gb=$(jq -r '.limit_gb // 0' <<<"$body")
    obfs=$(jq -r '.obfs // "off"' <<<"$body")
    ipv6=$(jq -r '.ipv6 // false' <<<"$body")
    dns=$(jq -r '.dns // ""' <<<"$body")
    note=$(jq -r '.note // ""' <<<"$body")
    token=$(openssl rand -hex 16)

    cat <<EOF >"$USER_DIR/$username.conf"
[snell-server]
listen = 0.0.0.0:$port
psk = $psk
obfs = $obfs
ipv6 = $ipv6
EOF
    if [[ -n "$dns" && "$dns" != "null" ]]; then
        echo "dns = $dns" >>"$USER_DIR/$username.conf"
    fi

    tmp=$(mktemp)
    jq --arg username "$username" \
       --argjson port "$port" \
       --arg psk "$psk" \
       --arg obfs "$obfs" \
       --argjson limit "$limit_gb" \
       --argjson ipv6 "$ipv6" \
       --arg dns "$dns" \
       --arg note "$note" \
       --arg token "$token" \
       --arg created "$(date -Iseconds)" \
       '.users += [{"username":$username,"port":$port,"psk":$psk,"obfs":$obfs,"limit_gb":$limit,"ipv6":$ipv6,"dns":$dns,"note":$note,"subscription_token":$token,"created_at":$created}]' "$DB_FILE" >"$tmp"
    mv "$tmp" "$DB_FILE"

    systemctl enable --now "snell-server@$username" >/dev/null 2>&1 || true

    if command -v iptables >/dev/null 2>&1; then
        iptables -C "$CHAIN" -p tcp --dport "$port" -m comment --comment "snell:$username" -j RETURN 2>/dev/null || \
        iptables -A "$CHAIN" -p tcp --dport "$port" -m comment --comment "snell:$username" -j RETURN
    fi

    jq -n --arg username "$username" --argjson port "$port" --arg psk "$psk" --arg token "$token" '{username:$username, port:$port, psk:$psk, subscription_token:$token}' | json_response
}

delete_user() {
    ensure_db
    local body username
    body=$(read_body)
    username=$(jq -r '.username // empty' <<<"$body")
    if [[ -z "$username" ]]; then
        bad_request "missing_username"
    fi
    if ! jq -e --arg u "$username" '.users[]? | select(.username == $u)' "$DB_FILE" >/dev/null; then
        not_found
    fi

    systemctl disable --now "snell-server@$username" >/dev/null 2>&1 || true
    rm -f "$USER_DIR/$username.conf"

    tmp=$(mktemp)
    jq --arg u "$username" '.users = (.users // [] | map(select(.username != $u)))' "$DB_FILE" >"$tmp"
    mv "$tmp" "$DB_FILE"

    if command -v iptables >/dev/null 2>&1; then
        while read -r num _; do
            iptables -D "$CHAIN" "$num"
            break
        done < <(iptables -L "$CHAIN" --line-numbers 2>/dev/null | awk -v u="snell:$username" '$0 ~ u {print $1, $0}')
    fi

    jq -n '{ok:true}' | json_response
}

reset_usage() {
    local body username
    body=$(read_body)
    username=$(jq -r '.username // empty' <<<"$body")
    if [[ -z "$username" ]]; then
        bad_request "missing_username"
    fi
    if command -v iptables >/dev/null 2>&1; then
        while read -r num _; do
            iptables -Z "$CHAIN" "$num"
        done < <(iptables -L "$CHAIN" --line-numbers 2>/dev/null | awk -v u="snell:$username" '$0 ~ u {print $1, $0}')
    fi
    jq -n '{ok:true}' | json_response
}

get_settings() {
    ensure_db
    local usage
    usage=$(usage_json)
    jq --argjson usage "$usage" --arg port "$ADMIN_PORT" --arg host "$SERVER_HOST" --arg token "$ADMIN_TOKEN" '{admin_port:$port, server_host:$host, admin_token:$token, subscription_base:("http://" + $host + ":" + $port + "/cgi-bin/subscribe.sh?token=")}' "$DB_FILE" >"$TMP_JSON"
    json_response <"$TMP_JSON"
}

update_settings() {
    local body new_host
    body=$(read_body)
    new_host=$(jq -r '.server_host // empty' <<<"$body")
    if [[ -z "$new_host" ]]; then
        bad_request "missing_server_host"
    fi
    cat <<EOF >"$ADMIN_CONFIG"
ADMIN_PORT=$ADMIN_PORT
ADMIN_TOKEN=$ADMIN_TOKEN
SERVER_HOST=$new_host
EOF
    jq -n --arg server_host "$new_host" '{server_host:$server_host}' | json_response
}

main() {
    load_config
    ensure_db
    require_auth
    local action=""
    if [[ -n "${QUERY_STRING:-}" ]]; then
        IFS='&' read -ra pairs <<<"$QUERY_STRING"
        for pair in "${pairs[@]}"; do
            IFS='=' read -r key value <<<"$pair"
            if [[ "$key" == "action" ]]; then
                action=$(urldecode "$value")
            fi
        done
    fi
    case "$action" in
        list-users)
            list_users
            ;;
        create-user)
            create_user
            ;;
        delete-user)
            delete_user
            ;;
        reset-usage)
            reset_usage
            ;;
        get-settings)
            get_settings
            ;;
        update-settings)
            update_settings
            ;;
        *)
            bad_request "unknown_action"
            ;;
    esac
}

main
CGI
    chmod 755 "$CGI_DIR/api.sh"

    cat <<'CGI' >"$CGI_DIR/subscribe.sh"
#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/etc/snell"
DB_FILE="$BASE_DIR/users.json"
ADMIN_CONFIG="$BASE_DIR/admin.conf"

urldecode() {
    local data="${1//+/ }"
    printf '%b' "${data//%/\\x}"
}

load_config() {
    # shellcheck disable=SC1090
    source "$ADMIN_CONFIG"
    SERVER_HOST=${SERVER_HOST:-$(hostname -I | awk '{print $1}')}
}

ensure_db() {
    if [[ ! -f "$DB_FILE" ]]; then
        echo "Status: 404 Not Found"
        echo "Content-Type: application/json"
        echo
        echo '{"error":"not_found"}'
        exit 0
    fi
}

subscription_response() {
    local token="$1"
    local data
    data=$(jq -r --arg t "$token" '.users[]? | select(.subscription_token == $t)' "$DB_FILE") || true
    if [[ -z "$data" || "$data" == "null" ]]; then
        echo "Status: 404 Not Found"
        echo "Content-Type: application/json"
        echo
        echo '{"error":"not_found"}'
        exit 0
    fi
    local username
    username=$(jq -r '.username' <<<"$data")
    local port
    port=$(jq -r '.port' <<<"$data")
    local psk
    psk=$(jq -r '.psk' <<<"$data")
    local obfs
    obfs=$(jq -r '.obfs' <<<"$data")
    local note
    note=$(jq -r '.note' <<<"$data")

    echo "Content-Type: application/json"
    echo
    jq -n --arg username "$username" --arg host "$SERVER_HOST" --argjson port "$port" --arg psk "$psk" --arg obfs "$obfs" --arg note "$note" '{type:"snell", user:$username, server:{host:$host, port:$port}, psk:$psk, obfs:$obfs, note:$note}'
}

main() {
    load_config
    ensure_db
    local token=""
    if [[ -n "${QUERY_STRING:-}" ]]; then
        IFS='&' read -ra pairs <<<"$QUERY_STRING"
        for pair in "${pairs[@]}"; do
            IFS='=' read -r key value <<<"$pair"
            if [[ "$key" == "token" ]]; then
                token=$(urldecode "$value")
            fi
        done
    fi
    if [[ -z "$token" ]]; then
        echo "Status: 400 Bad Request"
        echo "Content-Type: application/json"
        echo
        echo '{"error":"missing_token"}'
        exit 0
    fi
    subscription_response "$token"
}

main
CGI
    chmod 755 "$CGI_DIR/subscribe.sh"

    cat <<'HTML' >"$WEB_DIR/index.html"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Snell Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<link rel="stylesheet" href="/style.css" />
</head>
<body>
    <header>
        <h1>Snell Web 管理面板</h1>
        <p>管理 Snell 多用户及订阅</p>
    </header>
    <main>
        <section class="card">
            <h2>面板设置</h2>
            <div class="settings">
                <label>服务器地址
                    <input type="text" id="server-host" placeholder="example.com" />
                </label>
                <button id="save-settings">保存</button>
                <div class="token">
                    <span>管理令牌：</span>
                    <code id="admin-token"></code>
                </div>
            </div>
        </section>
        <section class="card">
            <h2>新增用户</h2>
            <form id="create-user-form">
                <div class="grid">
                    <label>用户名
                        <input type="text" name="username" required />
                    </label>
                    <label>端口
                        <input type="number" name="port" min="1" max="65535" placeholder="自动分配" />
                    </label>
                    <label>PSK
                        <input type="text" name="psk" placeholder="自动生成" />
                    </label>
                    <label>流量上限 (GB)
                        <input type="number" name="limit_gb" min="0" value="0" />
                    </label>
                    <label>Obfs
                        <select name="obfs">
                            <option value="off">关闭</option>
                            <option value="tls">TLS</option>
                            <option value="http">HTTP</option>
                        </select>
                    </label>
                    <label>DNS (可选, 逗号分隔)
                        <input type="text" name="dns" placeholder="1.1.1.1,8.8.8.8" />
                    </label>
                </div>
                <label>备注
                    <input type="text" name="note" placeholder="备注信息" />
                </label>
                <button type="submit">创建用户</button>
            </form>
        </section>
        <section class="card">
            <h2>用户列表</h2>
            <table id="users-table">
                <thead>
                    <tr>
                        <th>用户名</th>
                        <th>端口</th>
                        <th>已用流量</th>
                        <th>流量上限</th>
                        <th>订阅链接</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </section>
    </main>
    <template id="user-row-template">
        <tr>
            <td class="username"></td>
            <td class="port"></td>
            <td class="used"></td>
            <td class="limit"></td>
            <td class="subscription">
                <input type="text" readonly />
                <button class="copy">复制</button>
            </td>
            <td class="actions">
                <button class="reset">清零</button>
                <button class="delete">删除</button>
            </td>
        </tr>
    </template>
    <script src="/app.js"></script>
</body>
</html>
HTML

    cat <<'CSS' >"$WEB_DIR/style.css"
:root {
    color-scheme: light dark;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #0f172a;
    color: #e2e8f0;
}

body {
    margin: 0;
    padding: 0 1rem 2rem;
}

header {
    text-align: center;
    padding: 2rem 0 1rem;
}

h1 {
    margin: 0;
    font-size: 2.4rem;
}

main {
    max-width: 960px;
    margin: 0 auto;
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
}

.card {
    background: rgba(30, 41, 59, 0.85);
    border-radius: 1rem;
    padding: 1.5rem;
    box-shadow: 0 12px 30px rgba(15, 23, 42, 0.35);
}

.card h2 {
    margin-top: 0;
}

label {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
}

input, select, button {
    font: inherit;
    padding: 0.55rem 0.75rem;
    border-radius: 0.6rem;
    border: 1px solid rgba(148, 163, 184, 0.35);
    background: rgba(15, 23, 42, 0.6);
    color: inherit;
}

button {
    cursor: pointer;
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    border: none;
    color: white;
    transition: transform 0.15s ease, box-shadow 0.15s ease;
}

button:hover {
    transform: translateY(-1px);
    box-shadow: 0 10px 22px rgba(99, 102, 241, 0.35);
}

button:active {
    transform: translateY(1px);
}

#users-table {
    width: 100%;
    border-collapse: collapse;
}

#users-table th, #users-table td {
    border-bottom: 1px solid rgba(148, 163, 184, 0.2);
    padding: 0.75rem;
    text-align: left;
}

#users-table tbody tr:hover {
    background: rgba(30, 41, 59, 0.75);
}

#users-table input[type="text"] {
    width: 100%;
    background: rgba(15, 23, 42, 0.55);
}

.subscription {
    display: flex;
    gap: 0.5rem;
    align-items: center;
}

.subscription button {
    padding: 0.45rem 0.9rem;
}

.settings {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.settings .token {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    align-items: center;
}

@media (max-width: 720px) {
    .grid {
        grid-template-columns: 1fr;
    }
    .subscription {
        flex-direction: column;
    }
}

.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 0.75rem;
}
CSS

    cat <<'JS' >"$WEB_DIR/app.js"
(() => {
    const api = async (action, options = {}) => {
        const token = getToken();
        const headers = options.headers || {};
        headers['X-Auth-Token'] = token;
        if (options.body && !(options.body instanceof FormData)) {
            headers['Content-Type'] = 'application/json';
        }
        const response = await fetch(`/cgi-bin/api.sh?action=${encodeURIComponent(action)}`, {
            ...options,
            headers
        });
        if (!response.ok) {
            const err = await response.text();
            throw new Error(err || '请求失败');
        }
        return response.json();
    };

    const getToken = () => {
        let token = localStorage.getItem('snell-admin-token');
        if (!token) {
            token = prompt('请输入管理令牌');
            if (!token) {
                throw new Error('缺少令牌');
            }
            localStorage.setItem('snell-admin-token', token);
        }
        return token;
    };

    const fmtBytes = (bytes) => {
        if (!bytes) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let size = Number(bytes);
        let i = 0;
        while (size >= 1024 && i < units.length - 1) {
            size /= 1024;
            i++;
        }
        return `${size.toFixed(2)} ${units[i]}`;
    };

    const renderUsers = (data, settings) => {
        const tbody = document.querySelector('#users-table tbody');
        tbody.innerHTML = '';
        const template = document.querySelector('#user-row-template');
        (data || []).forEach((user) => {
            const row = template.content.cloneNode(true);
            row.querySelector('.username').textContent = user.username;
            row.querySelector('.port').textContent = user.port;
            row.querySelector('.used').textContent = fmtBytes(user.used_bytes);
            row.querySelector('.limit').textContent = user.limit_gb ? `${user.limit_gb} GB` : '不限';
            const subscriptionInput = row.querySelector('.subscription input');
            subscriptionInput.value = `${settings.subscription_base}${user.subscription_token}`;
            row.querySelector('.subscription .copy').addEventListener('click', () => {
                navigator.clipboard.writeText(subscriptionInput.value);
                alert('已复制订阅链接');
            });
            row.querySelector('.reset').addEventListener('click', async () => {
                if (!confirm(`确定要清零 ${user.username} 的流量吗？`)) return;
                await api('reset-usage', {
                    method: 'POST',
                    body: JSON.stringify({ username: user.username })
                });
                await refresh();
            });
            row.querySelector('.delete').addEventListener('click', async () => {
                if (!confirm(`确定要删除用户 ${user.username} 吗？`)) return;
                await api('delete-user', {
                    method: 'POST',
                    body: JSON.stringify({ username: user.username })
                });
                await refresh();
            });
            tbody.appendChild(row);
        });
    };

    const loadSettings = async () => {
        const settings = await api('get-settings');
        document.querySelector('#server-host').value = settings.server_host || '';
        document.querySelector('#admin-token').textContent = getToken();
        return settings;
    };

    const refresh = async () => {
        try {
            const settings = await loadSettings();
            const users = await api('list-users');
            renderUsers(users, settings);
        } catch (err) {
            console.error(err);
            alert(`加载失败: ${err.message}`);
        }
    };

    document.querySelector('#create-user-form').addEventListener('submit', async (event) => {
        event.preventDefault();
        const form = event.target;
        const formData = new FormData(form);
        const payload = Object.fromEntries(formData.entries());
        if (!payload.username) {
            alert('请输入用户名');
            return;
        }
        ['limit_gb', 'port'].forEach((key) => {
            if (payload[key]) {
                payload[key] = Number(payload[key]);
            } else {
                delete payload[key];
            }
        });
        payload.ipv6 = false;
        try {
            await api('create-user', {
                method: 'POST',
                body: JSON.stringify(payload)
            });
            form.reset();
            await refresh();
        } catch (err) {
            alert(`创建失败: ${err.message}`);
        }
    });

    document.querySelector('#save-settings').addEventListener('click', async () => {
        const host = document.querySelector('#server-host').value.trim();
        if (!host) {
            alert('请输入服务器地址');
            return;
        }
        try {
            await api('update-settings', {
                method: 'POST',
                body: JSON.stringify({ server_host: host })
            });
            alert('保存成功');
            await refresh();
        } catch (err) {
            alert(`保存失败: ${err.message}`);
        }
    });

    window.addEventListener('load', refresh);
})();
JS

    cat <<EOF >"$HTTPD_SERVICE"
[Unit]
Description=Snell Admin Web UI
After=network.target

[Service]
Type=simple
WorkingDirectory=$WEB_DIR
ExecStart=/usr/bin/env busybox httpd -f -p 0.0.0.0:${admin_port} -h $WEB_DIR
Restart=always
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF

    log_info "Snell Admin panel listening on port $admin_port"
    log_info "Admin token: $admin_token"

    systemctl daemon-reload
    systemctl enable --now snell-admin.service
}

ensure_tracking_chain() {
    if iptables -t filter -nL "$TRACK_CHAIN" >/dev/null 2>&1; then
        return
    fi
    iptables -N "$TRACK_CHAIN"
    iptables -C INPUT -p tcp -j "$TRACK_CHAIN" 2>/dev/null || iptables -I INPUT -p tcp -j "$TRACK_CHAIN"
}

install_stack() {
    local desired_port="${1:-}"
    require_root
    install_dependencies
    ensure_directories
    ensure_db
    download_snell
    setup_systemd_template
    ensure_tracking_chain
    setup_admin_service "$desired_port"
    log_info "Snell server and web UI installation completed."
    log_info "Access the panel at http://<server_ip>:${ADMIN_PORT:-$DEFAULT_ADMIN_PORT}".
}

uninstall_stack() {
    require_root
    log_warn "Stopping Snell instances..."
    if [[ -d "$USER_DIR" ]]; then
        for cfg in "$USER_DIR"/*.conf; do
            [[ -f "$cfg" ]] || continue
            name=$(basename "$cfg" .conf)
            systemctl disable --now "snell-server@$name" >/dev/null 2>&1 || true
        done
    fi
    systemctl disable --now snell-admin.service >/dev/null 2>&1 || true
    rm -f "$SYSTEMD_TEMPLATE" "$HTTPD_SERVICE"
    systemctl daemon-reload
    rm -rf "$ADMIN_DIR" "$BASE_DIR"
    if iptables -t filter -nL "$TRACK_CHAIN" >/dev/null 2>&1; then
        iptables -D INPUT -p tcp -j "$TRACK_CHAIN" 2>/dev/null || true
        iptables -F "$TRACK_CHAIN" 2>/dev/null || true
        iptables -X "$TRACK_CHAIN" 2>/dev/null || true
    fi
    rm -f "$SNELL_BIN"
    log_info "Snell server removed."
}

list_users_cli() {
    ensure_db
    jq -r '.users[]? | "- " + .username + " (port: " + (.port|tostring) + ", note: " + (.note // "") + ")"' "$DB_FILE"
}

show_admin_info() {
    if [[ ! -f "$ADMIN_CONFIG" ]]; then
        log_error "Admin config not found. Is the panel installed?"
        exit 1
    fi
    # shellcheck disable=SC1090
    source "$ADMIN_CONFIG"
    log_info "Admin panel port: ${ADMIN_PORT}"
    log_info "Admin token: ${ADMIN_TOKEN}"
    log_info "Server host: ${SERVER_HOST}"
}

cli_usage() {
    cat <<'USAGE'
Usage: ./Snell.sh <command>

Commands:
  install [--web-port <port>]  Install Snell server and web interface
  uninstall        Remove Snell server and all related files
  list-users       List configured Snell users
  admin-info       Show admin panel access information
USAGE
}

main() {
    local cmd="${1:-}"
    if [[ $# -gt 0 ]]; then
        shift
    fi
    case "$cmd" in
        install)
            local desired_port=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --web-port|--admin-port)
                        if [[ $# -lt 2 ]]; then
                            log_error "Option $1 requires a port value"
                            exit 1
                        fi
                        desired_port="$2"
                        shift 2
                        ;;
                    *)
                        log_error "Unknown option for install: $1"
                        exit 1
                        ;;
                esac
            done
            install_stack "$desired_port"
            ;;
        uninstall)
            uninstall_stack
            ;;
        list-users)
            list_users_cli
            ;;
        admin-info)
            show_admin_info
            ;;
        *)
            cli_usage
            ;;
    esac
}

main "$@"
