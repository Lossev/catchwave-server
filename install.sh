#!/usr/bin/env bash
# Установка CatchWave server на Ubuntu / Debian / Kali.
#
#   sudo bash install.sh            установить или обновить (пароль и сертификат сохраняются)
#   sudo bash install.sh show       ещё раз показать адрес, порт и QR-код
#   sudo bash install.sh password   задать новый пароль
#
# Переменные окружения: CATCHWAVE_PORT (по умолчанию 8443), CATCHWAVE_HOST (внешний адрес VPS),
# CATCHWAVE_PASSWORD (пароль; иначе установщик спросит его или придумает сам).
set -euo pipefail

PORT="${CATCHWAVE_PORT:-8443}"
SERVICE_USER=catchwave
HOME_DIR=/srv/catchwave
MUSIC_DIR="$HOME_DIR/music"
CONF_DIR=/etc/catchwave
APP_DIR=/opt/catchwave
APP="$APP_DIR/catchwave_server.py"
UNIT=/etc/systemd/system/catchwave.service
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Запустите через sudo: sudo bash install.sh" >&2
    exit 1
fi

show() {
    local host port token pin
    host="$(cat "$CONF_DIR/host")"
    port="$(cat "$CONF_DIR/port")"
    read -r token pin < <(python3 "$APP" --print-token --auth-file "$CONF_DIR/auth" --cert "$CONF_DIR/cert.pem")
    echo
    echo "=== Данные для подключения CatchWave ==="
    echo "Адрес:   $host"
    echo "Порт:    $port"
    echo "Пароль:  тот, что задан при установке (сменить: sudo bash install.sh password)"
    echo
    if command -v qrencode >/dev/null; then
        echo "Или отсканируйте QR-код в приложении — тогда пароль вводить не нужно:"
        qrencode -t ANSIUTF8 "catchwave://connect?host=$host&port=$port&token=$token&pin=$pin"
    fi
    echo "Папка для музыки на сервере: $MUSIC_DIR"
    echo "QR-код даёт такой же доступ, как пароль. Не публикуйте его."
}

# Записывает auth-файл по паролю из $1.
write_auth() {
    local line
    line="$(printf '%s\n' "$1" | python3 "$APP" --make-auth)"
    (umask 027; printf '%s\n' "$line" > "$CONF_DIR/auth")
    chown root:"$SERVICE_USER" "$CONF_DIR/auth"
    chmod 0640 "$CONF_DIR/auth"
}

# Спрашивает пароль дважды и кладёт его в переменную PASSWORD.
ask_password() {
    local again
    while true; do
        read -r -s -p "Придумайте пароль для приложения (минимум 8 символов): " PASSWORD; echo
        if [ "${#PASSWORD}" -lt 8 ]; then echo "Слишком короткий."; continue; fi
        read -r -s -p "Повторите пароль: " again; echo
        if [ "$PASSWORD" = "$again" ]; then break; fi
        echo "Пароли не совпадают."
    done
}

case "${1:-}" in
show)
    show
    exit 0
    ;;
password)
    PASSWORD="${CATCHWAVE_PASSWORD:-}"
    if [ -z "$PASSWORD" ]; then ask_password; fi
    write_auth "$PASSWORD"
    systemctl restart catchwave.service
    echo "Пароль изменён. В приложении нужно выйти и подключиться заново."
    exit 0
    ;;
esac

for tool in python3 openssl systemctl; do
    command -v "$tool" >/dev/null || { echo "Не найдено: $tool. Установите его и повторите." >&2; exit 1; }
done

# qrencode нужен только для показа QR-кода; без него установка всё равно продолжится.
if ! command -v qrencode >/dev/null && command -v apt-get >/dev/null; then
    apt-get install -y qrencode >/dev/null 2>&1 || true
fi

HOST="${CATCHWAVE_HOST:-}"
if [ -z "$HOST" ] && [ -f "$CONF_DIR/host" ]; then HOST="$(cat "$CONF_DIR/host")"; fi
if [ -z "$HOST" ]; then
    HOST="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}')"
fi
if [ -z "$HOST" ]; then
    echo "Не удалось определить адрес сервера. Укажите его: sudo CATCHWAVE_HOST=1.2.3.4 bash install.sh" >&2
    exit 1
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$HOME_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# Папка с музыкой закрыта для всех, кроме сервиса и группы catchwave.
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$HOME_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 2770 "$MUSIC_DIR"
install -d -o root -g "$SERVICE_USER" -m 0750 "$CONF_DIR"
install -d -o root -g root -m 0755 "$APP_DIR"
install -o root -g root -m 0644 "$SOURCE_DIR/catchwave_server.py" "$APP"

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    usermod -aG "$SERVICE_USER" "$SUDO_USER"
fi

umask 027
if [ ! -s "$CONF_DIR/cert.pem" ] || [ ! -s "$CONF_DIR/key.pem" ]; then
    if [[ "$HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then SAN="IP:$HOST"; else SAN="DNS:$HOST"; fi
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -nodes -days 3650 \
        -subj "/CN=CatchWave" -addext "subjectAltName=$SAN" \
        -keyout "$CONF_DIR/key.pem" -out "$CONF_DIR/cert.pem" 2>/dev/null
fi

GENERATED=""
if [ -n "${CATCHWAVE_PASSWORD:-}" ]; then
    write_auth "$CATCHWAVE_PASSWORD"
elif [ ! -s "$CONF_DIR/auth" ]; then
    if [ -t 0 ]; then
        ask_password
    else
        PASSWORD="$(python3 "$APP" --make-password)"
        GENERATED="$PASSWORD"
    fi
    write_auth "$PASSWORD"
fi
# Токен из первой версии сервера больше не используется.
rm -f "$CONF_DIR/token"

echo "$HOST" > "$CONF_DIR/host"
echo "$PORT" > "$CONF_DIR/port"
chown root:"$SERVICE_USER" "$CONF_DIR"/cert.pem "$CONF_DIR"/key.pem "$CONF_DIR"/host "$CONF_DIR"/port
chmod 0640 "$CONF_DIR"/key.pem

cat > "$UNIT" <<EOF
[Unit]
Description=CatchWave music server
After=network-online.target
Wants=network-online.target

[Service]
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=/usr/bin/env python3 $APP --music-dir $MUSIC_DIR --auth-file $CONF_DIR/auth --cert $CONF_DIR/cert.pem --key $CONF_DIR/key.pem --port $PORT
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
CapabilityBoundingSet=
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT"

systemctl daemon-reload
systemctl enable --quiet catchwave.service
systemctl restart catchwave.service

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "$PORT/tcp" >/dev/null
    echo "Порт $PORT открыт в ufw."
fi

sleep 1
if systemctl is-active --quiet catchwave.service; then
    echo "Сервер запущен."
else
    echo "Сервер не запустился. Смотрите журнал: journalctl -u catchwave -n 50" >&2
    exit 1
fi
show
if [ -n "$GENERATED" ]; then
    echo
    echo "Пароль придуман автоматически, запишите его — больше он показан не будет:"
    echo "    $GENERATED"
fi
