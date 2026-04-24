#!/usr/bin/env bash
set -euo pipefail

###################################################################
# TLS 1.3 Benchmark in Linux Network Namespaces
#
# Modes:
#   classic        = ECDSA P-256 + X25519
#   classic-rsa    = RSA-3072 + X25519
#   hybrid-kem     = ECDSA P-256 + X25519+MLKEM768
#   hybrid-full    = P256+MLDSA + X25519+MLKEM768
#   pqc            = MLDSA + MLKEM768
###################################################################

MODE="classic"
DELAY_MS=0
RATE_MBIT=0
MTU=1500
TIME_SECONDS=5
PCAP_LIMIT=5000
BASE_PORT=4440

# Script/log path handling (dynamic)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$(dirname "$SCRIPT_DIR")/log_ns"
mkdir -p "$LOG_DIR"
RESULT_CSV="$LOG_DIR/results_tls_bench_ns.csv"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --delay-ms) DELAY_MS="$2"; shift 2;;
    --rate-mbit) RATE_MBIT="$2"; shift 2;;
    --mtu) MTU="$2"; shift 2;;
    --time) TIME_SECONDS="$2"; shift 2;;
    --pcap-limit) PCAP_LIMIT="$2"; shift 2;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

# OQS OpenSSL paths
OQS=/usr/local/openssl/bin/openssl
OQS_MOD=/usr/local/openssl/lib64/ossl-modules
[[ -x "$OQS" ]] || { echo "❌ OQS OpenSSL not found at $OQS"; exit 1; }

TS=$(date +%s)

###################################################################
# Certificate helper functions
###################################################################

cert_ecdsa() {
  ip netns exec ns_srv openssl ecparam -name prime256v1 -genkey -noout -out /tmp/server.key
  ip netns exec ns_srv openssl req -new -x509 -key /tmp/server.key -subj "/CN=ns-server" \
    -out /tmp/server.crt -days 365
}

cert_rsa() {
  ip netns exec ns_srv openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out /tmp/server.key
  ip netns exec ns_srv openssl req -new -x509 -key /tmp/server.key -subj "/CN=ns-server" \
    -out /tmp/server.crt -days 365
}

write_oqs_conf_srv() {
  ip netns exec ns_srv bash -c "cat > /tmp/oqs_srv.cnf <<EOF
openssl_conf = init
[init]
providers = providers
ssl_conf   = sslsec
[providers]
default = default_sect
oqsprovider = oqs_sect
[default_sect]
activate = 1
[oqs_sect]
activate = 1
module = $OQS_MOD/oqsprovider.so
[sslsec]
system_default = sysdefault
[sysdefault]
Groups = $TLS_GROUPS
EOF"
}

write_oqs_conf_cli() {
  ip netns exec ns_cli bash -c "cat > /tmp/oqs_cli.cnf <<EOF
openssl_conf = init
[init]
providers = providers
ssl_conf   = sslsec
[providers]
default = default_sect
oqsprovider = oqs_sect
[default_sect]
activate = 1
[oqs_sect]
activate = 1
module = $OQS_MOD/oqsprovider.so
[sslsec]
system_default = sysdefault
[sysdefault]
Groups = $TLS_GROUPS
SignatureAlgorithms = ML-DSA-44:Dilithium2
EOF"
}

cert_pqc() {
  write_oqs_conf_srv
  ip netns exec ns_srv env OPENSSL_CONF=/tmp/oqs_srv.cnf OPENSSL_MODULES=$OQS_MOD \
    $OQS req -new -x509 -newkey mldsa44 \
      -keyout /tmp/server.key -out /tmp/server.crt \
      -subj "/CN=ns-server" -nodes -days 365 \
      -provider default -provider oqsprovider >/dev/null 2>&1 \
  || ip netns exec ns_srv env OPENSSL_CONF=/tmp/oqs_srv.cnf OPENSSL_MODULES=$OQS_MOD \
      $OQS req -new -x509 -newkey dilithium2 \
        -keyout /tmp/server.key -out /tmp/server.crt \
        -subj "/CN=ns-server" -nodes -days 365 \
        -provider default -provider oqsprovider
}

cert_hybrid_full() {
  write_oqs_conf_srv
  ip netns exec ns_srv env OPENSSL_CONF=/tmp/oqs_srv.cnf OPENSSL_MODULES=$OQS_MOD \
    $OQS req -new -x509 -newkey p256_mldsa44 \
      -keyout /tmp/server.key -out /tmp/server.crt \
      -subj "/CN=ns-server" -nodes -days 365 \
      -provider default -provider oqsprovider >/dev/null 2>&1 \
  || ip netns exec ns_srv env OPENSSL_CONF=/tmp/oqs_srv.cnf OPENSSL_MODULES=$OQS_MOD \
      $OQS req -new -x509 -newkey p256_dilithium2 \
        -keyout /tmp/server.key -out /tmp/server.crt \
        -subj "/CN=ns-server" -nodes -days 365 \
        -provider default -provider oqsprovider
}

###################################################################
# Mode selection
###################################################################

case "$MODE" in
  classic)
    TLS_GROUPS="X25519";         CERT_FUNC="cert_ecdsa";       TITLE="ns-classic";;
  classic-rsa)
    TLS_GROUPS="X25519";         CERT_FUNC="cert_rsa";         TITLE="ns-classic-rsa";;
  hybrid-kem)
    TLS_GROUPS="X25519MLKEM768"; CERT_FUNC="cert_ecdsa";       TITLE="ns-hybrid-kem";;
  hybrid-full)
    TLS_GROUPS="X25519MLKEM768"; CERT_FUNC="cert_hybrid_full"; TITLE="ns-hybrid-full";;
  pqc)
    TLS_GROUPS="MLKEM768";       CERT_FUNC="cert_pqc";         TITLE="ns-pqc";;
  *)
    echo "❌ Invalid mode"; exit 1;;
esac

PORT=$((BASE_PORT + RANDOM % 200 + 1))

echo "=== Namespace TLS Benchmark: $TITLE ==="
echo "[+] Logs → $LOG_DIR"
echo "[+] Mode: $MODE | Delay: ${DELAY_MS}ms | Rate: ${RATE_MBIT} mbit | MTU: $MTU"

###################################################################
# Namespace Setup
###################################################################

cleanup() {
  ip netns del ns_cli 2>/dev/null || true
  ip netns del ns_srv 2>/dev/null || true
}
trap cleanup EXIT

ip netns add ns_cli
ip netns add ns_srv

ip link add vethc type veth peer name veths
ip link set vethc netns ns_cli
ip link set veths netns ns_srv

ip netns exec ns_cli ip addr add 10.200.1.2/24 dev vethc
ip netns exec ns_srv ip addr add 10.200.1.1/24 dev veths

ip netns exec ns_cli ip link set lo up
ip netns exec ns_srv ip link set lo up
ip netns exec ns_cli ip link set vethc up
ip netns exec ns_srv ip link set veths up

ip netns exec ns_cli ip link set vethc mtu "$MTU"
ip netns exec ns_srv ip link set veths mtu "$MTU"

###################################################################
# Traffic Shaping
###################################################################

if [[ "$DELAY_MS" -gt 0 || "$RATE_MBIT" -gt 0 ]]; then
  ip netns exec ns_cli tc qdisc del dev vethc root 2>/dev/null || true
  if [[ "$RATE_MBIT" -gt 0 ]]; then
    ip netns exec ns_cli tc qdisc add dev vethc root handle 1: htb default 10
    ip netns exec ns_cli tc class add dev vethc parent 1: classid 1:10 htb rate ${RATE_MBIT}mbit
    [[ "$DELAY_MS" -gt 0 ]] && ip netns exec ns_cli tc qdisc add dev vethc parent 1:10 netem delay ${DELAY_MS}ms
  else
    ip netns exec ns_cli tc qdisc add dev vethc root netem delay ${DELAY_MS}ms
  fi
fi

###################################################################
# Start Server
###################################################################

echo "[+] Starting TLS server"
write_oqs_conf_srv
$CERT_FUNC

# --- Certificate size reporting ---
CERT_SIZE=$(ip netns exec ns_srv stat -c%s /tmp/server.crt 2>/dev/null || echo 0)
KEY_SIZE=$(ip netns exec ns_srv stat -c%s /tmp/server.key 2>/dev/null || echo 0)

echo "[+] Certificate size: ${CERT_SIZE} bytes"
echo "[+] Key size:         ${KEY_SIZE} bytes"

# Wrap the server in /usr/bin/time -v so we can parse its CPU usage later
ip netns exec ns_srv /usr/bin/time -v \
  env OPENSSL_CONF=/tmp/oqs_srv.cnf OPENSSL_MODULES="$OQS_MOD" \
  $OQS s_server -accept "$PORT" \
    -cert /tmp/server.crt -key /tmp/server.key \
    -tls1_3 -www -provider default -provider oqsprovider \
    >/tmp/server.log 2>&1 &

SERVER_PID=$!

sleep 0.7

###################################################################
# Verify handshake
###################################################################

write_oqs_conf_cli

echo "[+] Testing connection..."
ip netns exec ns_cli env OPENSSL_CONF=/tmp/oqs_cli.cnf OPENSSL_MODULES="$OQS_MOD" \
  $OQS s_client -connect 10.200.1.1:$PORT -tls1_3 \
    -provider default -provider oqsprovider </dev/null \
    | grep -E 'Cipher|Group|Signature' || true

###################################################################
# Benchmark
###################################################################

PCAP="ns_${MODE}_${TS}.pcap"
ip netns exec ns_cli tcpdump -i vethc -c "$PCAP_LIMIT" -w "/tmp/$PCAP" >/dev/null 2>&1 &
TCPDUMP_PID=$!

# === Benchmark (client) ===
set +e
RAW=$(ip netns exec ns_cli /usr/bin/time -v \
  env OPENSSL_CONF=/tmp/oqs_cli.cnf OPENSSL_MODULES=$OQS_MOD \
  $OQS s_time -connect 10.200.1.1:$PORT -tls1_3 -new \
  -provider default -provider oqsprovider \
  -time "$TIME_SECONDS" 2>&1)
set -e

kill "$SERVER_PID" 2>/dev/null || true
kill "$TCPDUMP_PID" 2>/dev/null || true

###################################################################
# Parse client results
###################################################################

CONN=$(echo "$RAW" | grep -Eo "^[0-9]+" | head -1)
CPU_TIME=$(echo "$RAW" | grep -Eo "in [0-9.]+s" | sed 's/in //;s/s//')
USER=$(echo "$RAW" | awk -F': ' '/User time/ {print $2}')
SYS=$(echo "$RAW" | awk -F': ' '/System time/ {print $2}')
RSS=$(echo "$RAW" | awk -F': ' '/Maximum resident/ {print $2}')

HPS=$(awk -v c="${CONN:-0}" -v t="${CPU_TIME:-0.001}" 'BEGIN{print (t>0?c/t:0)}')
LAT=$(awk -v h="$HPS" 'BEGIN{print (h>0?1000/h:"inf")}')
CLIENT_CPU_PER_HS=$(awk -v u="${USER:-0}" -v s="${SYS:-0}" -v c="${CONN:-0}" \
  'BEGIN{print (c>0?(u+s)/c:0)}')
CLIENT_MEM_PER_HS=$(awk -v r="${RSS:-0}" -v c="${CONN:-0}" \
  'BEGIN{print (c>0?r/c:0)}')

###################################################################
# Parse server CPU from /tmp/server.log
###################################################################

RAW_SRV=$(cat /tmp/server.log 2>/dev/null || echo "")
SRV_USER=$(echo "$RAW_SRV" | awk -F': ' '/User time/ {print $2}' || echo 0)
SRV_SYS=$(echo "$RAW_SRV" | awk -F': ' '/System time/ {print $2}' || echo 0)
SERVER_CPU_PER_HS=$(awk -v u="${SRV_USER:-0}" -v s="${SRV_SYS:-0}" -v c="${CONN:-0}" \
  'BEGIN{print (c>0?(u+s)/c:0)}')

###################################################################
# Handshake bytes (client side capture)
###################################################################

BYTES=0
if command -v tshark >/dev/null 2>&1; then
  BYTES=$(ip netns exec ns_cli tshark -r "/tmp/$PCAP" -Y "tls.handshake" \
     -T fields -e frame.len 2>/dev/null | awk '{s+=$1} END{print s+0}')
fi

BYTES_PER_CONN=$(awk -v b="$BYTES" -v c="${CONN:-1}" \
  'BEGIN{print (c>0?b/c:0)}')

###################################################################
# Print summary
###################################################################

echo "--- ns-$MODE Results ---"
echo "Connections: $CONN"
echo "H/s: $HPS"
echo "Latency: $LAT ms"
echo "Client CPU/hs: $CLIENT_CPU_PER_HS s"
echo "Server CPU/hs: $SERVER_CPU_PER_HS s"
echo "Client Mem/hs: $CLIENT_MEM_PER_HS KB"
echo "Bytes/conn: $BYTES_PER_CONN"
echo "Cert bytes: $CERT_SIZE"
echo "Key bytes:  $KEY_SIZE"
echo "PCAP: $PCAP"

###################################################################
# CSV logging
###################################################################

if [[ ! -f "$RESULT_CSV" ]]; then
  echo "mode,connections,handshakes_sec,latency_ms,client_cpu_per_handshake_s,server_cpu_per_handshake_s,client_mem_per_handshake_kb,handshake_bytes_per_conn,cert_bytes,key_bytes,delay_ms,rate_mbit,mtu" \
    > "$RESULT_CSV"
fi

echo "$MODE,$CONN,$HPS,$LAT,$CLIENT_CPU_PER_HS,$SERVER_CPU_PER_HS,$CLIENT_MEM_PER_HS,$BYTES_PER_CONN,$CERT_SIZE,$KEY_SIZE,$DELAY_MS,$RATE_MBIT,$MTU" \
  >> "$RESULT_CSV"

echo "[+] Saved → $RESULT_CSV"

