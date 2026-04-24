SCRIPT=./tls_bench_ns.sh
TIME=5

run_env () {
  local name="$1" delay="$2" rate="$3" mtu="$4"
  echo "=== $name (delay=${delay}ms rate=${rate}mbit mtu=${mtu}) ==="
  for mode in classic classic-rsa hybrid-kem hybrid-full pqc; do
    $SCRIPT --mode "$mode" --delay-ms "$delay" --rate-mbit "$rate" --mtu "$mtu" --time "$TIME"
  done
}

run_env "LAN / AD"        1   1000 1500
run_env "Home + VPN"      20  100  1400
run_env "4G"              40  50   1500
run_env "5G"              10  300  1500
run_env "Cloud-to-Cloud"  60  200  1500
run_env "Zero-Trust Edge" 15  200  1350

