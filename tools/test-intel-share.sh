#!/usr/bin/env bash
# Smoke test for kernel/iwlmvm-awdl-share-*.patch, no iPhone needed: with a
# monitor beside the associated station, does the firmware pass up other
# BSSs' frames, does a frame injected with the station's address go out, and
# does Wi-Fi keep working through it and after.
#
#   sudo [AWDL_SHARE=MASK] tools/test-intel-share.sh [--load DIR]
#
# MASK is iwlmvm's awdl_share bitmask (default 6: management frames from
# other BSSs, and injection; 1, promiscuous data, costs the station its AP's
# beacons on the AX210).
#
# --load DIR swaps in iwlwifi.ko and mvm/iwlmvm.ko built in DIR (Wi-Fi drops
# for a few seconds); without it, the loaded iwlmvm must already be patched.
# Undo a --load with: modprobe -r iwlmvm iwlwifi && modprobe iwlwifi
set -uo pipefail

MON=mon0
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }

if [ "${1:-}" = --load ]; then
  dir=${2:?--load DIR}
  modprobe -r iwlmvm iwlwifi || exit 1
  # insmod doesn't load dependencies, and modprobe -r took mac80211 with it.
  modprobe mac80211 || exit 1
  insmod "$dir/iwlwifi.ko" || exit 1
  # iwlwifi request_module()s its op mode once the firmware loads, which can
  # beat us to it with the stock iwlmvm: swap that one out if so.
  if ! insmod "$dir/mvm/iwlmvm.ko" awdl_share=${AWDL_SHARE:-6}; then
    [ -e /sys/module/iwlmvm/parameters/awdl_share ] || {
      rmmod iwlmvm && insmod "$dir/mvm/iwlmvm.ko" awdl_share=${AWDL_SHARE:-6}; } || exit 1
  fi
fi
[ -e /sys/module/iwlmvm/parameters/awdl_share ] || { echo "loaded iwlmvm isn't patched" >&2; exit 1; }
echo "${AWDL_SHARE:-6}" > /sys/module/iwlmvm/parameters/awdl_share

sta=""
for _ in $(seq 30); do
  for d in /sys/class/net/*/phy80211; do
    n=$(basename "$(dirname "$d")")
    iw dev "$n" link 2>/dev/null | grep -q '^Connected' && { sta=$n; break; }
  done
  [ -n "$sta" ] && break
  sleep 1
done
[ -n "$sta" ] || { echo "Wi-Fi didn't connect" >&2; exit 1; }
phy=$(basename "$(readlink -f "/sys/class/net/$sta/phy80211")")
mac=$(cat "/sys/class/net/$sta/address")
ap=$(iw dev "$sta" link | awk '/^Connected to/ {print $3}')
freq=$(iw dev "$sta" link | awk '/freq:/ {print int($2)}')
gw=$(ip -4 route show default dev "$sta" | awk '{print $3; exit}')
echo "station $sta $mac on $freq MHz, AP $ap, gateway $gw"

pingok() { ping -c3 -W2 -I "$sta" "$gw" >/dev/null 2>&1 && echo ok || echo FAILED; }
echo "ping before:  $(pingok)"

mark=$(date '+%Y-%m-%d %H:%M:%S')
iw dev "$MON" del 2>/dev/null
iw phy "$phy" interface add "$MON" type monitor || exit 1
ip link set "$MON" address "$mac"
ip link set "$MON" up || exit 1
sleep 1
journalctl -k --since "$mark" --no-pager | grep -E 'awdl_share|Microcode SW error|FW error|WARNING' | sed 's/^/kernel: /'

cap=$(mktemp)
# Through stdout: Debian's AppArmor profile limits where tcpdump may write.
timeout 10 tcpdump -i "$MON" -e -nn -c 2000 2>/dev/null > "$cap"
total=$(wc -l < "$cap")
# BSSID isn't printed for every frame type; count frames neither from nor to
# our AP or us, which the stock firmware never passes up while associated.
foreign=$(grep -viE "$ap|$mac" "$cap" | grep -cvE '^\s*$')
echo "monitor: $total frames in 10 s, $foreign not involving our AP or us"
grep -viE "$ap|$mac" "$cap" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(SA|TA|BSSID):/) print $i}' | sort | uniq -c | sort -rn | head -8

# Inject AWDL-shaped action frames (vendor-specific, Apple's OUI, to
# broadcast, AWDL's BSSID) with the station's address, and look for them
# leaving: TX status comes back through the monitor as the frame itself.
python3 - "$MON" "$mac" <<'EOF'
import socket, struct, sys, time
iface, mac = sys.argv[1], bytes.fromhex(sys.argv[2].replace(':', ''))
rt = struct.pack('<BBHI', 0, 0, 8, 0)
hdr = struct.pack('<HH', 0x00d0, 0) + b'\xff' * 6 + mac + bytes.fromhex('002500ff9473') + struct.pack('<H', 0)
body = bytes([127]) + bytes.fromhex('0017f2') + b'\x08' + b'omdrop-share-test'
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
sent = 0
for _ in range(20):
    try:
        s.send(rt + hdr + body); sent += 1
    except OSError as e:
        print('inject:', e); break
    time.sleep(0.05)
print(f'injected {sent}/20')
EOF
sleep 1
journalctl -k --since "$mark" --no-pager | grep -E 'No queue|Dropping|Microcode SW error|FW error|WARNING|awdl_share' | sed 's/^/kernel: /'
echo "ping during: $(pingok)"

ip link set "$MON" down
iw dev "$MON" del
sleep 2
journalctl -k --since "$mark" --no-pager | grep -E 'awdl_share: off' | sed 's/^/kernel: /'
echo "ping after:   $(pingok)"
rm -f "$cap"
