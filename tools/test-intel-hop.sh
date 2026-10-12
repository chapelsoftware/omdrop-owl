#!/usr/bin/env bash
# Spike for channel hopping on Intel: with the station associated on a
# non-AWDL channel, send it off-channel (remain-on-channel) to an AWDL channel
# again and again, and count the AWDL action frames a monitor beside it hears
# there. Hold an iPhone nearby with the share sheet open (AirDrop browsing).
#
#   sudo [ROC_WDEV=0x...] tools/test-intel-hop.sh [FREQ [DWELL_MS [SECONDS]]]
#
# FREQ defaults to 5745 (channel 149), DWELL_MS to 200, SECONDS to 20.
# Needs the patched iwlmvm (kernel/), run with awdl_share=6.
set -uo pipefail

FREQ=${1:-5745}
DWELL=${2:-200}
SECS=${3:-20}
MON=mon0
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }

sta=$(for d in /sys/class/net/*/phy80211; do n=$(basename "$(dirname "$d")"); iw dev "$n" link 2>/dev/null | grep -q '^Connected' && echo "$n"; done | head -1)
[ -n "$sta" ] || { echo "Wi-Fi isn't connected" >&2; exit 1; }
phy=$(basename "$(readlink -f "/sys/class/net/$sta/phy80211")")
mac=$(cat "/sys/class/net/$sta/address")
gw=$(ip -4 route show default dev "$sta" | awk '{print $3; exit}')
home=$(iw dev "$sta" link | awk '/freq:/ {print int($2)}')
echo "station $sta on $home MHz; hopping to $FREQ MHz for ${DWELL} ms at a time, ${SECS} s"
[ -e /sys/module/iwlmvm/parameters/awdl_share ] && echo "${AWDL_SHARE:-6}" > /sys/module/iwlmvm/parameters/awdl_share

iw dev "$MON" del 2>/dev/null
iw phy "$phy" interface add "$MON" type monitor || exit 1
ip link set "$MON" address "$mac"
ip link set "$MON" up || exit 1

cap=$(mktemp)
# Through stdout: Debian's AppArmor profile limits where tcpdump may write.
timeout -s INT "$((SECS + 2))" tcpdump -i "$MON" -U -w - 2>/dev/null > "$cap" &
tcp=$!
mark=$(date '+%Y-%m-%d %H:%M:%S')
end=$((SECONDS + SECS)); n=0; fail=0
while [ $SECONDS -lt $end ]; do
  if [ -n "${ROC_WDEV:-}" ]; then
    # Through the P2P device (iw wdev IDX p2p start first), not the station.
    iw wdev "$ROC_WDEV" roc start "$FREQ" "$DWELL" >/dev/null 2>&1 && n=$((n + 1)) || fail=$((fail + 1))
  elif iw dev "$sta" offchannel "$FREQ" "$DWELL" 2>/dev/null; then n=$((n + 1)); else fail=$((fail + 1)); fi
  sleep "$(awk -v d="$DWELL" 'BEGIN { printf "%.3f", (d + 50) / 1000 }')"
done
wait "$tcp"
ping -c3 -W1 -I "$sta" "$gw" >/dev/null 2>&1 && pingr=ok || pingr=FAILED

ip link set "$MON" down; iw dev "$MON" del
journalctl -k --since "$mark" --no-pager | grep -E 'Microcode SW error|FW error|WARNING|missed_beacons' | sort | uniq -c | head -5 | sed 's/^/kernel: /'

echo "offchannel requests: $n ok, $fail refused; ping after: $pingr"
txt=$(mktemp)
tcpdump -r - -e -nn < "$cap" > "$txt" 2>/dev/null
echo "frames by frequency:"; grep -oE '[0-9]{4} MHz' "$txt" | sort | uniq -c
# AWDL: vendor-specific action frames on AWDL's BSSID 00:25:00:ff:94:73.
echo "AWDL frames by frequency:"; grep -i 'BSSID:00:25:00:ff:94:73' "$txt" | grep -oE '[0-9]{4} MHz' | sort | uniq -c
echo "AWDL senders:"; grep -i 'BSSID:00:25:00:ff:94:73' "$txt" | grep -oE 'SA:[0-9a-f:]+' | sort | uniq -c | sort -rn | head -5
rm -f "$cap" "$txt"
