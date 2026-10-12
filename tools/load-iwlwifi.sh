#!/usr/bin/env bash
# Swap in iwlwifi.ko and mvm/iwlmvm.ko built in DIR (kernel/ patch applied),
# falling back to the stock modules if they don't load, so Wi-Fi comes back
# either way. Wi-Fi is down for a few seconds.
#
#   sudo tools/load-iwlwifi.sh DIR      # patched
#   sudo tools/load-iwlwifi.sh --stock  # back to the distribution's
set -u
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
DIR=${1:?usage: load-iwlwifi.sh DIR | --stock}
# modprobe -r takes iwlwifi (and mac80211) with iwlmvm; insmod loads no
# dependencies, so iwlwifi goes in first and mac80211 by hand.
modprobe -r iwlmvm iwlwifi
if [ "$DIR" != --stock ]; then
  modprobe mac80211
  if insmod "$DIR/iwlwifi.ko"; then
    # iwlwifi request_module()s its op mode when the firmware loads, which
    # can beat us to it with the stock iwlmvm: swap that one out if so.
    insmod "$DIR/mvm/iwlmvm.ko" 2>/dev/null \
      || [ -e /sys/module/iwlmvm/parameters/awdl_share ] \
      || { rmmod iwlmvm 2>/dev/null; insmod "$DIR/mvm/iwlmvm.ko"; }
  fi
fi
if [ ! -d /sys/module/iwlmvm ]; then
  [ "$DIR" = --stock ] || echo "patched modules didn't load; falling back to stock" >&2
  modprobe -r iwlwifi 2>/dev/null
  modprobe iwlwifi
fi
[ -e /sys/module/iwlmvm/parameters/awdl_share ] && echo patched || echo stock
