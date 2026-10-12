#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Service-owned AX211 GO radio. Never disconnects or reconfigures the station."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import subprocess
import time

LIB = Path(__file__).resolve().parent
RUN = Path('/run/omdrop-owl')
NET = Path('/sys/class/net')
OWNED = ('awdlgo0', 'mon0')
GO_CARDS = {('0x8086', '0x51f0'), ('0x8086', '0x2725')}
# /etc/omdrop/go-channel: the GO's channel, 6 by default. An iPhone keeps one
# slot in sixteen on 6, and moves most of a transfer to 149 (44 outside the US).
GO_FREQS = {6: 2437, 44: 5220, 149: 5745}


def go_owl_flags():
    """OWL's -F (fixed radio, unicast sent once with no ACK) unless
    /etc/omdrop/go-fixed-radio says 0: the GO ACKs for us, so unicast can be
    acknowledged and retried instead."""
    try:
        off = Path('/etc/omdrop/go-fixed-radio').read_text().split()[0] == '0'
    except (OSError, IndexError):
        off = False
    return ['-E'] if off else ['-F', '-E']


def go_stations():
    """/etc/omdrop/go-stations = 1: make each AWDL peer a station of the GO,
    so its ADDBA is answered and its A-MPDUs block-acked (needs the patched
    iwlmvm, awdl_share 512). Unanswered, an iPhone sent single frames at
    MCS 0."""
    try:
        return Path('/etc/omdrop/go-stations').read_text().split()[0] == '1'
    except (OSError, IndexError):
        return False


PEER_LINE = re.compile(r'\b(add|remove) peer ([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})\b')


def peer_commands(text):
    """`add MAC` / `del MAC` lines for OWL's add/remove peer log lines; OWL
    prints octets unpadded (ether_ntoa)."""
    out = []
    for op, addr in PEER_LINE.findall(text):
        mac = ':'.join(f'{int(o, 16):02x}' for o in addr.split(':'))
        out.append(f"{'add' if op == 'add' else 'del'} {mac}\n")
    return ''.join(out)


def go_channel():
    try:
        c = int(Path('/etc/omdrop/go-channel').read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return 6
    return c if c in GO_FREQS else 6
stopping = False


def command(args, check=True, timeout=5):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f'{args[0]}: {p.stderr.strip()}')
    return p


def save(state):
    path = RUN / 'go-state.tmp'
    path.write_text(json.dumps(state))
    path.chmod(0o600)
    path.replace(RUN / 'go-state.json')


def legal_channel(info, chan=6):
    freq = GO_FREQS[chan]
    rows = [r for r in info.splitlines() if re.search(rf'\b{freq}(?:\.0+)? MHz \[{chan}\]', r)]
    return len(rows) == 1 and not any(flag in rows[0].lower() for flag in ('disabled', 'no ir', 'no-ir', 'radar'))


def association(station):
    text = command(['iw', 'dev', station, 'link']).stdout
    match = re.search(r'Connected to ([0-9a-f:]{17})', text, re.I)
    if not match:
        raise RuntimeError('Wi-Fi is no longer connected')
    return match[1].lower()


def ping(station, gateway):
    return command(['ping', '-n', '-I', station, '-c', '1', '-W', '1', gateway], check=False).returncode == 0


def preflight(station):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', station):
        raise RuntimeError('Invalid station interface')
    path = NET / station
    # AX211 (51f0) and AX210 (2725): both offer managed + P2P-GO on two channels
    if ((path / 'device/vendor').read_text().strip(), (path / 'device/device').read_text().strip()) not in GO_CARDS:
        raise RuntimeError('Connected GO mode currently supports only Intel AX211 8086:51f0 and AX210 8086:2725')
    phy = (path / 'phy80211').resolve(strict=True).name
    if not re.fullmatch(r'phy[0-9]+', phy):
        raise RuntimeError('Invalid station PHY')
    for name in (*OWNED, 'awdl0'):
        if (NET / name).exists():
            raise RuntimeError(f'Interface {name} already exists; stop its owner first')
    info = command(['iw', 'phy', phy, 'info']).stdout
    if not legal_channel(info, go_channel()):
        raise RuntimeError(f'Channel {go_channel()} is not permitted for transmission here')
    if 'P2P-GO' not in info or not re.search(r'#channels <= [2-9]', info):
        raise RuntimeError('This driver does not advertise two-channel P2P GO concurrency')
    bssid = association(station)
    routes = json.loads(command(['ip', '-j', '-4', 'route', 'show', 'default', 'dev', station]).stdout)
    gateways = {r['gateway'] for r in routes if 'gateway' in r}
    if len(gateways) != 1:
        raise RuntimeError('Connected GO mode needs one IPv4 gateway on Wi-Fi')
    gateway = gateways.pop()
    if not all(ping(station, gateway) for _ in range(3)):
        raise RuntimeError('Wi-Fi gateway did not answer the connectivity checks')
    mac = ':'.join(f'{b:02x}' for b in bytes([2]) + secrets.token_bytes(5))
    existing = {p.read_text().strip() for p in NET.glob('*/address')}
    if mac in existing:
        raise RuntimeError('Generated radio address collided; try again')
    return dict(station=station, phy=phy, bssid=bssid, gateway=gateway, mac=mac, indices={})


def cleanup():
    """Also called by systemd ExecStopPost after SIGKILL or partial startup."""
    path = RUN / 'go-state.json'
    if not path.exists():
        return
    state = json.loads(path.read_text())
    errors = []
    for name in reversed(OWNED):
        net = NET / name
        if not net.exists():
            continue
        # The random MAC/PHY reservation is persisted before create; ifindex
        # adds protection once READY arrived. Never delete a replaced interface.
        index = state.get('indices', {}).get(name)
        if ((net / 'address').read_text().strip() != state['mac'] or
                (net / 'phy80211').resolve().name != state['phy'] or
                (index is not None and int((net / 'ifindex').read_text()) != index)):
            errors.append(f'{name} identity changed; left untouched')
            continue
        result = command(['iw', 'dev', name, 'del'], check=False)
        if result.returncode and net.exists():
            errors.append(f'{name}: {result.stderr.strip()}')
    for name in ('go-ready', 'supervisor.pid', 'owl.pid'):
        (RUN / name).unlink(missing_ok=True)
    if errors:
        raise RuntimeError('; '.join(errors))
    path.unlink()


def terminate(child):
    if child is not None and child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=4)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)


def run(station):
    state = preflight(station)
    save(state)
    children = []
    reason, succeeded = 'stopped', False

    def launch(args, filename, stdout=None, stdin=subprocess.DEVNULL):
        log = open(RUN / filename, 'a')
        child = subprocess.Popen(args, stdin=stdin, stdout=stdout or log, stderr=log)
        log.close()
        children.append(child)
        return child

    try:
        chan = go_channel()
        helper = launch([str(LIB / 'awdl-go'), '--phy', state['phy'][3:], '--mac', state['mac'],
                         '--freq', str(GO_FREQS[chan])],
                        'go.log', subprocess.PIPE,
                        subprocess.PIPE if go_stations() else subprocess.DEVNULL)
        selector = selectors.DefaultSelector()
        selector.register(helper.stdout, selectors.EVENT_READ)
        if not selector.select(12):
            raise RuntimeError('Secondary GO setup timed out')
        ready = helper.stdout.readline()
        selector.close()
        if not ready.startswith(b'READY ') or helper.poll() is not None:
            raise RuntimeError('Could not start secondary GO; see /run/omdrop-owl/go.log')
        state['indices'] = {name: int((NET / name / 'ifindex').read_text()) for name in OWNED}
        save(state)
        # Keep plain kernel IPv6 off the beaconing interface. IP belongs on TAP.
        command(['sysctl', '-qw', 'net.ipv6.conf.awdlgo0.disable_ipv6=1'])
        owl = launch([str(LIB / 'owl'), '-i', 'mon0', '-h', 'awdl0', '-m', state['mac'],
                      '-N', '-c', str(chan), '-S', 'pin', *go_owl_flags(), '-v'], 'owl.log')
        (RUN / 'owl.pid').write_text(str(owl.pid))
        (RUN / 'supervisor.pid').write_text(str(os.getpid()))
        until_ready = time.monotonic() + 12
        while time.monotonic() < until_ready and not stopping:
            if owl.poll() is not None or helper.poll() is not None:
                raise RuntimeError('OWL or the GO helper exited during startup')
            if (NET / 'awdl0').exists():
                command(['nmcli', 'device', 'set', 'awdl0', 'managed', 'no'], check=False)
                addresses = json.loads(command(['ip', '-j', '-6', 'addr', 'show', 'dev', 'awdl0', 'scope', 'link']).stdout)
                if any(a.get('scope') == 'link' and not a.get('tentative') and not a.get('dadfailed')
                       for entry in addresses for a in entry.get('addr_info', [])):
                    break
            time.sleep(.1)
        else:
            raise RuntimeError('AWDL did not acquire a usable link-local address')
        if stopping:
            return 0
        (RUN / 'go-ready').write_text('ready\n')
        (RUN / 'reason').write_text('')
        misses, burst, next_burst = 0, None, 0
        owl_log = open(RUN / 'owl.log', 'r', errors='replace') if go_stations() else None
        while not stopping:
            if owl_log is not None:
                lines = peer_commands(owl_log.read())
                if lines:
                    try:
                        helper.stdin.write(lines.encode())
                        helper.stdin.flush()
                    except (BrokenPipeError, OSError):
                        raise RuntimeError('GO helper stopped taking stations')
            until = int((RUN / 'until').read_text().strip())
            if until and time.time() >= until:
                reason = 'expired'
                break
            if owl.poll() is not None or helper.poll() is not None:
                raise RuntimeError('OWL or GO helper exited')
            if association(station) != state['bssid']:
                raise RuntimeError('Wi-Fi association changed')
            misses = 0 if ping(station, state['gateway']) else misses + 1
            if misses >= 3:
                raise RuntimeError('Wi-Fi gateway stopped responding')
            if burst is not None and burst.poll() not in (None, 0):
                raise RuntimeError('AirDrop announcement failed')
            if time.monotonic() >= next_burst and (burst is None or burst.poll() is not None):
                # Reap completed bursts; a forever window must not grow a list.
                children[:] = [p for p in children if p.poll() is None]
                burst = launch(['/usr/bin/python3', str(LIB / 'awdl-airdrop-adv.py'), '--iface', 'awdl0',
                                '--plain', '--flags', '137', '--port', '8771', '--count', '64', '--interval', '0.0164'],
                               'announce.log')
                next_burst = time.monotonic() + 4
            time.sleep(.7)
        succeeded = True
    except Exception as error:
        reason = str(error)
        print(reason, flush=True)
    finally:
        (RUN / 'reason').write_text(reason)
        for child in reversed(children):
            terminate(child)
        cleanup()
    return 0 if succeeded else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('run', 'cleanup'))
    parser.add_argument('--station')
    args = parser.parse_args()
    if os.geteuid():
        parser.error('requires root')
    if args.action == 'cleanup':
        cleanup()
        return 0
    if not args.station:
        parser.error('--station required')
    try:
        return run(args.station)
    except Exception as error:
        (RUN / 'reason').write_text(str(error))
        print(error, flush=True)
        return 1


def stop(signum, frame):
    global stopping
    stopping = True


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    raise SystemExit(main())
