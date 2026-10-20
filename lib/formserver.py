#!/usr/bin/env python3

"""One-page form server (used by bin/form).

Public by design: the owner mails the link and anyone with it can fill the
form in. That means there is deliberately no CSRF token and no login — a
cross-site POST here can do nothing an attacker couldn't do by opening the
page themselves.

What that openness *does* require is that an anonymous POST can't cost more
than a form submission is worth:

  * The body is capped before it is read. The old code did
    `self.rfile.read(Content-Length)` with no ceiling, so one POST declaring
    4GB made the box allocate 4GB.
  * Each stored value is length-capped, and the submissions file has a hard
    row ceiling — it is rewritten in full on every append, so an unbounded
    one is both a disk-fill and an O(n^2) CPU sink.
  * Field names and values only ever leave here inside JSON; the page itself
    is rendered once at startup from the operator's --fields spec.
"""

import argparse
import html
import json
import os
import sys
import fcntl
import tempfile
import threading
import types
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs

_HERE_LIB = os.path.dirname(os.path.abspath(__file__))
if _HERE_LIB not in sys.path:
    sys.path.insert(0, _HERE_LIB)
from porch_http import (  # noqa: E402  (shared HTTP core)
    client_ip, content_length, csp_nonce, make_server, porch_css_tag, porch_mark,
    porch_style_src, security_headers, serve_asset,
)

# A form submission is text a person types. These ceilings are far above any
# real use of bin/form and exist purely so an anonymous POST cannot turn
# Content-Length into an allocation request or the output file into a disk sink.
MAX_BODY = 1024 * 1024          # whole urlencoded body
MAX_FIELD_LEN = 64 * 1024       # per stored value
MAX_SUBMISSIONS = 10000         # rows kept in the output file

# Per-peer submission rate limit: at most RATE_LIMIT_COUNT POSTs per
# RATE_LIMIT_WINDOW seconds from one address. Generous for a person filling a
# form in; it stops one client from scripting the file up to MAX_SUBMISSIONS.
RATE_LIMIT_COUNT = 10
RATE_LIMIT_WINDOW = 60.0


class RateLimiter:
    """Sliding-window counter keyed by peer address."""

    def __init__(self, count=RATE_LIMIT_COUNT, window=RATE_LIMIT_WINDOW, clock=time.monotonic):
        self.count = count
        self.window = window
        self.clock = clock
        self._hits = {}
        self._lock = threading.Lock()

    def allow(self, key):
        now = self.clock()
        cutoff = now - self.window
        with self._lock:
            hits = [t for t in self._hits.get(key, ()) if t > cutoff]
            if len(hits) >= self.count:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            # Keep the table bounded: drop peers with no recent hits.
            if len(self._hits) > 4096:
                for k in [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]:
                    del self._hits[k]
            return True


def peer_address(peer_ip, headers):
    """The address to rate-limit on: porch_http.client_ip (X-Forwarded-For
    believed only from a loopback peer, i.e. frpc; right-most non-loopback
    hop, since anything to its left was supplied by the client)."""
    return client_ip(types.SimpleNamespace(client_address=(peer_ip,), headers=headers))


# The pages are built once at startup; NONCE_MARK is swapped for a fresh nonce
# on every response. It contains '<', which html.escape() turns into &lt;, so
# no escaped title, name or option can contain it.
NONCE_MARK = '<N>'

_FORM_STYLE = r"""<style nonce="<N>">
.form-wrap form{display:flex;flex-direction:column;gap:20px}
.field{display:flex;flex-direction:column;gap:8px}
.field > label{font-size:13px;font-weight:500}
.checkbox-wrap{display:flex;align-items:center;gap:10px;min-height:32px}
.checkbox-wrap input[type="checkbox"]{width:20px;height:20px;accent-color:var(--accent);cursor:pointer;margin:0}
.checkbox-wrap label{cursor:pointer;font-size:15px}
.thanks{align-items:flex-start}
</style>
"""

FORM_HTML = r"""<!DOCTYPE html>
<html lang="en" data-app="form">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FORM_TITLE</title>
__PORCH_CSS__
""" + _FORM_STYLE + r"""</head>
<body>
<main class="p-shell p-shell--narrow">
  <header class="p-head">
    <div class="p-kicker">__MARK__<span>FORM_SUBTITLE</span></div>
    <h1 class="p-title">FORM_TITLE</h1>
    <p class="p-lede">Your answers go only to whoever sent you this link.</p>
  </header>
  <div class="p-card form-wrap">
    <form method="POST" action="/">
FORM_FIELDS
      <button class="p-btn p-btn--lg p-btn--block" type="submit">Send</button>
    </form>
  </div>
  <footer class="p-foot">sent through porch</footer>
</main>
</body>
</html>"""


THANKS_HTML = r"""<!DOCTYPE html>
<html lang="en" data-app="form">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Thank you</title>
__PORCH_CSS__
""" + _FORM_STYLE + r"""</head>
<body>
<main class="p-shell p-shell--narrow">
  <div class="p-notice p-notice--ok" role="status">
    <svg class="p-notice-icon" width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M4 10.5 L8 14 L16 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
    <div><h1 class="p-title p-title--sm">Thank you</h1><p class="p-muted">Your answers were recorded. You can close this tab.</p></div>
  </div>
  <div><a class="p-btn p-btn--ghost" href="/">Send another</a></div>
  <footer class="p-foot">sent through porch</footer>
</main>
</body>
</html>"""

FORM_HTML = FORM_HTML.replace('__PORCH_CSS__', porch_css_tag()).replace('__MARK__', porch_mark(16))
THANKS_HTML = THANKS_HTML.replace('__PORCH_CSS__', porch_css_tag())


def parse_field_spec(spec):
    """Parse field DSL: name:type[:option1:option2:...]"""
    fields = []
    for part in spec.split(','):
        parts = part.strip().split(':')
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        ftype = parts[1].strip()
        options = [p.strip() for p in parts[2:]] if len(parts) > 2 else []
        fields.append({'name': name, 'type': ftype, 'options': options})
    return fields


def render_field_html(field):
    """Render a single form field to HTML."""
    name = html.escape(field['name'])
    ftype = field['type']
    label = field['name'].replace('_', ' ').replace('-', ' ').title()
    escaped_label = html.escape(label)

    if ftype == 'textarea':
        return (
            f'      <div class="field">\n'
            f'        <label for="{name}">{escaped_label}</label>\n'
            f'        <textarea class="p-textarea" id="{name}" name="{name}"></textarea>\n'
            f'      </div>'
        )
    elif ftype == 'select':
        opts = '\n'.join(
            f'          <option value="{html.escape(o)}">{html.escape(o)}</option>'
            for o in field['options']
        )
        return (
            f'      <div class="field">\n'
            f'        <label for="{name}">{escaped_label}</label>\n'
            f'        <select class="p-select" id="{name}" name="{name}">\n'
            f'          <option value="">Select...</option>\n'
            f'{opts}\n'
            f'        </select>\n'
            f'      </div>'
        )
    elif ftype == 'checkbox':
        return (
            f'      <div class="field">\n'
            f'        <div class="checkbox-wrap">\n'
            f'          <input type="checkbox" id="{name}" name="{name}" value="yes">\n'
            f'          <label for="{name}">{escaped_label}</label>\n'
            f'        </div>\n'
            f'      </div>'
        )
    else:
        # text, email, number
        input_type = ftype if ftype in ('text', 'email', 'number') else 'text'
        return (
            f'      <div class="field">\n'
            f'        <label for="{name}">{escaped_label}</label>\n'
            f'        <input class="p-input" type="{input_type}" id="{name}" name="{name}">\n'
            f'      </div>'
        )


def format_title(name):
    """Format name into a nice title: capitalize, replace hyphens with spaces."""
    return name.replace('-', ' ').replace('_', ' ').title()


class SubmissionsFull(Exception):
    """The output file already holds MAX_SUBMISSIONS rows."""


def append_submission(output_file, submission):
    """Append a submission to the JSON array file with file locking.

    Returns the new row count. Raises SubmissionsFull once the ceiling is hit:
    the whole array is re-read and rewritten on every append, so an unbounded
    file is both a disk-fill and quadratic CPU for anyone who can POST — and
    on a public form, that is everyone.
    """
    out_dir = os.path.dirname(os.path.abspath(output_file))
    os.makedirs(out_dir, mode=0o700, exist_ok=True)

    # Lock file for safe concurrent writes. O_NOFOLLOW: a symlink planted at
    # the lock path must not make us create/truncate whatever it points at.
    lock_path = output_file + '.lock'
    lock_raw = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_raw, 'r+') as lock_fd:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                if not isinstance(data, list):
                    data = []
            else:
                data = []

            if len(data) >= MAX_SUBMISSIONS:
                raise SubmissionsFull(output_file)
            data.append(submission)

            # Atomic write: a fresh O_EXCL 0600 temp file, then rename over
            # the target (rename replaces a symlink instead of following it).
            fd, tmp_path = tempfile.mkstemp(dir=out_dir, prefix='.form-')
            try:
                with os.fdopen(fd, 'w') as f:
                    json.dump(data, f, indent=2)
                os.replace(tmp_path, output_file)
            except BaseException:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
            return len(data)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)


class FormHandler(BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'
    # Bound how long a half-open or slow-loris connection can hold a thread.
    timeout = 120
    # Don't advertise the Python version to anonymous callers.
    server_version = 'cush-tools'
    sys_version = ''

    form_html = ""
    thanks_html = ""
    fields = []
    output_file = ""
    limiter = RateLimiter()

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith('GET'):
            return
        sys.stderr.write(f"[formserver] {self.address_string()} - {format % args}\n")

    def _security_headers(self):
        """Headers every response carries.

        nosniff stops a browser from re-deciding that something we labelled
        text/plain is really HTML and running it on this origin.
        """
        security_headers(self)

    def _send_html(self, body, status=200):
        nonce = csp_nonce()
        body = body.replace(NONCE_MARK, nonce)
        body = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        # The page loads porch.css and its fonts and runs no script at all;
        # form-action 'self' keeps a rewritten <form action> from posting the
        # visitor's answers somewhere else.
        self.send_header('Content-Security-Policy', (
            f"default-src 'none'; {porch_style_src(nonce)}; "
            "base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'"
        ))
        self._security_headers()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _send_text(self, text, status=200):
        body = text.encode()
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        if self.close_connection:
            # Answering without draining the request body — say so explicitly
            # so the leftover bytes aren't parsed as the next request.
            self.send_header('Connection', 'close')
        self._security_headers()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if serve_asset(self, head=self.command == 'HEAD'):
            return
        path = self.path.split('?')[0].rstrip('/')
        if path == '' or path == '/':
            self._send_html(self.form_html)
            return
        self._send_text('Not found', 404)

    def do_POST(self):
        if self.path.split('?')[0].rstrip('/') not in ('', '/'):
            self._send_text('Not found', 404)
            return

        if not self.limiter.allow(peer_address(self.client_address[0], self.headers)):
            self.close_connection = True
            self._send_text('Too many submissions — wait a minute and try again.', 429)
            return

        body_length = content_length(self)
        if body_length < 0:
            self.close_connection = True
            self._send_text('Bad Content-Length', 400)
            return
        if body_length > MAX_BODY:
            # Refused before a single byte is read: the declared size is what an
            # attacker would otherwise turn into an allocation.
            self.close_connection = True
            self._send_text('Submission too large', 413)
            return
        if content_length == 0:
            # No Content-Length (e.g. chunked): BaseHTTPRequestHandler does not
            # de-chunk, and reading an unbounded body is the DoS being avoided.
            self._send_text('Content-Length required', 411)
            return

        raw = self.rfile.read(content_length)
        try:
            body = raw.decode('utf-8')
        except UnicodeDecodeError:
            self._send_text('Invalid encoding', 400)
            return
        form_data = parse_qs(body, keep_blank_values=True)

        submission = {
            '_timestamp': datetime.now(timezone.utc).isoformat(),
        }
        for field in self.fields:
            name = field['name']
            if field['type'] == 'checkbox':
                submission[name] = name in form_data
            else:
                values = form_data.get(name, [''])
                # Truncate rather than reject: a friendly form shouldn't bounce
                # someone for a long answer, but nothing unbounded gets stored.
                submission[name] = str(values[0])[:MAX_FIELD_LEN]

        try:
            count = append_submission(self.output_file, submission)
        except SubmissionsFull:
            sys.stderr.write("[formserver] Refused submission: output file is full\n")
            self._send_text('This form is no longer accepting submissions.', 503)
            return
        except OSError as e:
            # Log the detail locally; the caller gets nothing but "it failed"
            # (exception strings carry filesystem paths).
            sys.stderr.write(f"[formserver] Failed to store submission: {e}\n")
            self._send_text('Could not store submission', 500)
            return

        sys.stderr.write(f"[formserver] New submission ({count} total)\n")
        self._send_html(self.thanks_html)


def main():
    parser = argparse.ArgumentParser(description='Form server')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--name', type=str, required=True)
    parser.add_argument('--fields', type=str, required=True)
    parser.add_argument('--output', type=str, required=True)
    parser.add_argument('--bind', type=str, default='127.0.0.1')
    args = parser.parse_args()

    fields = parse_field_spec(args.fields)
    if not fields:
        sys.stderr.write("[formserver] Error: no valid fields parsed from spec\n")
        sys.exit(1)

    title = format_title(args.name)
    fields_html = '\n'.join(render_field_html(f) for f in fields)

    rendered = FORM_HTML
    rendered = rendered.replace('FORM_TITLE', html.escape(title))
    rendered = rendered.replace('FORM_SUBTITLE', html.escape(args.name))
    rendered = rendered.replace('FORM_FIELDS', fields_html)

    FormHandler.form_html = rendered
    FormHandler.thanks_html = THANKS_HTML
    FormHandler.fields = fields
    FormHandler.output_file = args.output

    server = make_server(FormHandler, args.port, args.bind, tag='form')
    sys.stderr.write(f"[formserver] Listening on :{args.port}, serving form '{args.name}'\n")
    sys.stderr.write(f"[formserver] Fields: {', '.join(f['name'] + ':' + f['type'] for f in fields)}\n")
    sys.stderr.write(f"[formserver] Output: {args.output}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[formserver] Shutting down.\n")
        server.shutdown()


if __name__ == '__main__':
    main()
