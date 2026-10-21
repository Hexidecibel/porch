#!/usr/bin/env python3

"""Chat UI in front of the local LLM router (used by bin/chat).

Public by design: the owner mails the link and whoever has it can talk to the
model. That is the contract — but it means an anonymous caller drives real
compute on this box, so the limits below are the only thing between a shared
link and the "local LLM starves everything else" failure mode:

  * /api/chat caps the request body before reading it, and caps how many
    messages (and how much text) it will forward.
  * A semaphore caps concurrent upstream requests; over that, callers get 503
    with Retry-After instead of the box getting another inference thread.
  * The page is rendered once at startup with its name escaped, and raw HTML
    in the model's markdown is dropped rather than injected into the DOM.
"""

import argparse
import html
import json
import secrets
import os
import sys
import threading
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler
from pathlib import Path

_HERE_LIB = os.path.dirname(os.path.abspath(__file__))
if _HERE_LIB not in sys.path:
    sys.path.insert(0, _HERE_LIB)
from porch_http import (  # noqa: E402  (shared HTTP core)
    content_length, make_server, porch_css_tag, porch_mark, porch_style_src,
    security_headers, serve_asset,
)

# marked + highlight.js are vendored (lib/vendor/, see SOURCES there) and
# served from /static/, so the page needs no third-party script origin and
# its CSP can be 'self' + a per-response nonce instead of 'unsafe-inline'.
VENDOR_DIR = Path(__file__).resolve().parent / 'vendor'
STATIC_FILES = {
    '/static/marked.min.js': ('marked.min.js', 'text/javascript; charset=utf-8'),
    '/static/highlight.min.js': ('highlight.min.js', 'text/javascript; charset=utf-8'),
    '/static/atom-one-dark.min.css': ('atom-one-dark.min.css', 'text/css; charset=utf-8'),
}

# Upstream timeouts. Time-to-first-byte gets a long budget (prompt processing
# on a big context is slow); once streaming, a gap longer than the idle
# timeout means the model has stalled. A client that disconnected is only
# noticed on the next write, so this idle bound is what frees the inflight
# slot when a stalled stream is also abandoned.
UPSTREAM_CONNECT_TIMEOUT = 120
UPSTREAM_IDLE_TIMEOUT = 20

# A chat turn is text a person typed. These are far above any real use and
# exist so an anonymous POST can't turn Content-Length into an allocation.
MAX_BODY = 1024 * 1024          # whole JSON request body
MAX_MESSAGES = 200              # conversation turns forwarded upstream
MAX_MESSAGE_CHARS = 200_000     # total characters forwarded upstream
MAX_SYSTEM_CHARS = 20_000

# Concurrent upstream inferences. The router behind this is shared with
# everything else on the box (see the Plex-buffering incident: one CPU LLM
# pinning RAM and cores took playback down), so a public URL must not be able
# to open an unbounded number of them.
MAX_INFLIGHT = 4
_inflight = threading.BoundedSemaphore(MAX_INFLIGHT)


CHAT_HTML = r"""<!DOCTYPE html>
<html lang="en" data-app="chat">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Chat</title>
__PORCH_CSS__
<script src="/static/marked.min.js"></script>
<link rel="stylesheet" href="/static/atom-one-dark.min.css">
<script src="/static/highlight.min.js"></script>
<style nonce="CSP_NONCE">
body{min-height:100vh;min-height:100dvh}
.container{max-width:900px;margin:0 auto;padding:16px var(--gutter);display:flex;flex-direction:column;gap:14px;height:100vh;height:100dvh}
.chat-head{display:flex;align-items:flex-end;justify-content:space-between;gap:12px;padding:8px 4px 0}
.chat-head .p-title{font-size:26px}
.toolbar{display:flex;gap:8px;flex-shrink:0}
.toolbar button.active{background:var(--accent-soft);border-color:var(--accent-line);color:var(--accent-ink)}
.chat-area{background:var(--surface);border:1px solid var(--line);border-radius:var(--r-2xl);
  display:flex;flex-direction:column;flex:1;min-height:0;overflow:hidden}
.settings-panel{display:none;padding:14px 16px;border-bottom:1px solid var(--line);flex-shrink:0}
.settings-panel textarea{min-height:64px}
.messages{display:flex;flex-direction:column;overflow-y:auto;flex:1;padding:16px;gap:12px}
.messages:empty::before{content:"Ask anything. Messages stay on this page until you clear them.";
  margin:auto;text-align:center;color:var(--muted);font-size:14px;max-width:32ch}
.msg{max-width:82%;padding:12px 16px;line-height:1.55;font-size:15px;overflow-wrap:break-word}
.msg.user{align-self:flex-end;background:var(--accent);color:var(--on-accent);border-radius:16px 16px 4px 16px;white-space:pre-wrap}
.msg.assistant{align-self:flex-start;background:var(--raised);border-radius:16px 16px 16px 4px}
.msg.error{align-self:center;background:var(--danger-soft);border:1px solid var(--danger-line);border-radius:var(--r-lg);font-size:14px;text-align:center}
.streaming-cursor{display:inline-block;width:6px;height:14px;background:var(--accent);border-radius:2px;
  margin-left:3px;vertical-align:text-bottom;animation:pulse 1s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}

/* Markdown content inside assistant bubbles */
.msg.assistant p{margin:.4em 0}
.msg.assistant p:first-child{margin-top:0}
.msg.assistant p:last-child{margin-bottom:0}
.msg.assistant pre{background:#1B181E;color:#F3ECE4;border-radius:var(--r-sm);padding:14px;overflow-x:auto;margin:.6em 0}
.msg.assistant pre code{background:none !important;padding:0;font:400 .88em/1.55 var(--font-mono)}
.msg.assistant code{background:var(--veil);border-radius:4px;padding:2px 6px;font:400 .88em var(--font-mono)}
.msg.assistant ul,.msg.assistant ol{margin:.4em 0;padding-left:1.5em}
.msg.assistant li{margin:.2em 0}
.msg.assistant blockquote{border-left:3px solid var(--accent-line);margin:.5em 0;padding:.3em 0 .3em 12px;color:var(--muted)}
.msg.assistant table{border-collapse:collapse;margin:.5em 0;width:100%}
.msg.assistant th,.msg.assistant td{border:1px solid var(--line-strong);padding:6px 10px;text-align:left;font-size:.9em}
.msg.assistant th{background:var(--veil)}
.msg.assistant hr{border:0;border-top:1px solid var(--line-strong);margin:.8em 0}
.msg.assistant h1,.msg.assistant h2,.msg.assistant h3,.msg.assistant h4,.msg.assistant h5,.msg.assistant h6{
  font-family:var(--font-display);letter-spacing:-.01em;margin:.6em 0 .3em}
.msg.assistant h1{font-size:1.3em}
.msg.assistant h2{font-size:1.15em}
.msg.assistant h3{font-size:1.05em}
.input-area{display:flex;gap:10px;padding:12px;border-top:1px solid var(--line);flex-shrink:0;align-items:flex-end}
.input-area textarea{flex:1;resize:none;min-height:var(--control-h);max-height:150px;padding:12px 14px}
.send-btn{flex-shrink:0;width:var(--control-h);padding:0}
.send-btn svg{width:18px;height:18px;fill:currentColor}
@media(max-width:600px){.msg{max-width:90%}}
</style>
</head>
<body>
<div class="container">
  <header class="chat-head">
    <div class="p-head">
      <div class="p-kicker">__MARK__<span>a chat on a porch</span></div>
      <h1 class="p-title">CHAT_NAME</h1>
    </div>
    <div class="toolbar">
      <button class="p-btn p-btn--ghost p-btn--sm" id="settingsBtn" type="button" aria-controls="settingsPanel">Settings</button>
      <button class="p-btn p-btn--quiet p-btn--sm" id="clearBtn" type="button">Clear</button>
    </div>
  </header>
  <div class="chat-area">
    <div class="settings-panel p-field" id="settingsPanel">
      <label class="p-label" for="systemPrompt">System prompt</label>
      <textarea class="p-textarea" id="systemPrompt">You are a helpful assistant.</textarea>
    </div>
    <div class="messages" id="messages" aria-live="polite"></div>
    <div class="input-area">
      <label class="sr-only" for="input">Message</label>
      <textarea class="p-textarea" id="input" placeholder="Type a message" rows="1"></textarea>
      <button class="p-btn send-btn" id="sendBtn" type="button" aria-label="Send">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>
      </button>
    </div>
  </div>
</div>
<script nonce="CSP_NONCE">
let messages = [];
let streaming = false;
let abortController = null;

marked.setOptions({
  highlight: function(code, lang) {
    if (lang && hljs.getLanguage(lang)) return hljs.highlight(code, {language: lang}).value;
    return hljs.highlightAuto(code).value;
  }
});

// BEGIN markdown-sanitize (tests/test_textapps.py runs this block in node)
// marked passes raw HTML in the markdown straight through, and the rendered
// string goes into innerHTML below. A model that emits `<img src=x
// onerror=...>` — because it was asked to, or because it read that somewhere —
// would otherwise get script running on this origin. Drop HTML tokens instead;
// fenced code blocks are unaffected, they are escaped by the code renderer.
//
// Links and images are the other way in: [x](javascript:...) renders an
// <a href="javascript:..."> that runs on click. Only http(s)/mailto links and
// http(s) images survive; anything else is reduced to its text.
function escAttr(s) {
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;')
    .replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/'/g, '&#39;');
}
function safeUrl(href, schemes) {
  if (typeof href !== 'string' || !href.trim()) return null;
  let u;
  // new URL() normalises the tricks browsers accept (leading spaces,
  // "java\tscript:", entity-free case games) before we look at the scheme.
  try { u = new URL(href.trim(), location.href); } catch (e) { return null; }
  return schemes.indexOf(u.protocol) >= 0 ? u.href : null;
}
marked.use({renderer: {
  html: () => '',
  link(href, title, text) {
    const url = safeUrl(href, ['http:', 'https:', 'mailto:']);
    if (!url) return text;
    const t = title ? ' title="' + escAttr(title) + '"' : '';
    return '<a href="' + escAttr(url) + '"' + t +
      ' target="_blank" rel="noopener noreferrer nofollow">' + text + '</a>';
  },
  image(href, title, text) {
    const url = safeUrl(href, ['http:', 'https:']);
    if (!url) return escAttr(text || '');
    const t = title ? ' title="' + escAttr(title) + '"' : '';
    return '<img src="' + escAttr(url) + '" alt="' + escAttr(text || '') + '"' + t + '>';
  },
}});
// END markdown-sanitize

const messagesEl = document.getElementById('messages');
const inputEl = document.getElementById('input');
const sendBtn = document.getElementById('sendBtn');

inputEl.addEventListener('input', function() {
  this.style.height = 'auto';
  this.style.height = Math.min(this.scrollHeight, 150) + 'px';
});

inputEl.addEventListener('keydown', function(e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    if (!streaming) sendMessage();
  }
});

function toggleSettings() {
  const panel = document.getElementById('settingsPanel');
  const btn = document.getElementById('settingsBtn');
  if (panel.style.display === 'block') {
    panel.style.display = 'none';
    btn.classList.remove('active');
  } else {
    panel.style.display = 'block';
    btn.classList.add('active');
  }
}

function clearChat() {
  messages = [];
  messagesEl.innerHTML = '';
  inputEl.focus();
}

function scrollToBottom() {
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function addBubble(role, content) {
  const div = document.createElement('div');
  div.className = 'msg ' + role;
  if (role === 'assistant') {
    div.innerHTML = marked.parse(content || '');
    div.querySelectorAll('pre code').forEach(el => hljs.highlightElement(el));
  } else if (role === 'error') {
    div.textContent = content;
  } else {
    div.textContent = content;
  }
  messagesEl.appendChild(div);
  scrollToBottom();
  return div;
}

async function sendMessage() {
  const text = inputEl.value.trim();
  if (!text || streaming) return;

  messages.push({role: 'user', content: text});
  addBubble('user', text);

  inputEl.value = '';
  inputEl.style.height = 'auto';
  inputEl.focus();

  const bubble = document.createElement('div');
  bubble.className = 'msg assistant';
  bubble.innerHTML = '<span class="streaming-cursor"></span>';
  messagesEl.appendChild(bubble);
  scrollToBottom();

  streaming = true;
  sendBtn.disabled = true;
  abortController = new AbortController();

  const system = document.getElementById('systemPrompt').value.trim();
  let fullContent = '';

  try {
    const resp = await fetch('/api/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({messages, system}),
      signal: abortController.signal
    });

    if (!resp.ok) {
      const errText = await resp.text();
      bubble.remove();
      addBubble('error', 'Error: ' + (resp.status === 502 ? 'LLM server unreachable' : resp.status + ' ' + errText));
      streaming = false;
      sendBtn.disabled = false;
      return;
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    let streamDone = false;
    while (!streamDone) {
      const {done, value} = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, {stream: true});
      const parts = buffer.split('\n\n');
      buffer = parts.pop();

      for (const part of parts) {
        for (const line of part.split('\n')) {
          if (!line.startsWith('data: ')) continue;
          const data = line.slice(6);
          if (data === '[DONE]') { streamDone = true; break; }
          try {
            const parsed = JSON.parse(data);
            const delta = parsed.choices && parsed.choices[0] && parsed.choices[0].delta;
            if (delta && delta.content) {
              fullContent += delta.content;
              bubble.innerHTML = marked.parse(fullContent) + '<span class="streaming-cursor"></span>';
              bubble.querySelectorAll('pre code').forEach(el => hljs.highlightElement(el));
              scrollToBottom();
            }
          } catch(e) {}
        }
        if (streamDone) break;
      }
    }

    // Process remaining buffer
    if (buffer.trim()) {
      for (const line of buffer.split('\n')) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6);
        if (data === '[DONE]') continue;
        try {
          const parsed = JSON.parse(data);
          const delta = parsed.choices && parsed.choices[0] && parsed.choices[0].delta;
          if (delta && delta.content) {
            fullContent += delta.content;
          }
        } catch(e) {}
      }
    }

    bubble.innerHTML = marked.parse(fullContent || '*No response*');
    bubble.querySelectorAll('pre code').forEach(el => hljs.highlightElement(el));
    scrollToBottom();

    if (fullContent) {
      messages.push({role: 'assistant', content: fullContent});
    }

  } catch(e) {
    if (e.name === 'AbortError') {
      bubble.innerHTML = marked.parse(fullContent || '*Cancelled*');
      bubble.querySelectorAll('pre code').forEach(el => hljs.highlightElement(el));
      if (fullContent) messages.push({role: 'assistant', content: fullContent});
    } else {
      if (fullContent) {
        bubble.innerHTML = marked.parse(fullContent + '\n\n*(stream interrupted)*');
        bubble.querySelectorAll('pre code').forEach(el => hljs.highlightElement(el));
        messages.push({role: 'assistant', content: fullContent});
      } else {
        bubble.remove();
        addBubble('error', 'Network error: could not reach server');
      }
    }
  }

  streaming = false;
  sendBtn.disabled = false;
  abortController = null;
}

document.getElementById('settingsBtn').addEventListener('click', toggleSettings);
document.getElementById('clearBtn').addEventListener('click', clearChat);
sendBtn.addEventListener('click', () => sendMessage());
inputEl.focus();
</script>
</body>
</html>"""


class ChatHandler(BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'
    # Bound how long a half-open or slow-loris connection can hold a thread.
    # Generous, because a streamed answer legitimately takes minutes.
    timeout = 300
    # Don't advertise the Python version to anonymous callers.
    server_version = 'porch'
    sys_version = ''

    name = 'chat'
    llm_url = 'http://127.0.0.1:9600'
    # Router alias, not a concrete model name. Naming a concrete model pins the
    # request to whichever host serves it and bypasses the router's own
    # placement (a big model forced onto a CPU-only host can starve everything
    # else on it). Override with --llm-model only if you truly mean to target
    # one specific host.
    llm_model = 'default'
    chat_html = ''
    chat_parts = ()     # chat_html split at each nonce slot

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith('GET'):
            return
        sys.stderr.write(f"[chatserver] {self.address_string()} - {format % args}\n")

    def _security_headers(self):
        """Headers every response carries.

        nosniff is the important one: it stops a browser from re-deciding that
        an SSE or text/plain body is really HTML and running it on this origin.
        """
        security_headers(self)

    def _send_text(self, text, status=200, extra=None):
        body = text.encode() if isinstance(text, str) else text
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
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
        if path in STATIC_FILES:
            fname, ctype = STATIC_FILES[path]
            try:
                body = (VENDOR_DIR / fname).read_bytes()
            except OSError:
                self._send_text('Not found', 404)
                return
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'public, max-age=86400')
            self._security_headers()
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)
            return
        if path == '' or path == '/':
            nonce = secrets.token_urlsafe(16)
            body = nonce.join(self.chat_parts).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            # Scripts and styles: this origin (vendored marked/highlight.js)
            # and the page's own nonce'd blocks — no 'unsafe-inline', no CDN.
            # Element.style writes from the script are CSSOM, not inline
            # styles, so they are unaffected.
            self.send_header('Content-Security-Policy', (
                "default-src 'none'; "
                f"script-src 'self' 'nonce-{nonce}'; "
                f"{porch_style_src(nonce)}; "
                "img-src 'self' data:; connect-src 'self'; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            ))
            self._security_headers()
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)
            return

        self._send_text('Not found', 404)

    def _clean_messages(self, raw_messages):
        """Whatever the client sent, reduced to a bounded list of chat turns.

        The old code did `llm_messages.extend(data.get('messages', []))` — any
        JSON at all went straight upstream, with no ceiling on how many turns
        or how much text. This keeps only well-formed {role, content} pairs and
        stops at the message/character caps.
        """
        if not isinstance(raw_messages, list):
            return []
        out = []
        budget = MAX_MESSAGE_CHARS
        for item in raw_messages[:MAX_MESSAGES]:
            if not isinstance(item, dict):
                continue
            role = item.get('role')
            content = item.get('content')
            if role not in ('user', 'assistant', 'system') or not isinstance(content, str):
                continue
            if budget <= 0:
                break
            content = content[:budget]
            budget -= len(content)
            out.append({'role': role, 'content': content})
        return out

    def do_POST(self):
        if self.path.split('?')[0].rstrip('/') != '/api/chat':
            self._send_text('Not found', 404)
            return

        # Phase 1: prepare request (no response headers sent yet).
        # Any exception here is safe to convert to a plain error response.
        upstream = None
        acquired = False
        try:
            length = content_length(self)
            if length < 0:
                self.close_connection = True
                self._send_text('Bad Content-Length', 400)
                return
            if length > MAX_BODY:
                # Refused before a single byte is read: the declared size is
                # what an attacker would otherwise turn into an allocation.
                self.close_connection = True
                self._send_text('Request too large', 413)
                return
            if length == 0:
                # No Content-Length (e.g. chunked): BaseHTTPRequestHandler does
                # not de-chunk, and reading an unbounded body is the DoS being
                # avoided here.
                self._send_text('Content-Length required', 411)
                return

            try:
                data = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
                self._send_text('Invalid JSON', 400)
                return
            if not isinstance(data, dict):
                self._send_text('Invalid JSON', 400)
                return

            llm_messages = []
            system_text = data.get('system')
            if isinstance(system_text, str) and system_text.strip():
                llm_messages.append({'role': 'system',
                                     'content': system_text.strip()[:MAX_SYSTEM_CHARS]})
            llm_messages.extend(self._clean_messages(data.get('messages')))
            if not llm_messages:
                self._send_text('No messages', 400)
                return

            payload = json.dumps({
                'model': self.llm_model,
                'messages': llm_messages,
                'stream': True
            }).encode()

            url = f"{self.llm_url}/v1/chat/completions"
            req = urllib.request.Request(
                url,
                data=payload,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )

            # Never hold more than MAX_INFLIGHT inferences open at once. Anyone
            # with the link can POST here, and each one of these pins real RAM
            # and cores on the box for as long as it runs.
            acquired = _inflight.acquire(blocking=False)
            if not acquired:
                self._send_text('Busy — too many chats in flight, try again shortly.',
                                503, extra={'Retry-After': '10'})
                return

            try:
                upstream = urllib.request.urlopen(req, timeout=UPSTREAM_CONNECT_TIMEOUT)
            except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
                sys.stderr.write(f"[chatserver] LLM unreachable: {e}\n")
                self._send_text('LLM server unreachable', 502)
                return
        except Exception as e:
            sys.stderr.write(f"[chatserver] request setup failed: {e}\n")
            self.close_connection = True
            try:
                # Generic text only: internal exception strings carry internal
                # URLs and filesystem paths, and this used to echo str(e).
                self._send_text('Server error', 500)
            except Exception:
                pass
            return
        finally:
            if acquired and upstream is None:
                _inflight.release()

        # Phase 2: stream. Headers are committed after send_response(200);
        # do NOT try to send a new status code here — that would corrupt SSE.
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Accel-Buffering', 'no')
        # The body length isn't known ahead of time and we are not chunking it,
        # so end-of-stream has to be end-of-connection.
        self.send_header('Connection', 'close')
        self.close_connection = True
        self._security_headers()
        self.end_headers()

        # Headers are in: from here on, a long silence is a stalled model.
        _set_read_timeout(upstream, UPSTREAM_IDLE_TIMEOUT)
        try:
            while True:
                line = upstream.readline()
                if not line:
                    break
                self.wfile.write(line)
                self.wfile.flush()
        except BrokenPipeError:
            pass
        except OSError:
            pass
        finally:
            upstream.close()
            _inflight.release()


def _set_read_timeout(resp, secs):
    """Best effort: shorten the socket timeout on an open urllib response.

    urlopen's timeout covers connect + every read alike; there is no public
    knob to change it once the response is open, so reach the socket through
    http.client's reader. If the layout ever differs, keep the old timeout.
    """
    try:
        resp.fp.raw._sock.settimeout(secs)
    except AttributeError:
        pass


def main():
    parser = argparse.ArgumentParser(description='Chat server')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--name', type=str, default='chat')
    parser.add_argument('--llm-url', type=str, default='http://127.0.0.1:9600')
    parser.add_argument('--llm-model', type=str, default=ChatHandler.llm_model)
    parser.add_argument('--bind', type=str, default='127.0.0.1')
    args = parser.parse_args()

    ChatHandler.name = args.name
    ChatHandler.llm_url = args.llm_url.rstrip('/')
    ChatHandler.llm_model = args.llm_model
    # html.escape: --name comes from the tunnel name on the command line, which
    # is not a trusted string, and it lands straight in the page body.
    page = CHAT_HTML.replace('__PORCH_CSS__', porch_css_tag()).replace('__MARK__', porch_mark(16))
    ChatHandler.chat_html = page.replace('CHAT_NAME', html.escape(args.name))
    ChatHandler.chat_parts = tuple(
        piece.replace('CHAT_NAME', html.escape(args.name))
        for piece in page.split('CSP_NONCE'))

    server = make_server(ChatHandler, args.port, args.bind, tag='chat')
    sys.stderr.write(f"[chatserver] Listening on :{args.port}, name='{args.name}', llm={args.llm_url}, model={args.llm_model}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[chatserver] Shutting down.\n")
        server.shutdown()


if __name__ == '__main__':
    main()
