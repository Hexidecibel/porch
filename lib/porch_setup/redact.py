"""Process-wide secret redaction.

Every secret value this process reads or writes (secretstore.get/put, secret
Inputs) is registered here, and every line that leaves the process through
the engine (state file, log file, IO events, recorded Runner calls) goes
through `redact()` first.

    from porch_setup import redact
    redact.REDACTOR.add(value)       # usually done for you by secretstore
    redact.REDACTOR.redact(text)     # -> text with every known value masked

Tests make their own `Redactor()` and pass it to make_context(redactor=...).
"""

import json
import threading

MASK = "[redacted]"
MIN_LEN = 4  # shorter values would mangle ordinary output


class Redactor:
    def __init__(self):
        self._values = set()
        self._lock = threading.Lock()

    def add(self, value):
        """Register a secret value (str or bytes). Values shorter than
        MIN_LEN are ignored. Multi-line values (keys) also register each
        line of 8+ characters, and the JSON-escaped form is registered so
        the value is caught inside serialized state."""
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        if not isinstance(value, str) or len(value) < MIN_LEN:
            return
        forms = {value, value.strip(), json.dumps(value)[1:-1]}
        if "\n" in value:
            forms.update(ln.strip() for ln in value.splitlines() if len(ln.strip()) >= 8)
        with self._lock:
            self._values.update(f for f in forms if len(f) >= MIN_LEN)

    def redact(self, text):
        if not isinstance(text, str) or not text:
            return text
        with self._lock:
            values = sorted(self._values, key=len, reverse=True)
        for v in values:
            if v in text:
                text = text.replace(v, MASK)
        return text

    def redact_obj(self, obj):
        """Redact every string inside a JSON-like structure (keys too)."""
        if isinstance(obj, str):
            return self.redact(obj)
        if isinstance(obj, dict):
            return {self.redact(k) if isinstance(k, str) else k: self.redact_obj(v)
                    for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.redact_obj(v) for v in obj]
        return obj

    def __contains__(self, value):
        with self._lock:
            return value in self._values

    def clear(self):
        with self._lock:
            self._values.clear()


REDACTOR = Redactor()
