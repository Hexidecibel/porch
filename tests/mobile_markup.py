"""Markup checks for pages people open on phones (used by several test files).

check_pickers: every file picker is a real <input type=file> that iOS Safari
and Android will open with their Photo Library / gallery option: no `capture`
(that forces the camera), no `*/*` or odd accept list, not hidden from
assistive tech or the tab order, and activated natively by a <label> (wrapping
it or pointing at it with `for`), never by JS calling .click() on it.

check_responsive: a width=device-width viewport, and no fixed pixel width
wider than the smallest phone (320px) in the page's own <style>.
"""
import re
from html.parser import HTMLParser

SANE_ACCEPT = re.compile(r'^(?:(?:image|video|audio)/\*|\.[a-z0-9]+)$', re.I)
MIN_PHONE = 320


class _Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []          # open elements: (tag, attrs)
        self.inputs = {}         # id -> (attrs, inside_label)
        self.label_for = set()
        self.viewport = None
        self.styles = []
        self._in_style = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'meta' and a.get('name') == 'viewport':
            self.viewport = a.get('content', '')
        if tag == 'label' and a.get('for'):
            self.label_for.add(a['for'])
        if tag == 'input' and (a.get('type') or '').lower() == 'file':
            inside = any(t == 'label' for t, _ in self.stack)
            self.inputs[a.get('id')] = (a, inside)
        if tag == 'style':
            self._in_style = True
            self.styles.append('')
        if tag not in ('input', 'meta', 'link', 'br', 'img', 'source', 'path'):
            self.stack.append((tag, a))

    def handle_endtag(self, tag):
        if tag == 'style':
            self._in_style = False
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if self._in_style:
            self.styles[-1] += data


def parse(html):
    p = _Parser()
    p.feed(html)
    return p


def check_pickers(tc, html, multiple=(), single=()):
    """Assert the pickers with these ids are native, label-activated inputs."""
    p = parse(html)
    for pid in tuple(multiple) + tuple(single):
        tc.assertIn(pid, p.inputs, f'no <input type=file id={pid}>')
        a, inside = p.inputs[pid]
        tc.assertNotIn('capture', a, f'{pid}: capture forces the camera, no photo library')
        for part in filter(None, (x.strip() for x in (a.get('accept') or '').split(','))):
            tc.assertRegex(part, SANE_ACCEPT, f'{pid}: odd accept entry {part!r}')
        tc.assertNotIn('disabled', a)
        tc.assertNotEqual(a.get('aria-hidden'), 'true', f'{pid}: hidden from assistive tech')
        tc.assertNotEqual(a.get('tabindex'), '-1', f'{pid}: not reachable by keyboard')
        if pid in multiple:
            tc.assertIn('multiple', a, f'{pid}: must allow picking several photos')
        else:
            tc.assertNotIn('multiple', a)
        tc.assertTrue(inside or pid in p.label_for, f'{pid}: no <label> activates it')
        # No script forwards a tap to it: that is what iOS refuses.
        for pat in (rf"getElementById\(['\"]{pid}['\"]\)\.click\(\)",
                    rf"\$\(['\"]{pid}['\"]\)\.click\(\)"):
            tc.assertIsNone(re.search(pat, html), f'{pid}: opened by JS .click()')
    # The usual forwarding idiom on a variable (fi.click()) is gone too.
    tc.assertIsNone(re.search(r'\bfi\.click\(\)', html))
    # pointer-events:none on a file input is what made the forwarding necessary
    css = '\n'.join(p.styles)
    tc.assertIsNone(re.search(r'input[^{}]*\{[^}]*pointer-events:\s*none', css))


def check_responsive(tc, html):
    p = parse(html)
    tc.assertIsNotNone(p.viewport, 'no viewport meta')
    tc.assertIn('width=device-width', p.viewport)
    tc.assertIn('initial-scale=1', p.viewport)
    tc.assertNotIn('user-scalable=no', p.viewport)
    css = '\n'.join(p.styles)
    for m in re.finditer(r'(?<![-\w(])(?:min-)?width\s*:\s*(\d+)px', css):
        tc.assertLessEqual(int(m.group(1)), MIN_PHONE, f'fixed width in page CSS: {m.group(0)}')
    return p, css
