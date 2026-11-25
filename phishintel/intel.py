"""Offline evidence enrichment. Findings are observations, not proof of phishing."""
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit, parse_qsl
import ipaddress
import json
import re
import unicodedata

URL = re.compile(r'https?://[^\s<>"\x27]+', re.I)
SHORTENERS = frozenset({'bit.ly','tinyurl.com','t.co','is.gd','ow.ly','cutt.ly'})
EXEC = {'exe','scr','js','vbs','lnk','hta','bat','cmd','ps1','msi','com'}
ARCHIVE = {'zip','rar','7z','gz','iso','img'}
DECOY = {'pdf','doc','docx','xls','xlsx','jpg','png','txt'}
BIDI = {'\u202a','\u202b','\u202c','\u202d','\u202e','\u2066','\u2067','\u2068','\u2069'}


def host(value):
    try:
        return value.rstrip('.').lower().encode('idna').decode('ascii')
    except (UnicodeError, AttributeError):
        return ''


def domain(value):
    from email.utils import parseaddr
    try:
        return host(parseaddr(value)[1].rpartition('@')[2])
    except (ValueError, IndexError):
        return ''


def safe(value):
    return ''.join(c for c in value if unicodedata.category(c) not in {'Cc','Cf'})[:250].replace('.', '[.]')


def url_host(value):
    try:
        parts = urlsplit(value)
        return host(parts.hostname) if parts.scheme.lower() in {'http','https'} else ''
    except ValueError:
        return ''


@dataclass(frozen=True)
class IntelPolicy:
    watched: tuple[str, ...] = ()
    protected: tuple[str, ...] = ()

    @classmethod
    def load(cls, path):
        with open(path, 'rb') as handle:
            raw = handle.read(65537)
        if len(raw) > 65536:
            raise ValueError('Policy too large')
        data = json.loads(raw)
        if not isinstance(data, dict) or set(data) - {'watched','protected'}:
            raise ValueError('Invalid policy fields')
        def validate(key):
            values = data.get(key, [])
            if not isinstance(values, list) or len(values) > 100:
                raise ValueError('Invalid policy list')
            result = []
            for value in values:
                if not isinstance(value, str) or len(value) > 253:
                    raise ValueError('Invalid policy domain')
                normalized = host(value)
                if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', normalized):
                    raise ValueError('Invalid policy domain')
                result.append(normalized)
            return tuple(sorted(set(result)))
        return cls(validate('watched'), validate('protected'))


def under(value, suffix):
    return value == suffix or value.endswith('.' + suffix)


def one_edit(a, b):
    if a == b or abs(len(a)-len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x,y in zip(a,b)) == 1
    if len(a) > len(b):
        a,b = b,a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i+1:]


class HTMLSignals(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.codes = set()
        self.anchor = None
        self.label = []
        self.anchor_pairs = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'a':
            self.anchor = a.get('href') or ''
            self.label = []
        if tag == 'form':
            self.codes.add('html_form')
        if tag == 'input' and (a.get('type') or '').lower() == 'password':
            self.codes.add('password_field')
        if tag == 'img' and url_host(a.get('src') or ''):
            self.codes.add('remote_image')
            if a.get('width') == '1' or a.get('height') == '1':
                self.codes.add('tracking_pixel')
        if tag in {'script','iframe','object','embed'}:
            self.codes.add('active_content')
        if 'hidden' in a or re.search(r'display\s*:\s*none|visibility\s*:\s*hidden', a.get('style') or '', re.I):
            self.codes.add('hidden_html')

    def handle_data(self, data):
        if self.anchor is not None and len(self.label) < 100:
            self.label.append(data[:500])

    def handle_endtag(self, tag):
        if tag == 'a' and self.anchor is not None:
            if len(self.anchor_pairs) < 200:
                self.anchor_pairs.append((''.join(self.label), self.anchor))
            self.anchor = None
            self.label = []


def html_signals(text):
    parser = HTMLSignals()
    parser.feed(text[:100_000])
    parser.close()
    for label, target in parser.anchor_pairs:
        shown = URL.search(label)
        if shown and url_host(shown.group()) and url_host(target) and url_host(shown.group()) != url_host(target):
            parser.codes.add('anchor_mismatch')
    return tuple(sorted(parser.codes))


HTML_CODES = {
    'html_form': ('review','Email contains an HTML form'),
    'password_field': ('high','Email contains a password input'),
    'remote_image': ('info','Remote image reference; not fetched'),
    'tracking_pixel': ('review','Possible tracking pixel'),
    'active_content': ('review','Active HTML content; not executed'),
    'hidden_html': ('review','Hidden HTML element'),
    'anchor_mismatch': ('high','Displayed URL host differs from link target'),
}


def enrich(email, policy=IntelPolicy()):
    findings = {}
    domains = set()
    def add(code, severity, detail):
        # At most one bounded, sanitised observation per rule.
        findings.setdefault(code, {'code':code,'severity':severity,'detail':safe(detail)})
    sender = domain(email.sender)
    reply = domain(email.reply_to)
    return_path = domain(getattr(email, 'return_path', ''))
    if getattr(email, 'from_count', 1) > 1:
        add('multiple_from','high','Multiple From headers')
    if not sender:
        add('missing_sender','info','Sender domain unavailable')
    if sender and return_path and sender != return_path:
        add('return_path_mismatch','info','Envelope and visible sender domains differ; may be legitimate')
    for d in (sender,reply,return_path):
        if d:
            domains.add(d)
    for code in getattr(email, 'html_codes', ()):
        if code in HTML_CODES:
            add(code,*HTML_CODES[code])
    links = list(dict.fromkeys((*email.links, *URL.findall(email.body[:100_000]))))[:200]
    for url in links:
        try:
            p = urlsplit(url[:8192])
            d = url_host(url[:8192])
            if not d:
                continue
            domains.add(d)
            if d in SHORTENERS:
                add('shortened_url','review',d)
            if len(d.split('.')) >= 5:
                add('deep_subdomain','review',d)
            if p.port is not None and p.port != (443 if p.scheme.lower() == 'https' else 80):
                add('nonstandard_port','review',d)
            if re.search(r'%[0-9a-f]{2}', p.netloc, re.I):
                add('encoded_authority','review',d)
            if any(k.lower() in {'redirect','redirect_uri','return','returnurl','next','url'} and url_host(v)
                   for k,v in parse_qsl(p.query, max_num_fields=100)):
                add('redirect_parameter','review',d)
        except ValueError:
            add('url_parse_error','review','URL structure or query exceeds parsing limits')
    for d in sorted(domains):
        if any(under(d, w) for w in policy.watched):
            add('watchlist_match','high',d)
        if not any(under(d, p) for p in policy.protected):
            for p in policy.protected:
                # Compare full domain or its same-length suffix, not a public-suffix guess.
                candidate = '.'.join(d.split('.')[-len(p.split('.')):])
                if one_edit(candidate, p):
                    add('lookalike_domain','review',d)
                    break
    for name in email.attachments[:100]:
        n = unicodedata.normalize('NFKC',name).lower().rstrip(' .')
        parts = n.split('.')
        ext = parts[-1]
        if set(name) & BIDI:
            add('bidi_filename','high','Bidirectional control in attachment filename')
        if len(parts) >= 3 and parts[-2] in DECOY and ext in EXEC:
            add('double_extension','high','Document-like name with executable extension')
        if ext in ARCHIVE:
            add('archive_attachment','review','Archive or disk image; contents not inspected')
        if ext in {'html','htm','mhtml','svg'}:
            add('html_attachment','review','HTML or SVG attachment; not rendered')
        if ext in {'docm','xlsm','pptm'}:
            add('macro_document','review','Macro-enabled document; not opened')
        if n == '(attached email)' or ext == 'eml':
            add('nested_email','info','Attached message; not inspected')
    text = (email.subject + '\n' + email.body)[:100_000].lower()
    for code, pattern, detail in (
        ('urgency_language',r'\b(?:urgent|immediately|final notice|within 24 hours)\b','Urgency or deadline language'),
        ('credential_request',r'\b(?:verify|confirm|enter|submit|update)\b.{0,40}\b(?:password|credentials|login details)\b','Possible credential request'),
        ('payment_request',r'\b(?:wire transfer|bank details|payment instructions|bank account)\b','Payment or banking language'),
        ('gift_card_request',r'\bgift cards?\b','Gift card language'),
    ):
        if re.search(pattern,text):
            add(code,'review',detail)
    return {'findings':sorted(findings.values(),key=lambda x:({'high':0,'review':1,'info':2}[x['severity']],x['code'])),
            'domains':[safe(d) for d in sorted(domains)[:100]], 'link_count':len(links),
            'attachment_count':len(email.attachments)}


def triage(result, evidence, legacy=()):
    levels = {f['severity'] for f in evidence['findings']}
    levels.update(f['severity'] for f in legacy)
    verdict = result['verdict']
    priority = ('high' if verdict == 'Likely phishing' or 'high' in levels else
                'review' if verdict != 'Likely legitimate' or 'review' in levels else 'routine')
    return {'priority':priority,'action':'Escalate for independent verification' if priority != 'routine' else 'Verify unexpected requests independently',
            'automatic_clearance':False}


def summary(result, evidence, decision):
    """Shareable metadata only; excludes domains, raw text and explanation terms."""
    return {'schema':1,'verdict':result['verdict'],'score':result['score'],
            'priority':decision['priority'],'indicator_codes':[f['code'] for f in evidence['findings']],
            'link_count':evidence['link_count'],'attachment_count':evidence['attachment_count']}
