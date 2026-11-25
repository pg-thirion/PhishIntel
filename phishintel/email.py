"""Parse email as untrusted data. Never fetch remote content or open attachments."""
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit
import ipaddress
import re
import unicodedata
from .intel import html_signals

MAX_BYTES = 1024 * 1024
MAX_TEXT = 100_000
MAX_PARTS = 200
MAX_DEPTH = 20
URL = re.compile(r'https?://[^\s<>"\x27]+', re.I)

class PlainHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.chunks = []
        self.links = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "template"}:
            self.hidden += 1
        if tag == "a":
            for key, value in attrs:
                if key == "href" and value:
                    self.links.append(value)
        if tag in {"p", "br", "div", "li"}:
            self.chunks.append(" ")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "template"}:
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden:
            self.chunks.append(data)

@dataclass(frozen=True)
class Email:
    subject: str = ""
    sender: str = ""
    reply_to: str = ""
    body: str = ""
    links: tuple[str, ...] = ()
    attachments: tuple[str, ...] = ()
    authentication: str = ""
    return_path: str = ""
    from_count: int = 1
    html_codes: tuple[str, ...] = ()

    def model_text(self):
        return (self.subject + "\n" + self.body)[:MAX_TEXT]

def parse_eml(raw: bytes) -> Email:
    if len(raw) > MAX_BYTES:
        raise ValueError("Email exceeds the 1 MiB analysis limit.")
    if not raw.strip():
        raise ValueError("Empty email.")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except (RecursionError, ValueError) as exc:
        raise ValueError("Malformed or excessively nested email.") from exc
    plain, html, links, attachments = [], [], [], []
    html_codes = set()
    stack = [(message, 0)]
    count = 0
    while stack:
        part, depth = stack.pop()
        count += 1
        if count > MAX_PARTS or depth > MAX_DEPTH:
            raise ValueError("Email MIME complexity exceeds limits.")
        if part.get_content_type() == "message/rfc822":
            attachments.append("(attached email)")
            continue
        if part.get_content_disposition() == "attachment" or part.get_filename():
            attachments.append(str(part.get_filename() or "(unnamed)")[:200])
            continue
        if part.is_multipart():
            stack.extend((child, depth + 1) for child in reversed(list(part.iter_parts())))
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError, ValueError):
            content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if not isinstance(content, str):
            continue
        content = content[:MAX_TEXT]
        if part.get_content_type() == "text/plain":
            plain.append(content)
        else:
            html_codes.update(html_signals(content))
            parser = PlainHTML()
            parser.feed(content)
            parser.close()
            html.append(" ".join(parser.chunks))
            links.extend(parser.links)
    body = "\n".join(plain or html)[:MAX_TEXT]
    links.extend(URL.findall("\n".join(plain + html)[:MAX_TEXT]))
    return Email(str(message.get("Subject", ""))[:500],
                 str(message.get("From", ""))[:500],
                 str(message.get("Reply-To", ""))[:500],
                 body, tuple(dict.fromkeys(links))[:200],
                 tuple(attachments)[:100],
                 " ".join(str(h) for h in message.get_all("Authentication-Results", []))[:2000],
                 str(message.get("Return-Path", ""))[:500],
                 len(message.get_all("From", [])), tuple(sorted(html_codes)))

def domain(address):
    try:
        return parseaddr(address)[1].rpartition("@")[2].lower().rstrip(".")
    except (ValueError, IndexError):
        return ""

def defang(value):
    value = "".join(c for c in value if unicodedata.category(c) not in {"Cc", "Cf"})[:250]
    return re.sub(r"\.", "[.]", re.sub(r"^http", "hxxp", value, flags=re.I))

def indicators(email: Email):
    """Independent triage observations; not proof of maliciousness."""
    out = []
    def add(level, title, detail):
        out.append({"severity": level, "indicator": title, "detail": detail})
    sender, reply = domain(email.sender), domain(email.reply_to)
    if sender and reply and sender != reply:
        add("review", "Reply-To domain differs", defang(sender) + " vs " + defang(reply))
    for url in dict.fromkeys((*email.links, *URL.findall(email.body[:MAX_TEXT]))):
        if len(out) >= 30:
            break
        try:
            parts = urlsplit(url)
            if parts.scheme.lower() not in {"http", "https"}:
                continue
            host = parts.hostname or ""
            if not host:
                continue
            try:
                ipaddress.ip_address(host)
                add("review", "IP address used as link host", defang(host))
            except ValueError:
                pass
            if "xn--" in host.lower() or any(ord(c) > 127 for c in host):
                add("review", "Internationalised link domain", defang(host))
            if parts.username is not None:
                add("review", "User-info in URL", defang(host))
            if parts.scheme.lower() == "http":
                add("info", "Unencrypted HTTP link", defang(host))
        except ValueError:
            add("review", "Malformed URL", "URL could not be parsed safely.")
    for name in email.attachments:
        if len(out) >= 60:
            break
        if unicodedata.normalize("NFKC", name).rstrip(" .").lower().endswith((".exe", ".scr", ".js", ".vbs", ".lnk", ".iso", ".hta", ".bat", ".cmd", ".ps1", ".docm", ".xlsm")):
            add("review", "Potentially risky attachment type", defang(name))
    if re.search(r"\b(?:spf|dkim|dmarc)\s*=\s*(?:fail|softfail|permerror)\b", email.authentication, re.I):
        add("review", "Reported authentication failure", "Unverified Authentication-Results header; confirm with the receiving mail server.")
    return out
