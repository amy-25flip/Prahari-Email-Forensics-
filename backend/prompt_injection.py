"""Detects content crafted to manipulate an automated classifier -- this
platform's own model, or any downstream LLM-based analyst assistant that
might ingest this email later -- rather than to deceive a human reader.

This is a real, emerging evasion technique distinct from a classic phishing
lure: `text` passed to scan() below is exactly what engine.py's own pipeline
extracts from the email and feeds to ml.classify() and every language
heuristic (general_detection.language_checks), so an instruction an attacker
hides from a human reader (invisible CSS styling, zero-width Unicode
characters) but leaves in that extracted text reaches the model precisely
as written -- the exact vector this module exists to catch.

Pattern-based heuristic only, matching this project's other detection
modules (general_detection.py): presence of these patterns is a strong,
explainable signal -- a legitimate email has no legitimate reason to address
instructions to an AI system -- but this module does not claim to catch
every injection technique, and a clear result is not proof the email is
safe. It also does not claim to catch every way HTML can hide content: only
display:none/visibility:hidden/zero font-size/zero opacity via an inline
style attribute are recognized. class-based CSS, `mso-hide:all`,
`max-height:0`, off-screen positioning, `color:transparent` and
media-query-hidden fragments are known, deliberately out-of-scope gaps, not
oversights.
"""
import re
from html.parser import HTMLParser

# Each pattern is deliberately narrow (tied to AI/classifier-specific
# framing, not generic business language) to keep false positives low on
# ordinary corporate email -- see test_prompt_injection.py's negative cases.
# Two review rounds (Codex) reshaped this list: the first found several
# still too broad (e.g. "do not mark this email as [anything]" matched
# "do not mark this email as read/closed") or missing close variants; the
# second found the fix for one of those had gone too far the other way
# (missed "mark this EMAIL as legitimate") and that a new pattern
# ("return only approved/clean") was itself broad enough to match ordinary
# business phrasing ("return only approved invoices"). Both addressed below,
# with regression tests for every specific example raised.
INSTRUCTION_PATTERNS = [
    (re.compile(r'\bignor(?:e|ing)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+(?:system\s+)?instructions?\b', re.I),
     'Instructs an AI system to ignore its previous instructions'),
    (re.compile(r'\bdisregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|context|rules?|prompts?)\b', re.I),
     'Instructs an AI system to disregard prior context or rules'),
    (re.compile(r'\b(?:new|updated|revised)\s+system\s+(?:instructions?|prompt)\s*[:\-]', re.I),
     'Injects new "system instructions" addressed to an AI system'),
    (re.compile(r'\byou\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|uncensored|jailbroken|in\s+(?:developer|debug|admin|god|dan)\s+mode)\b', re.I),
     "Attempts to reassign an AI system's role into an unrestricted mode"),
    (re.compile(r'\bact\s+as\s+(?:an?\s+)?(?:AI|language model|chatbot|assistant)\s+(?:with\s+no|without)\b', re.I),
     'Attempts AI roleplay framing to bypass restrictions'),
    (re.compile(r'\b(?:enter|enable|activate)\s+(?:developer|debug|admin|god|jailbreak|DAN)\s+mode\b', re.I),
     'Attempts to activate a privileged or safety-bypass mode'),
    (re.compile(r'\bdo\s+not\s+(?:flag|report|classify|mark|log)\s+this\s+(?:email\s+)?as\s+(?:suspicious|spam|phishing|malicious|a\s+threat)\b', re.I),
     'Instructs a classifier not to flag this email as suspicious'),
    (re.compile(r'\b(?:mark|classify|rate|label)\s+(?:this|it)(?:\s+(?:email|message))?\s+as\s+(?:safe|legitimate|not\s+phishing|benign|non-?malicious|clean)\b', re.I),
     'Instructs a classifier to mark this email safe'),
    (re.compile(r'\b(?:return|respond|output)\s+only\s+(?:with\s+)?["\']?(?:safe|legitimate|ok|approved|benign|clean)["\']?\s+as\s+(?:your|the)\s+(?:answer|verdict|classification|response|output|analysis)\b', re.I),
     "Attempts to constrain an AI system's output to a safe verdict"),
    (re.compile(r'\b(?:output|respond\s+with)\s+["\']?legitimate["\']?\s+(?:and|with)\s+no\s+(?:explanation|further\s+(?:analysis|comment))\b', re.I),
     "Attempts to constrain an AI system's output and suppress its reasoning"),
    (re.compile(r'\boverride\s+(?:your|the)\s+(?:instructions|classification|analysis|filter)\b', re.I),
     "Instructs an AI system to override its own analysis"),
    (re.compile(r'\bbypass\s+(?:the|your)\s+(?:spam\s+)?(?:filter|detection|classifier)\b', re.I),
     'Instructs bypassing a detection system'),
    (re.compile(r'\b(?:reveal|print|show|display|repeat|provide|leak|tell\s+me|ignore|override|disregard)\s+(?:your|the)\s+system\s+prompt\b', re.I),
     'Attempts to extract or override an AI system\'s system prompt'),
    (re.compile(r'\[\s*system\s*\]|<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|assistant\|>|###\s*instruction\b', re.I),
     'Contains an AI chat-template control token'),
    (re.compile(r'\byou\s+must\s+comply\s+with\s+(?:this|these|the\s+above)\s+instructions?\b', re.I),
     'Attempts to compel AI compliance with injected instructions'),
    (re.compile(r'\bthis\s+email\s+has\s+been\s+(?:pre-?approved|verified\s+safe)\s+by\s+(?:the\s+)?(?:an?\s+)?(?:AI|automated\s+system)\b', re.I),
     'Falsely asserts prior automated approval to influence review'),
]

# Inline-style values treated as "hidden from a human reader". Matched only
# against style attributes found while walking the DOM (see
# _HiddenTextExtractor below), never used to score raw HTML by itself.
HIDDEN_STYLE_VALUE = re.compile(
    r'display\s*:\s*none|visibility\s*:\s*hidden|'
    r'font-size\s*:\s*0(?:px|em|%)?\b|opacity\s*:\s*0(?:\.0+)?\b', re.I)

# Void elements never have an end tag and can't contain children/text --
# tracked separately so a plain (non-self-closed) `<br>`/`<img>`/etc. can't
# push an entry onto the hidden-state stack that's never popped.
_VOID_ELEMENTS = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
                   'link', 'meta', 'param', 'source', 'track', 'wbr'}
_RAW_TEXT_ELEMENTS = {'script', 'style'}  # content here never reaches the model; exclude it entirely


class _HiddenTextExtractor(HTMLParser):
    """Walks the DOM tracking which text sits inside an element (or an
    ancestor of one) styled invisible to a human reader.

    Tracks (tag, hidden) pairs, not just a hidden bool, and on a closing tag
    pops up to and including the nearest matching open tag -- not just one
    entry -- so mismatched/implicit-close HTML (real email HTML is full of
    it) can't leave a stale "hidden" entry on the stack that mislabels a
    later, genuinely visible sibling as hidden. A completely unmatched
    closing tag is simply ignored, matching how browsers degrade."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._stack = []  # list of (tag, hidden) pairs
        self._raw_text_depth = 0  # >0 while inside <script>/<style>
        self.hidden_text = []

    def handle_starttag(self, tag, attrs):
        if tag in _RAW_TEXT_ELEMENTS:
            self._raw_text_depth += 1
        if tag in _VOID_ELEMENTS:
            return
        style = dict(attrs).get('style', '') or ''
        is_hidden = bool(HIDDEN_STYLE_VALUE.search(style))
        parent_hidden = self._stack[-1][1] if self._stack else False
        self._stack.append((tag, is_hidden or parent_hidden))

    def handle_endtag(self, tag):
        if tag in _RAW_TEXT_ELEMENTS and self._raw_text_depth > 0:
            self._raw_text_depth -= 1
        if tag in _VOID_ELEMENTS:
            return
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                return
        # No matching open tag -- ignore, rather than popping something unrelated.

    def handle_data(self, data):
        if self._raw_text_depth:
            return  # script/style content never reaches the classifier at all
        if self._stack and self._stack[-1][1]:
            self.hidden_text.append(data)


# Explicit \u escapes, not literal characters -- these codepoints are
# invisible in a source file too, which would make this file itself
# impossible to review for exactly the class of bug it exists to catch.
ZERO_WIDTH_CHARS = '\u200b\u200c\u200d\u2060\ufeff'  # ZWSP, ZWNJ, ZWJ, word joiner, BOM -- explicit escapes, not literal invisible chars, so this stays reviewable
_ZERO_WIDTH_RE = re.compile('[' + ZERO_WIDTH_CHARS + ']')
_ZERO_WIDTH_THRESHOLD = 5  # a handful can appear from ordinary copy/paste; a cluster suggests deliberate use

# hidden_content_present is intentionally 0-weight/informational -- see
# engine.py's manipulation_points map. Kept here so scan() itself can decide
# `status` without engine.py needing to know which indicator types matter.
_INFORMATIONAL_TYPES = {'hidden_content_present'}


def _find_instruction(text):
    for pattern, description in INSTRUCTION_PATTERNS:
        match = pattern.search(text)
        if match:
            return description, match.group(0).strip()[:120]
    return None


def scan(text, html_sources=()):
    """text: the already-extracted subject+body text this platform's own
    pipeline feeds to its classifier and language heuristics -- checking
    this directly (not re-parsing HTML) proves a matched instruction_pattern
    is exactly what the model sees. html_sources: the raw HTML of each
    text/html MIME part, used only to find text hidden from a human reader
    (via CSS) that ALSO reaches the classifier (since HTMLText's own
    extraction -- and this module's own hidden-text walk -- both include
    display:none/etc. content; only <script>/<style> content and HTML
    comments are excluded). Never raises; always returns a dict.

    A hidden instruction is deliberately reported as BOTH instruction_pattern
    (it's real text sitting in `text`) and hidden_instruction (it was also
    specifically hidden from a human reader) -- two distinct facts about the
    same content, not double-counting a single fact. Both contribute points,
    capped at the group level in engine.py."""
    text = text or ''
    indicators = []

    for pattern, description in INSTRUCTION_PATTERNS:
        match = pattern.search(text)
        if match:
            indicators.append({'type': 'instruction_pattern', 'description': description,
                                'excerpt': match.group(0).strip()[:120]})

    zero_width_count = len(_ZERO_WIDTH_RE.findall(text))
    if zero_width_count >= _ZERO_WIDTH_THRESHOLD:
        indicators.append({'type': 'zero_width_characters',
                            'description': f'{zero_width_count} zero-width/invisible Unicode characters in the '
                                           'message text -- can hide or obfuscate content from a human reader '
                                           'while it still reaches automated text extraction.',
                            'excerpt': None})

    # Hidden CSS styling is extremely common in ordinary marketing/ESP email
    # (preheader text, responsive desktop/mobile fragments) and must never
    # score on its own -- only when the specific hidden text itself matches
    # an instruction pattern is it treated as a manipulation attempt, since
    # that's the only case actually proving something was hidden from a
    # human reader while still being fed to the classifier.
    for html in html_sources:
        extractor = _HiddenTextExtractor()
        try:
            extractor.feed(html or '')
        except Exception:
            continue  # malformed HTML must degrade to "nothing found", never crash the scan
        hidden_text = ' '.join(extractor.hidden_text)
        if not hidden_text.strip():
            continue
        found = _find_instruction(hidden_text)
        if found:
            description, excerpt = found
            indicators.append({'type': 'hidden_instruction',
                                'description': f'Hidden (display:none/zero-opacity/etc.) content contains an '
                                                f'AI-directed instruction pattern: {description}',
                                'excerpt': excerpt})
        else:
            indicators.append({'type': 'hidden_content_present',
                                'description': 'Email contains CSS-hidden content not visible to a human reader. '
                                                'Common in legitimate marketing email (preheader text); on its own '
                                                'this is informational, not a manipulation signal.',
                                'excerpt': None})

    # HTML comments are NOT included in classifier_text -- engine.py's own
    # HTMLText parser never emits comment content via handle_data, so an
    # instruction hidden only in a comment does not currently reach
    # ml.classify(). Reported as a distinct, honestly-labeled raw-HTML-only
    # signal (worth an analyst's attention -- and worth revisiting if this
    # platform later feeds raw HTML to an LLM-based assistant) rather than
    # folded into instruction_pattern, which would overclaim what the model
    # actually saw. Every comment is scanned (no count cap): padding harmless
    # comments ahead of a payload must not be a free evasion, and MAX_BYTES
    # already bounds the whole email (so worst-case comment count/size).
    combined_html = '\n'.join(html_sources)
    for comment in re.findall(r'<!--(.*?)-->', combined_html, re.S):
        found = _find_instruction(comment)
        if found:
            description, excerpt = found
            indicators.append({'type': 'hidden_comment_raw_html_only',
                                'description': f'HTML comment (not part of the text the current classifier '
                                                f'analyzes) contains an AI-directed instruction pattern: '
                                                f'{description}',
                                'excerpt': excerpt})

    # status is severity-aware: purely informational indicators (hidden
    # content with no instruction in it) must not read as "flagged" the same
    # way an actual instruction pattern does -- an ordinary preheader-text
    # email should not look like a manipulation attempt to an API client,
    # export, or future UI that only checks `status`.
    real_indicators = [i for i in indicators if i['type'] not in _INFORMATIONAL_TYPES]
    if real_indicators:
        status = 'flagged'
    elif indicators:
        status = 'informational'
    else:
        status = 'clear'

    return {
        'status': status,
        'indicators': indicators,
        'detail': 'Pattern-based heuristic for content crafted to manipulate an automated classifier or an AI '
                   'analyst assistant, not a general-purpose prompt-injection defense. Presence is a strong, '
                   'explainable signal; absence does not prove the email is safe.',
    }
