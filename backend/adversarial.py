"""Adversarial-input detection for the NLP classifier.

Attackers who know a BERT-style classifier is in the loop can substitute Latin
letters with visually identical Cyrillic/Greek homoglyphs (e.g. Cyrillic 'а'
U+0430 for Latin 'a') or inject zero-width characters. A human reads the same
words, but the tokenizer fragments the text and the model's phishing probability
collapses. This module builds a normalized "skeleton" of the text; the engine
classifies both the raw text and the skeleton and flags a large probability
jump as an evasion attempt.

The confusables map is a curated set of the characters actually used in phishing
homoglyph attacks -- not the full Unicode UTS-39 confusables table."""
import unicodedata

ZERO_WIDTH = '​‌‍⁠﻿­'  # ZWSP, ZWNJ, ZWJ, word-joiner, BOM, soft hyphen

CONFUSABLES = {
    # Cyrillic -> Latin (lowercase)
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ј': 'j',
    'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ո': 'n', 'к': 'k',
    'м': 'm', 'т': 't', 'н': 'h', 'в': 'b',
    # Cyrillic -> Latin (uppercase)
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M',
    'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T',
    'Х': 'X', 'Ѕ': 'S', 'І': 'I', 'Ј': 'J',
    # Greek -> Latin
    'ο': 'o', 'α': 'a', 'ε': 'e', 'ρ': 'p', 'ν': 'v',
    'τ': 't', 'η': 'n', 'κ': 'k', 'ι': 'i', 'υ': 'u',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H',
    'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O',
    'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
}


def contains_suspect(text):
    """Cheap gate: is there any zero-width or known confusable character? Only
    then is the second (normalized) classification worth running."""
    return isinstance(text, str) and any(ch in ZERO_WIDTH or ch in CONFUSABLES for ch in text)


def skeleton(text):
    """Normalized form: drop zero-width characters, fold confusables to their
    Latin look-alike, then NFKC-normalize. This is the text as a human reads it."""
    if not isinstance(text, str):
        return text
    stripped = ''.join(ch for ch in text if ch not in ZERO_WIDTH)
    folded = ''.join(CONFUSABLES.get(ch, ch) for ch in stripped)
    return unicodedata.normalize('NFKC', folded)
