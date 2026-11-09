"""
Text Normalization and Obfuscation De-cloaking.
Performs NFKC normalization, strips zero-width and bidi characters,
folds Cyrillic/Greek homoglyphs, performs leetspeak folding,
and detects/decodes inline Base64, Hex, and ROT13 payloads.
"""

import re
import unicodedata
import base64
import codecs
from typing import Tuple, List

# Cyrillic and Greek homoglyphs to Latin ASCII
HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԏ': 't', 'ԝ': 'w',
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
    'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'У': 'Y',
    'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v',
    'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x'
}

# Basic Leetspeak replacements
LEET_MAP = {
    '4': 'a', '@': 'a',
    '3': 'e',
    '1': 'i', '!': 'i', '|': 'i',
    '0': 'o',
    '5': 's', '$': 's',
    '7': 't', '+': 't'
}

# Zero-width and bidirectional control characters
RE_STRIP_CHARS = re.compile(r'[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069]')


def strip_invisible_chars(text: str) -> str:
    """Strip zero-width spaces, joiners, and bidi override characters."""
    return RE_STRIP_CHARS.sub('', text)


def fold_homoglyphs(text: str) -> str:
    """Convert lookalike Unicode characters to Latin ASCII equivalents."""
    return "".join(HOMOGLYPH_MAP.get(c, c) for c in text)


def fold_leetspeak(text: str) -> str:
    """Fold common leetspeak substitutions to standard characters."""
    return "".join(LEET_MAP.get(c, c) for c in text)


def try_decode_base64(candidate: str) -> str:
    """Attempt decoding a base64 string if it decodes to printable text."""
    clean = re.sub(r'\s+', '', candidate)
    if len(clean) < 12 or len(clean) % 4 != 0:
        return ""
    try:
        decoded_bytes = base64.b64decode(clean, validate=True)
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
        # Check if contains significant printable ASCII
        printable_ratio = sum(1 for c in decoded_str if 32 <= ord(c) <= 126) / max(1, len(decoded_str))
        if printable_ratio > 0.85 and len(decoded_str) >= 8:
            return decoded_str
    except Exception:
        pass
    return ""


def try_decode_hex(candidate: str) -> str:
    """Attempt decoding a hex-encoded string."""
    clean = candidate.replace("0x", "").replace(" ", "")
    if len(clean) < 16 or len(clean) % 2 != 0:
        return ""
    try:
        decoded_bytes = bytes.fromhex(clean)
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
        printable_ratio = sum(1 for c in decoded_str if 32 <= ord(c) <= 126) / max(1, len(decoded_str))
        if printable_ratio > 0.85 and len(decoded_str) >= 8:
            return decoded_str
    except Exception:
        pass
    return ""


def try_decode_rot13(candidate: str) -> str:
    """Decode ROT13 text if key triggers appear."""
    try:
        decoded = codecs.decode(candidate, 'rot_13')
        # If decoded contains strong instruction triggers
        if any(w in decoded.lower() for w in ["ignore", "system", "prompt", "instruction", "password"]):
            return decoded
    except Exception:
        pass
    return ""


def normalize_input(raw_text: str) -> Tuple[str, List[str]]:
    """
    Run comprehensive normalization and payload extraction.
    Returns:
        (normalized_text, list_of_decoded_payloads)
    """
    # 1. Unicode NFKC normalization
    nfkc_text = unicodedata.normalize('NFKC', raw_text)

    # 2. Strip invisible and bidi control characters
    stripped_text = strip_invisible_chars(nfkc_text)

    # 3. Fold homoglyphs
    homoglyph_folded = fold_homoglyphs(stripped_text)

    # 4. Leetspeak folded version
    leet_folded = fold_leetspeak(homoglyph_folded)

    # 5. Extract and decode inline encoded strings
    decoded_payloads: List[str] = []

    # Check for Base64 sequences (e.g. "aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM=")
    b64_matches = re.finditer(r'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', stripped_text)
    for m in b64_matches:
        decoded = try_decode_base64(m.group(0))
        if decoded and decoded not in decoded_payloads:
            decoded_payloads.append(decoded)

    # Check for Hex strings (e.g. "69676e6f726520616c6c2070726576696f7573")
    hex_matches = re.finditer(r'\b(?:0x)?([0-9a-fA-F]{16,})\b', stripped_text)
    for m in hex_matches:
        decoded = try_decode_hex(m.group(0))
        if decoded and decoded not in decoded_payloads:
            decoded_payloads.append(decoded)

    # Check for ROT13
    rot13_candidate = try_decode_rot13(stripped_text)
    if rot13_candidate and rot13_candidate != stripped_text:
        decoded_payloads.append(rot13_candidate)

    # Combine primary normalized forms
    combined_normalized = f"{homoglyph_folded} {leet_folded}"

    return combined_normalized, decoded_payloads
