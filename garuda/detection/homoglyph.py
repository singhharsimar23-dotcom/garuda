import unicodedata
from typing import List, Tuple

# Comprehensive Unicode Confusable Mapping (Spec Additions + Standard Cyrillic/Greek/Latin Lookalikes)
CONFUSABLE_MAP: dict[str, str] = {
    # Exact specification additions
    "ɑ": "a",
    "ƅ": "b",
    "ϲ": "c",
    "ⅾ": "d",
    "ꬲ": "e",
    "ꞙ": "f",
    "ɡ": "g",
    "ĸ": "k",
    "ɩ": "i",
    "ʝ": "j",
    "ⅼ": "l",
    "ɱ": "m",
    "ŋ": "n",
    "ⲟ": "o",
    "ρ": "p",
    "զ": "q",
    "ꞧ": "r",
    "ƽ": "s",
    "ŧ": "t",
    "ⅴ": "v",
    "ʍ": "w",
    "ⅹ": "x",
    "ʏ": "y",
    "ƶ": "z",
    # Cyrillic Confusables
    "а": "a",
    "А": "A",
    "б": "b",
    "в": "v",
    "г": "r",
    "д": "d",
    "е": "e",
    "Е": "E",
    "ж": "zh",
    "з": "z",
    "і": "i",
    "І": "I",
    "ј": "j",
    "Ј": "J",
    "к": "k",
    "К": "K",
    "м": "m",
    "М": "M",
    "н": "n",
    "Н": "H",
    "о": "o",
    "О": "O",
    "п": "n",
    "р": "p",
    "Р": "P",
    "с": "c",
    "С": "C",
    "т": "t",
    "Т": "T",
    "у": "y",
    "У": "Y",
    "ф": "f",
    "х": "x",
    "Х": "X",
    "ц": "ts",
    "ч": "ch",
    "ш": "sh",
    "щ": "sh",
    "ы": "y",
    "ь": "",
    "э": "e",
    "ю": "yu",
    "я": "ya",
    # Greek Confusables
    "α": "a",
    "β": "b",
    "γ": "y",
    "δ": "d",
    "ε": "e",
    "ζ": "z",
    "η": "n",
    "θ": "th",
    "ι": "i",
    "κ": "k",
    "λ": "l",
    "μ": "u",
    "ν": "v",
    "ξ": "x",
    "ο": "o",
    "π": "n",
    "σ": "s",
    "τ": "t",
    "υ": "u",
    "φ": "f",
    "χ": "x",
    "ψ": "ps",
    "ω": "w",
}


def normalize_domain(domain: str) -> str:
    """
    Normalize domain name using NFKD decomposition, confusable translation, and ASCII conversion.

    Args:
        domain: Input domain string potentially containing unicode homoglyphs.

    Returns:
        Normalized lowercase ASCII domain string.
    """
    if not domain:
        return ""

    # Decompose unicode characters via NFKD
    decomposed = unicodedata.normalize("NFKD", domain.lower().strip().lstrip("*."))

    # Map character by character through confusable dictionary
    translated = []
    for char in decomposed:
        if char in CONFUSABLE_MAP:
            translated.append(CONFUSABLE_MAP[char])
        else:
            translated.append(char)

    joined = "".join(translated)

    # Encode to ASCII, ignoring non-translatable combining marks/accents
    ascii_normalized = (
        unicodedata.normalize("NFKD", joined)
        .encode("ascii", "ignore")
        .decode("ascii")
    )
    return ascii_normalized.lower()


def detect_homoglyph(domain: str) -> Tuple[bool, List[str]]:
    """
    Detect presence of internationalized unicode homoglyphs or lookalike spoofing characters.

    Args:
        domain: Target domain to test.

    Returns:
        Tuple of:
            - bool: True if one or more homoglyphs were detected, False otherwise.
            - list[str]: List of offending non-ASCII or confusable characters detected.
    """
    if not domain:
        return False, []

    detected_chars: List[str] = []
    cleaned = domain.lower().strip().lstrip("*.")

    for char in cleaned:
        if char in CONFUSABLE_MAP or ord(char) > 127:
            detected_chars.append(char)

    has_homoglyphs = len(detected_chars) > 0
    return has_homoglyphs, detected_chars
