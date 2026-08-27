import json
import math
from pathlib import Path
import re
from typing import Any, List, Set, Tuple
import numpy as np
try:
    import xgboost as xgb
except ImportError:
    xgb = None

# Global caches for DGA feature engineering
_WORDLIST: Set[str] = set()
_TOP_BIGRAMS: Set[str] = set()
_XGB_MODEL: Any = None


def _load_resources():
    """Load dictionary words and top bigrams once into memory."""
    global _WORDLIST, _TOP_BIGRAMS
    data_dir = Path(__file__).resolve().parent.parent / "data"

    # Words
    words_file = data_dir / "words.txt"
    if words_file.exists() and not _WORDLIST:
        with open(words_file, "r", encoding="utf-8") as f:
            _WORDLIST = {line.strip().lower() for line in f if line.strip()}

    # Bigrams
    bigrams_file = data_dir / "top_bigrams.json"
    if bigrams_file.exists() and not _TOP_BIGRAMS:
        with open(bigrams_file, "r", encoding="utf-8") as f:
            bigrams_data = json.load(f)
            _TOP_BIGRAMS = set(bigrams_data)


def _extract_stem(domain: str) -> str:
    """Extract domain stem excluding TLD and subdomains."""
    parts = domain.lower().strip().lstrip("*.").split(".")
    if len(parts) >= 2:
        return parts[0]
    return domain.lower().strip()


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def _max_consonant_cluster(s: str) -> int:
    """Compute length of longest consecutive sequence of consonants."""
    consonants_regex = re.findall(r"[bcdfghjklmnpqrstvwxyz]+", s.lower())
    if not consonants_regex:
        return 0
    return max(len(c) for c in consonants_regex)


def _dictionary_coverage(stem: str, wordlist: Set[str]) -> float:
    """Compute fraction of stem covered by authentic dictionary words."""
    if not stem or not wordlist:
        return 0.0
    matched_chars = 0
    stem_lower = stem.lower()
    for word in wordlist:
        if len(word) >= 3 and word in stem_lower:
            matched_chars += len(word)
    return min(1.0, float(matched_chars) / float(len(stem)))


def extract_dga_features(domain: str) -> List[float]:
    """
    Extract 8 statistical and linguistic numeric features for DGA classification.

    Features:
        1. length: len(domain_stem)
        2. entropy: Shannon entropy of character distribution
        3. vowel_ratio: count(aeiou) / length
        4. consonant_clusters: max consecutive consonants
        5. digit_ratio: count(digits) / length
        6. unique_char_ratio: len(set(stem)) / len(stem)
        7. bigram_miss_rate: fraction of bigrams not in top English bigrams
        8. dict_coverage: fraction of chars covered by wordlist

    Args:
        domain: Input domain name.

    Returns:
        List[float]: 8-dimensional feature vector.
    """
    _load_resources()
    stem = _extract_stem(domain)
    n = max(1, len(stem))

    # 1. Length
    length_feat = float(len(stem))

    # 2. Shannon Entropy
    entropy_feat = float(_shannon_entropy(stem))

    # 3. Vowel Ratio
    vowels = sum(1 for c in stem if c in "aeiou")
    vowel_ratio = float(vowels) / float(n)

    # 4. Consonant Clusters
    consonant_clusters = float(_max_consonant_cluster(stem))

    # 5. Digit Ratio
    digits = sum(1 for c in stem if c.isdigit())
    digit_ratio = float(digits) / float(n)

    # 6. Unique Character Ratio
    unique_char_ratio = float(len(set(stem))) / float(n)

    # 7. Bigram Miss Rate
    bigrams = [stem[i : i + 2] for i in range(len(stem) - 1)]
    if bigrams:
        misses = sum(1 for b in bigrams if b not in _TOP_BIGRAMS)
        bigram_miss_rate = float(misses) / float(len(bigrams))
    else:
        bigram_miss_rate = 0.5

    # 8. Dictionary Coverage
    dict_coverage = float(_dictionary_coverage(stem, _WORDLIST))

    return [
        length_feat,
        entropy_feat,
        vowel_ratio,
        consonant_clusters,
        digit_ratio,
        unique_char_ratio,
        bigram_miss_rate,
        dict_coverage,
    ]


def _get_model():
    """Load or initialize pre-trained XGBoost DGA classifier."""
    global _XGB_MODEL
    if _XGB_MODEL is not None:
        return _XGB_MODEL

    model_path = Path(__file__).resolve().parent.parent / "data" / "dga_model.json"

    if xgb is not None and model_path.exists():
        try:
            model = xgb.Booster()
            model.load_model(str(model_path))
            _XGB_MODEL = model
            return _XGB_MODEL
        except Exception:
            pass

    return None


def predict_dga(domain: str) -> Tuple[bool, float]:
    """
    Predict whether a domain was algorithmically generated (DGA) by malware or botnets.

    Args:
        domain: Target domain to test.

    Returns:
        Tuple of:
            - bool: True if domain is classified as DGA, False otherwise.
            - float: DGA confidence score between 0.0 and 1.0.
    """
    features = extract_dga_features(domain)
    model = _get_model()

    if model is not None and xgb is not None:
        try:
            dmatrix = xgb.DMatrix(np.array([features]))
            pred = float(model.predict(dmatrix)[0])
            return pred >= 0.5, round(pred, 4)
        except Exception:
            pass

    # Heuristic scoring fallback
    length_f, entropy_f, vowel_r, cons_c, digit_r, uniq_r, bigram_miss, dict_cov = features
    score = 0.0

    if entropy_f > 3.4:
        score += 0.35
    if vowel_r < 0.20 or vowel_r > 0.65:
        score += 0.20
    if cons_c >= 5:
        score += 0.25
    if bigram_miss > 0.60:
        score += 0.25
    if dict_cov < 0.15:
        score += 0.20
    if length_f > 18:
        score += 0.15

    confidence = round(min(1.0, max(0.0, score)), 4)
    is_dga = confidence >= 0.50
    return is_dga, confidence
