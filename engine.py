"""
engine.py
=========
Analytics core for the Anvaya Dark Web De-anonymization Platform.

Responsibilities
----------------
1.  Materialise the synthetic corpus into a real SQLite database (in-memory by
    default, file-backed on request) so the API layer is doing genuine queries
    rather than dict lookups.
2.  Build a NetworkX relationship graph over seven entity classes and run an
    independent union-find cluster resolution that is *cross-checked* against
    the corpus's ground-truth cluster labels.
3.  Run a leave-one-out calibrated stylometry engine (character 2-4 grams, word
    1-2 grams, orthographic habits, punctuation/layout) and a circadian
    phase-correlation engine.
4.  Fuse every firing vector with the probabilistic noisy-OR model

        Score = 1 - prod( 1 - weight_i * similarity_i )

    grouped into five analyst-facing evidence channels, and return a fully
    explainable breakdown.
5.  Produce csv / json / printable-HTML dossier exports of any filtered view.

No network I/O of any kind. Everything is computed from the seed corpus.
"""

from __future__ import annotations

import csv
import html
import io
import json
import math
import re
import sqlite3
import threading
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import networkx as nx
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

import seed_data

# --------------------------------------------------------------------------- #
# Tunables
# --------------------------------------------------------------------------- #

#: Weight of each analyst-facing evidence channel. These are priors for the
#: probability that a *firing* channel is telling the truth, in the sense of
#: "how much of the residual probability does this independent artefact remove".
CHANNEL_WEIGHTS: Dict[str, float] = {
    "stylometric": 0.62,
    "formatting": 0.30,
    "circadian": 0.45,
    "crypto": 0.94,
    "infrastructure": 0.90,
}

#: Weight of each individual sub-vector inside a channel.
SUBVECTOR_WEIGHTS: Dict[str, float] = {
    "char_ngram": 0.62,
    "word_tfidf": 0.45,
    "orthographic": 0.50,
    "topic_overlap": 0.25,
    "punctuation": 0.65,
    "activity_window": 1.00,
    "pgp_primary": 0.95,
    "pgp_subkey": 0.99,
    "wallet_address": 0.95,
    "tx_cluster": 0.92,
    "cert_serial": 0.95,
    "cert_sha256": 0.97,
    "favicon_mmh3": 0.60,
    "server_header": 0.35,
    "onion_reuse": 0.90,
}

#: Soft-only attributions (no hard selector fired) are capped here. Analyst
#: discipline: behavioural correlation is a lead, never a de-anonymisation.
SOFT_MATCH_CAP = 0.79
#: Hard-selector-backed attributions saturate just short of certainty.
HARD_MATCH_CEILING = 0.995
#: Minimum separation from the runner-up actor before we will call a match.
MIN_MARGIN = 0.05
#: Absolute floor below which nothing is reportable.
MIN_FLOOR = 0.45
#: Score at which a behavioural-only match is promoted from lead to probable.
SOFT_PROMOTION = 0.70
#: Score at which a hard-selector match is promoted from assessed to confirmed.
HARD_PROMOTION = 0.85


def classify_verdict(score: float, hard_selector_fired: bool) -> str:
    """Single source of truth for the confidence banding shown in the UI."""
    if score < MIN_FLOOR:
        return "NO_MATCH"
    if hard_selector_fired:
        return "CONFIRMED" if score >= HARD_PROMOTION else "ASSESSED"
    if score >= SOFT_PROMOTION:
        return "PROBABLE_SOFT"
    return "LEAD" if score >= 0.60 else "WEAK"

CATEGORY_COLORS = {
    "Ransomware": "#f43f5e",
    "Stolen Data": "#f59e0b",
    "Illicit Goods": "#a855f7",
    "Laundering": "#22d3ee",
}

ENTITY_COLORS = {
    "ThreatActor": "#ff2e63",
    "Persona": "#38bdf8",
    "PGPKey": "#facc15",
    "CryptoWallet": "#34d399",
    "OnionService": "#a78bfa",
    "ClearnetIP": "#fb923c",
    "MessagingID": "#22d3ee",
    "TxCluster": "#64748b",
    "Sample": "#f472b6",
}

SCHEMA = """
PRAGMA journal_mode=MEMORY;

CREATE TABLE markets (
    id TEXT PRIMARY KEY, name TEXT, onion_domain TEXT, kind TEXT,
    status TEXT, shutdown_date TEXT, successor TEXT, notes TEXT
);
CREATE TABLE actors (
    id TEXT PRIMARY KEY, codename TEXT, first_seen TEXT, last_scan_date TEXT,
    category TEXT, threat_level TEXT, confidence REAL,
    resolution_method TEXT, attribution_note TEXT
);
CREATE TABLE personas (
    id TEXT PRIMARY KEY, handle TEXT UNIQUE, actor_id TEXT, source_id TEXT,
    category TEXT, first_seen TEXT, last_scan_date TEXT, confidence REAL,
    role TEXT, status TEXT, threat_level TEXT, language TEXT, geo_assumed TEXT,
    bio TEXT, post_count INT, rebrand_of TEXT, rebrand_note TEXT,
    style_profile TEXT, circadian TEXT
);
CREATE TABLE selectors (
    id TEXT PRIMARY KEY, persona_id TEXT, type TEXT, value TEXT, label TEXT,
    first_seen TEXT, last_seen TEXT, note TEXT
);
CREATE TABLE pgp_keys (
    id TEXT PRIMARY KEY, persona_id TEXT, type TEXT, value TEXT, label TEXT,
    algo TEXT, created TEXT, first_seen TEXT, last_seen TEXT, note TEXT
);
CREATE TABLE wallets (
    id TEXT PRIMARY KEY, persona_id TEXT, currency TEXT, address TEXT,
    tx_cluster TEXT, first_seen TEXT, last_seen TEXT, note TEXT
);
CREATE TABLE tx_links (
    id TEXT PRIMARY KEY, cluster_id TEXT, wallet_a TEXT, wallet_b TEXT,
    shared_txs INT, first_shared TEXT, confidence REAL, note TEXT
);
CREATE TABLE onion_services (
    id TEXT PRIMARY KEY, persona_id TEXT, address TEXT, title TEXT,
    cert_sha256 TEXT, cert_serial TEXT, favicon_mmh3 TEXT, server_header TEXT,
    server_status INT, power_on_hours INT, first_seen TEXT, last_seen TEXT,
    origin_ip TEXT, origin_asn TEXT, origin_org TEXT, origin_country TEXT,
    origin_port INT, osint_note TEXT, confidence REAL
);
CREATE TABLE infra_links (
    id TEXT PRIMARY KEY, kind TEXT, value TEXT, owner_onion TEXT,
    other_onion TEXT, other_persona TEXT, same_actor INT, confidence REAL,
    contested INT, note TEXT
);
CREATE TABLE posts (
    id TEXT PRIMARY KEY, persona_id TEXT, posted_at TEXT, utc_hour INT,
    channel TEXT, title TEXT, body TEXT, lang TEXT
);
CREATE TABLE evidence (
    id TEXT PRIMARY KEY, persona_id TEXT, "group" TEXT, vector TEXT, label TEXT,
    similarity REAL, weight REAL, compared_to TEXT, detail TEXT
);
CREATE TABLE timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, persona_id TEXT,
    market_id TEXT, kind TEXT, severity TEXT, summary TEXT
);
CREATE TABLE clearnet_pivots (
    id INTEGER PRIMARY KEY AUTOINCREMENT, persona_id TEXT, source TEXT,
    pivot TEXT, artifact TEXT, confidence REAL
);
CREATE TABLE edges (
    id TEXT PRIMARY KEY, source TEXT, target TEXT, type TEXT,
    confidence REAL, label TEXT, evidence TEXT
);
CREATE TABLE resolution_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, cluster_id TEXT, method TEXT,
    verdict TEXT, confidence REAL, detail TEXT
);
CREATE INDEX idx_posts_persona ON posts(persona_id);
CREATE INDEX idx_sel_value ON selectors(value);
CREATE INDEX idx_sel_persona ON selectors(persona_id);
CREATE INDEX idx_ev_persona ON evidence(persona_id);
"""

_WORD_RE = re.compile(r"[A-Za-z0-9']+")
_SENT_RE = re.compile(r"[.!?]+")
_EMOJI_RE = re.compile(
    "[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF]"
)
_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "is", "it", "that", "for",
    "on", "with", "as", "at", "by", "be", "this", "are", "was", "i", "you",
    "we", "not", "but", "have", "has", "do", "does", "so", "if",
}


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _safe_div(a: float, b: float, default: float = 0.0) -> float:
    return a / b if b else default


# --------------------------------------------------------------------------- #
# Handcrafted feature vectors
# --------------------------------------------------------------------------- #

ORTHOGRAPHIC_FEATURES = [
    "caps_word_rate", "lowercase_start_rate", "exclam_rate", "question_rate",
    "ellipsis_rate", "comma_run_rate", "digit_rate", "emoji_rate",
    "trailing_space_rate", "double_space_rate", "avg_word_len", "long_word_rate",
    "type_token_ratio", "stopword_rate", "non_ascii_rate", "typo_signature_rate",
]

PUNCTUATION_FEATURES = [
    "semicolon_per_sentence", "comma_per_sentence", "dash_per_sentence",
    "quote_rate", "colon_rate", "paren_rate", "line_count", "blank_line_rate",
    "avg_line_len", "sentence_len_cv", "greeting_line", "signoff_line",
    "punct_variety", "terminal_punct_missing_rate", "all_caps_line_rate",
]


def orthographic_vector(text: str) -> np.ndarray:
    """Typographic habit vector -- the things a re-registration does not change."""
    n_chars = max(len(text), 1)
    words = _WORD_RE.findall(text)
    n_words = max(len(words), 1)
    sentences = [s for s in _SENT_RE.split(text) if s.strip()]
    n_sent = max(len(sentences), 1)
    punct = Counter(c for c in text if not c.isalnum() and not c.isspace())

    values = {
        "caps_word_rate": _safe_div(sum(1 for w in words if len(w) > 2 and w.isupper()), n_words),
        "lowercase_start_rate": _safe_div(
            sum(1 for line in text.splitlines() if line and line[0].islower()),
            max(len(text.splitlines()), 1)),
        "exclam_rate": _safe_div(text.count("!"), n_sent),
        "question_rate": _safe_div(text.count("?"), n_sent),
        "ellipsis_rate": _safe_div(text.count("...") + text.count(".."), n_sent),
        "comma_run_rate": _safe_div(text.count(",,") + text.count(",,,"), n_sent),
        "digit_rate": _safe_div(sum(c.isdigit() for c in text), n_chars),
        "emoji_rate": _safe_div(len(_EMOJI_RE.findall(text)), n_words),
        "trailing_space_rate": _safe_div(
            sum(1 for line in text.splitlines() if line.endswith(" ")),
            max(len(text.splitlines()), 1)),
        "double_space_rate": _safe_div(text.count("  "), max(len(text.splitlines()), 1)),
        "avg_word_len": float(np.mean([len(w) for w in words])) if words else 0.0,
        "long_word_rate": _safe_div(sum(1 for w in words if len(w) >= 8), n_words),
        "type_token_ratio": _safe_div(len(set(w.lower() for w in words)), n_words),
        "stopword_rate": _safe_div(
            sum(1 for w in words if w.lower() in _STOPWORDS), n_words),
        "non_ascii_rate": _safe_div(sum(1 for c in text if ord(c) > 127), n_chars),
        "typo_signature_rate": _safe_div(
            sum(text.count(t) for t in ("reciev", "seperat", "definately",
                                        "negociat", "verificat", "avaliab",
                                        "delivr", "shipin", "qnt", "qality")),
            n_words),
    }
    return np.array([values[name] for name in ORTHOGRAPHIC_FEATURES], dtype=float)


def punctuation_vector(text: str) -> np.ndarray:
    """Layout and punctuation-shape vector: sign-offs, bullet chars, line rhythm."""
    lines = text.splitlines()
    n_lines = max(len(lines), 1)
    sentences = [s for s in _SENT_RE.split(text) if s.strip()]
    n_sent = max(len(sentences), 1)
    lengths = [len(s.split()) for s in sentences] or [0]
    punct_chars = set(c for c in text if not c.isalnum() and not c.isspace())
    first = lines[0] if lines else ""
    last = lines[-1] if lines else ""

    values = {
        "semicolon_per_sentence": _safe_div(text.count(";"), n_sent),
        "comma_per_sentence": _safe_div(text.count(","), n_sent),
        "dash_per_sentence": _safe_div(text.count("--") + text.count(" - "), n_sent),
        "quote_rate": _safe_div(text.count('"') + text.count("'"), n_sent),
        "colon_rate": _safe_div(text.count(":"), n_sent),
        "paren_rate": _safe_div(text.count("(") + text.count(")"), n_sent),
        "line_count": float(n_lines),
        "blank_line_rate": _safe_div(sum(1 for ln in lines if not ln.strip()), n_lines),
        "avg_line_len": float(np.mean([len(ln) for ln in lines])) if lines else 0.0,
        "sentence_len_cv": _safe_div(float(np.std(lengths)), float(np.mean(lengths)) or 1.0),
        "greeting_line": 1.0 if re.search(
            r"^(hi|hey|hello|yo|gm|good (morning|evening|afternoon)|attention|greetings|"
            r"to all|evening|dear|new account)", first.strip(), re.I) else 0.0,
        "signoff_line": 1.0 if re.search(
            r"(--|\b(regards|cheers|thx|thank you|ty|best regards|kind regards)\b|"
            r"dispatch desk|contact (us|over))", last.strip(), re.I) else 0.0,
        "punct_variety": float(len(punct_chars)),
        "terminal_punct_missing_rate": _safe_div(
            sum(1 for ln in lines if ln.strip() and ln.strip()[-1] not in ".!?\"'[]"), n_lines),
        "all_caps_line_rate": _safe_div(
            sum(1 for ln in lines if len(ln.strip()) > 6 and ln.strip().isupper()), n_lines),
    }
    return np.array([values[name] for name in PUNCTUATION_FEATURES], dtype=float)


# --------------------------------------------------------------------------- #
# Calibration
# --------------------------------------------------------------------------- #


@dataclass
class Calibrator:
    """Maps a raw similarity onto 0-1 using an impostor (leave-one-out) null.

    Raw TF-IDF cosine is not a probability: it sits in a narrow band whose scale
    depends entirely on corpus composition. We therefore z-score each raw
    similarity against the distribution of scores produced by impostor
    documents, and cap at ``z_ref`` sigma. The resulting z-score is reported
    verbatim in the UI, which is the most auditable statement we can make.
    """

    mu: float
    sigma: float
    z_ref: float = 4.0
    label: str = ""

    def z(self, raw: float) -> float:
        return (raw - self.mu) / max(self.sigma, 1e-6)

    def score(self, raw: float) -> float:
        return _clamp(self.z(raw) / self.z_ref)

    def as_dict(self, raw: float) -> Dict[str, Any]:
        return {
            "raw": round(raw, 4),
            "z": round(self.z(raw), 2),
            "score": round(self.score(raw), 4),
            "null_mean": round(self.mu, 4),
            "null_sigma": round(self.sigma, 4),
            "z_ref": self.z_ref,
            "method": self.label,
        }


# --------------------------------------------------------------------------- #
# Stylometry index
# --------------------------------------------------------------------------- #


@dataclass
class PersonaStyleProfile:
    persona_id: str
    handle: str
    char_vector: np.ndarray
    word_vector: np.ndarray
    #: Standardised but deliberately left UN-normalised, because a query may be
    #: unable to express some features (see StylometryIndex.query_vector) and we
    #: must be able to mask those columns before computing cosine.
    ortho_vector: np.ndarray
    punct_vector: np.ndarray
    topic_vector: np.ndarray
    post_count: int
    corpus_chars: int
    top_phrases: List[str] = field(default_factory=list)


class StylometryIndex:
    """Character n-gram + word TF-IDF + handcrafted habit vectors, calibrated."""

    KINDS = ("char_ngram", "word_tfidf", "orthographic", "punctuation", "topic_overlap")

    def __init__(self, posts: Sequence[Dict[str, Any]], personas: Sequence[Dict[str, Any]]):
        self.persona_ids = [p["id"] for p in personas]
        self.handle_of = {p["id"]: p["handle"] for p in personas}
        self.actor_of = {p["id"]: p["actor_id"] for p in personas}
        texts = [p["body"] for p in posts]
        owner = [p["persona_id"] for p in posts]

        self.char_vec = TfidfVectorizer(
            analyzer="char_wb", ngram_range=(2, 4), min_df=1, sublinear_tf=True,
            max_features=120_000, lowercase=True,
        )
        self.word_vec = TfidfVectorizer(
            analyzer="word", ngram_range=(1, 2), min_df=1, sublinear_tf=True,
            lowercase=True, token_pattern=r"[A-Za-z0-9']+",
        )
        self.char_matrix = self.char_vec.fit_transform(texts)
        self.word_matrix = self.word_vec.fit_transform(texts)

        self.ortho_raw = np.array([orthographic_vector(t) for t in texts])
        self.punct_raw = np.array([punctuation_vector(t) for t in texts])
        # Standardise the habit vectors against the corpus, but leave them
        # un-normalised so a per-query feature mask can still be applied.
        self.ortho_scaler = self._fit_scaler(self.ortho_raw)
        self.punct_scaler = self._fit_scaler(self.punct_raw)
        self.ortho_floor = self.ortho_raw.min(axis=0)
        self.punct_floor = self.punct_raw.min(axis=0)
        self.ortho_matrix = self._apply_scaler(self.ortho_raw, self.ortho_scaler)
        self.punct_matrix = self._apply_scaler(self.punct_raw, self.punct_scaler)

        self.topic_vocab = self._build_topic_vocab(texts)
        self.topic_matrix = self._l2(np.array(
            [self._topic_counts(t) for t in texts], dtype=float))

        self.profiles: Dict[str, PersonaStyleProfile] = {}
        for pid in self.persona_ids:
            rows = [i for i, o in enumerate(owner) if o == pid]
            corpus = " ".join(texts[i] for i in rows)
            self.profiles[pid] = PersonaStyleProfile(
                persona_id=pid,
                handle=self.handle_of[pid],
                char_vector=self._l2_one(self.char_matrix[rows].mean(axis=0)),
                word_vector=self._l2_one(self.word_matrix[rows].mean(axis=0)),
                ortho_vector=self.ortho_matrix[rows].mean(axis=0),
                punct_vector=self.punct_matrix[rows].mean(axis=0),
                topic_vector=self._l2_one(self.topic_matrix[rows].mean(axis=0)),
                post_count=len(rows),
                corpus_chars=len(corpus),
                top_phrases=self._salient_phrases(corpus, pid, owner, texts),
            )

        self.calibrators = self._calibrate(owner, texts, self.actor_of)

    # -- helpers ----------------------------------------------------------- #

    @staticmethod
    def _fit_scaler(matrix: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        mean = matrix.mean(axis=0)
        std = matrix.std(axis=0)
        std[std < 1e-9] = 1.0
        return mean, std

    @staticmethod
    def _apply_scaler(matrix: np.ndarray, scaler: Tuple[np.ndarray, np.ndarray]) -> np.ndarray:
        return (matrix - scaler[0]) / scaler[1]

    @staticmethod
    def _l2(matrix: np.ndarray) -> np.ndarray:
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        norms[norms < 1e-12] = 1.0
        return matrix / norms

    @staticmethod
    def _l2_rows(matrix: np.ndarray) -> np.ndarray:
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        norms[norms < 1e-12] = 1.0
        return matrix / norms

    @staticmethod
    def _dense(value) -> np.ndarray:
        """Accept a dense array, an np.matrix or a scipy sparse row/column."""
        if hasattr(value, "toarray"):
            value = value.toarray()
        elif hasattr(value, "todense"):
            value = np.asarray(value.todense())
        return np.asarray(value, dtype=float).ravel()

    @staticmethod
    def _l2_one(value) -> np.ndarray:
        array = StylometryIndex._dense(value)
        norm = float(np.linalg.norm(array))
        return array / norm if norm > 1e-12 else array

    def _build_topic_vocab(self, texts: Sequence[str]) -> List[str]:
        counts: Counter = Counter()
        for text in texts:
            for word in _WORD_RE.findall(text.lower()):
                if len(word) > 3 and word not in _STOPWORDS and not word.isdigit():
                    counts[word] += 1
        return [word for word, _ in counts.most_common(400)]

    def _topic_counts(self, text: str) -> np.ndarray:
        words = Counter(w.lower() for w in _WORD_RE.findall(text))
        return np.array([words.get(vocab, 0) for vocab in self.topic_vocab], dtype=float)

    def _salient_phrases(
        self, corpus: str, pid: str, owner: Sequence[str], texts: Sequence[str]
    ) -> List[str]:
        """Character 4-grams that are over-represented here vs. the whole corpus."""
        own = self._char_counts(corpus, 4)
        allc: Counter = Counter()
        for text in texts:
            allc.update(self._char_counts(text, 4))
        total = sum(allc.values()) or 1
        ranked = sorted(
            own.items(),
            key=lambda kv: (kv[1] / max(sum(own.values()), 1)) - (allc.get(kv[0], 0) / total),
            reverse=True,
        )
        out: List[str] = []
        for gram, _ in ranked:
            g = gram.strip()
            if len(g) < 4 or g in out:
                continue
            if not any(g in existing for existing in out):
                out.append(g)
            if len(out) >= 8:
                break
        return out

    @staticmethod
    def _char_counts(text: str, n: int) -> Counter:
        flat = "".join(c for c in text.lower() if not c.isspace())
        return Counter(flat[i:i + n] for i in range(len(flat) - n + 1))

    # -- leave-one-out calibration ----------------------------------------- #

    def _calibrate(self, owner: Sequence[str], texts: Sequence[str],
                   actor_of: Dict[str, str]) -> Dict[str, Calibrator]:
        """Leave-one-out null built from CROSS-ACTOR impostor pairs only.

        The hypothesis under test is "this sample was written by a different
        actor". A sibling persona belonging to the same cluster is, by
        construction, the *genuine* class for that hypothesis -- including those
        pairs in the null would double-count near-duplicate authors and inflate
        sigma until every real match looked mediocre. With a production corpus of
        thousands of actors the null would be overwhelmingly unrelated authors
        anyway, so this is also the behaviour that scales.
        """
        position = {pid: i for i, pid in enumerate(self.persona_ids)}
        impostor: Dict[str, List[float]] = {k: [] for k in self.KINDS}
        for i, pid in enumerate(owner):
            for kind in self.KINDS:
                query, mask = self.query_vector(kind, texts[i])
                matrix = self.profile_matrix(kind, mask)
                for other in self.persona_ids:
                    if actor_of[other] == actor_of[pid]:
                        continue  # same cluster: genuine class, not an impostor
                    impostor[kind].append(float(query @ matrix[position[other]]))

        calibrators: Dict[str, Calibrator] = {}
        for name, values in impostor.items():
            if len(values) < 8:  # pragma: no cover - tiny corpora only
                values = values + list(values)
            calibrators[name] = Calibrator(
                mu=float(np.mean(values)),
                sigma=float(np.std(values)) or 1e-6,
                z_ref=4.0,
                label="cross-actor leave-one-out impostor z-score",
            )
        return calibrators

    # -- public query API -------------------------------------------------- #

    def profile_matrix(self, kind: str, mask: Optional[np.ndarray] = None) -> np.ndarray:
        attr = {
            "char_ngram": "char_vector",
            "word_tfidf": "word_vector",
            "orthographic": "ortho_vector",
            "punctuation": "punct_vector",
            "topic_overlap": "topic_vector",
        }[kind]
        matrix = np.array([self._dense(getattr(self.profiles[pid], attr))
                           for pid in self.persona_ids])
        if mask is not None:
            matrix = matrix.copy()
            matrix[:, mask] = 0.0
        return StylometryIndex._l2_rows(matrix)

    def query_vector(self, kind: str, text: str) -> np.ndarray:
        """Vectorise one sample. Returns a unit vector plus an optional mask.

        For the handcrafted habit vectors a pasted sample frequently cannot
        express a feature at all -- emoji rate, trailing whitespace, transliteration
        typos. Those components sit at the corpus floor, so comparing them is
        comparing absence against presence. We mask them out (imputing the
        corpus mean) instead of penalising the author for a paste operation.
        """
        mask: Optional[np.ndarray] = None
        if kind == "char_ngram":
            vector = self._dense(self.char_vec.transform([text]))
        elif kind == "word_tfidf":
            vector = self._dense(self.word_vec.transform([text]))
        elif kind == "orthographic":
            raw = orthographic_vector(text)
            mask = raw <= self.ortho_floor + 1e-9
            vector = (raw - self.ortho_scaler[0]) / self.ortho_scaler[1]
        elif kind == "punctuation":
            raw = punctuation_vector(text)
            mask = raw <= self.punct_floor + 1e-9
            vector = (raw - self.punct_scaler[0]) / self.punct_scaler[1]
        elif kind == "topic_overlap":
            vector = self._topic_counts(text)
        else:
            raise KeyError(kind)
        if mask is not None and mask.all():
            mask = None
        if mask is not None:
            vector = np.where(mask, 0.0, vector)
        return self._l2_one(vector), mask

    def similarities(self, text: str) -> Dict[str, Dict[str, Dict[str, float]]]:
        """Return {persona_id: {vector_name: calibration_payload}} for one sample."""
        results: Dict[str, Dict[str, float]] = {}
        for kind, calibrator in self.calibrators.items():
            query, mask = self.query_vector(kind, text)
            sims = self.profile_matrix(kind, mask) @ query
            for i, pid in enumerate(self.persona_ids):
                results.setdefault(pid, {})[kind] = float(sims[i])
        return {
            pid: {
                kind: self.calibrators[kind].as_dict(raw)
                for kind, raw in vectors.items()
            }
            for pid, vectors in results.items()
        }

    def pairwise(self, kind: str) -> Dict[str, Dict[str, float]]:
        """Corpus-on-corpus similarity, for the graph's stylometry edges."""
        matrix = self.profile_matrix(kind)
        sims = matrix @ matrix.T
        out: Dict[str, Dict[str, float]] = {}
        for i, a in enumerate(self.persona_ids):
            out[a] = {b: float(sims[i, j]) for j, b in enumerate(self.persona_ids)}
        return out


# --------------------------------------------------------------------------- #
# Circadian engine
# --------------------------------------------------------------------------- #


class CircadianEngine:
    """24-bin UTC activity profiles, compared against a circular phase-shift null."""

    def __init__(self, profiles: Dict[str, List[float]], personas: Sequence[Dict[str, Any]]):
        self.persona_ids = [p["id"] for p in personas]
        self.handle_of = {p["id"]: p["handle"] for p in personas}
        self.profiles = {pid: np.array(vec, dtype=float) for pid, vec in profiles.items()}
        self.peak_hour = {pid: int(np.argmax(vec)) for pid, vec in self.profiles.items()}

    @staticmethod
    def from_counts(counts: Sequence[float]) -> np.ndarray:
        vector = np.zeros(24, dtype=float)
        for hour, weight in counts:
            vector[int(hour) % 24] += float(weight)
        total = vector.sum()
        return vector / total if total > 0 else vector

    @staticmethod
    def pearson(a: np.ndarray, b: np.ndarray) -> float:
        if a.std() < 1e-12 or b.std() < 1e-12:
            return 0.0
        return float(np.corrcoef(a, b)[0, 1])

    @staticmethod
    def phase_null(profile: np.ndarray) -> List[float]:
        """r against every circular shift of itself: the correct null for phase."""
        return [CircadianEngine.pearson(profile, np.roll(profile, k)) for k in range(1, 24)]

    def compare(self, query: np.ndarray) -> Dict[str, Dict[str, Any]]:
        if query.sum() <= 0 or query.std() < 1e-12:
            return {}
        null = self.phase_null(query)
        mu = float(np.mean(null))
        sigma = float(np.std(null)) or 1e-6
        calibrator = Calibrator(mu=mu, sigma=sigma, z_ref=3.0,
                                label="circular phase-shift null")
        out: Dict[str, Dict[str, Any]] = {}
        for pid in self.persona_ids:
            raw = self.pearson(query, self.profiles[pid])
            payload = calibrator.as_dict(raw)
            payload["peak_hour"] = self.peak_hour[pid]
            payload["null_span"] = [round(min(null), 3), round(max(null), 3)]
            out[pid] = payload
        return out


# --------------------------------------------------------------------------- #
# The engine
# --------------------------------------------------------------------------- #


class IntelEngine:
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        # FastAPI runs these synchronous endpoints in a worker threadpool, so
        # several requests can touch the single sqlite3.Connection at once.
        # sqlite3 connections are not safe for concurrent use even with
        # check_same_thread=False (it raises InterfaceError: bad parameter or
        # other API misuse), and an in-memory database cannot be shared by
        # per-thread connections because each would see an empty schema.
        # The corpus is read-only after __init__, so a re-entrant lock around
        # every statement is both correct and cheap.
        self._db_lock = threading.RLock()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.corpus: Dict[str, Any] = seed_data.build_database()
        self._seed()
        self.posts = self._rows("SELECT * FROM posts ORDER BY posted_at")
        self.personas = self._rows("SELECT * FROM personas")
        self.persona_ids = [p["id"] for p in self.personas]
        self.persona_by_handle = {p["handle"]: p for p in self.personas}
        self.persona_by_id = {p["id"]: p for p in self.personas}
        self.actors = self._rows("SELECT * FROM actors ORDER BY codename")
        self.actor_by_id = {a["id"]: a for a in self.actors}
        self.actor_codename = {a["id"]: a["codename"] for a in self.actors}

        self.stylometry = StylometryIndex(self.posts, self.personas)
        self.circadian = CircadianEngine(
            {p["id"]: json.loads(p["circadian"]) for p in self.personas}, self.personas
        )
        self._build_selector_index()
        self._build_phrase_index()
        # Graph edges embed stylometric and circadian measurements, so they can
        # only be written once the analytical indices exist.
        self._seed_graph_edges()
        self.graph = self._build_graph()
        self.resolution = self._resolve_clusters()

    # -- database ---------------------------------------------------------- #

    def _rows(self, sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        with self._db_lock:
            return [dict(row) for row in self.db.execute(sql, params)]

    def _one(self, sql: str, params: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
        """First row as a dict, or None."""
        with self._db_lock:
            row = self.db.execute(sql, params).fetchone()
        return dict(row) if row is not None else None

    def _scalar(self, sql: str, params: Sequence[Any] = ()) -> Any:
        with self._db_lock:
            row = self.db.execute(sql, params).fetchone()
        return row[0] if row is not None else None

    def _iter(self, sql: str, params: Sequence[Any] = ()) -> List[sqlite3.Row]:
        """Materialise a cursor inside the lock (never leak a live cursor)."""
        with self._db_lock:
            return list(self.db.execute(sql, params))

    def _seed(self) -> None:
        cur = self.db.cursor()
        for m in self.corpus["markets"]:
            cur.execute(
                "INSERT INTO markets VALUES (:id,:name,:onion_domain,:kind,:status,"
                ":shutdown_date,:successor,:notes)", m)
        for a in self.corpus["actors"]:
            cur.execute(
                "INSERT INTO actors VALUES (:id,:codename,:first_seen,:last_scan_date,"
                ":category,:threat_level,:confidence,:resolution_method,:attribution_note)", a)
        for p in self.corpus["personas"]:
            row = dict(p)
            row["style_profile"] = json.dumps(
                seed_data.STYLE_PROFILES[p["handle"]], ensure_ascii=False)
            row["circadian"] = json.dumps(seed_data.CIRCADIAN_PROFILES[p["handle"]])
            cur.execute(
                "INSERT INTO personas VALUES (:id,:handle,:actor_id,:source_id,:category,"
                ":first_seen,:last_scan_date,:confidence,:role,:status,:threat_level,"
                ":language,:geo_assumed,:bio,:post_count,:rebrand_of,:rebrand_note,"
                ":style_profile,:circadian)", row)
        for k in self.corpus["pgp_keys"]:
            cur.execute(
                "INSERT INTO pgp_keys VALUES (:id,:persona_id,:type,:value,:label,:algo,"
                ":created,:first_seen,:last_seen,:note)", k)
            cur.execute(
                "INSERT INTO selectors VALUES (:id,:persona_id,:type,:value,:label,"
                ":first_seen,:last_seen,:note)",
                (f"sel-{k['id']}", k["persona_id"], f"pgp_{k['type'].replace('pgp_', '')}",
                 k["value"], k["label"], k["first_seen"], k["last_seen"], k["note"]))
        for w in self.corpus["wallets"]:
            cur.execute(
                "INSERT INTO wallets VALUES (:id,:persona_id,:currency,:address,"
                ":tx_cluster,:first_seen,:last_seen,:note)", w)
            cur.execute(
                "INSERT INTO selectors VALUES (:id,:persona_id,:type,:value,:label,"
                ":first_seen,:last_seen,:note)",
                (f"sel-{w['id']}", w["persona_id"], f"{w['currency'].lower()}_address",
                 w["address"], f"{w['currency']} wallet -- {w['tx_cluster']}",
                 w["first_seen"], w["last_seen"], w["note"]))
        for t in self.corpus["tx_links"]:
            cur.execute(
                "INSERT INTO tx_links VALUES (:id,:cluster_id,:wallet_a,:wallet_b,"
                ":shared_txs,:first_shared,:confidence,:note)", t)
        for m in self.corpus["messaging"]:
            cur.execute(
                "INSERT INTO selectors VALUES (:id,:persona_id,:type,:value,:label,"
                ":first_seen,:last_seen,:note)", m)
        for o in self.corpus["onion_services"]:
            cur.execute(
                "INSERT INTO onion_services VALUES (:id,:persona_id,:address,:title,"
                ":cert_sha256,:cert_serial,:favicon_mmh3,:server_header,:server_status,"
                ":power_on_hours,:first_seen,:last_seen,:origin_ip,:origin_asn,:origin_org,"
                ":origin_country,:origin_port,:osint_note,:confidence)", o)
            cur.execute(
                "INSERT INTO selectors VALUES (:id,:persona_id,:type,:value,:label,"
                ":first_seen,:last_seen,:note)",
                (f"sel-{o['id']}", o["persona_id"], "onion_service", o["address"],
                 o["title"], o["first_seen"], o["last_seen"], o["osint_note"]))
        for p in self.corpus["posts"]:
            cur.execute(
                "INSERT INTO posts VALUES (:id,:persona_id,:posted_at,:utc_hour,:channel,"
                ":title,:body,:lang)", p)
        for pid, items in self.corpus["evidence"].items():
            for index, item in enumerate(items):
                cur.execute(
                    "INSERT INTO evidence VALUES (:id,:persona_id,:group,:vector,:label,"
                    ":similarity,:weight,:compared_to,:detail)",
                    (f"ev-{pid}-{index + 1:02d}", pid, item["group"], item["vector"],
                     item["label"], item["similarity"], item["weight"],
                     item.get("compared_to"), item["detail"]))
        for index, t in enumerate(self.corpus["timeline"]):
            cur.execute(
                "INSERT INTO timeline (ts,persona_id,market_id,kind,severity,summary) "
                "VALUES (?,?,?,?,?,?)",
                (t["ts"], t["persona_id"], t["market_id"], t["kind"], t["severity"],
                 t["summary"]))
        for c in self.corpus["clearnet_pivots"]:
            cur.execute(
                "INSERT INTO clearnet_pivots (persona_id,source,pivot,artifact,confidence) "
                "VALUES (?,?,?,?,?)",
                (c["persona_id"], c["source"], c["pivot"], c["artifact"], c["confidence"]))
        self._seed_infra_links()
        self.db.commit()

    def _seed_infra_links(self) -> None:
        services = self.corpus["onion_services"]
        actor_of = {r["id"]: r["actor_id"]
                    for r in self._rows("SELECT id, actor_id FROM personas")}
        index = 0
        for svc in services:
            for kind in ("cert_serial", "cert_sha256", "favicon_mmh3", "origin_ip"):
                value = svc.get(kind)
                if not value:
                    continue
                for other in services:
                    if other["id"] == svc["id"] or other.get(kind) != value:
                        continue
                    same_actor = actor_of[svc["persona_id"]] == actor_of[other["persona_id"]]
                    index += 1
                    self.db.execute(
                        "INSERT INTO infra_links VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (f"il-{index:03d}", kind, value, svc["id"], other["id"],
                         other["persona_id"], int(same_actor),
                         svc["confidence"] if same_actor else 0.41,
                         0 if same_actor else 1,
                         svc["osint_note"] if same_actor else
                         "Cross-actor artifact collision. Held at 41% and de-emphasised."))
        self.db.commit()

    def _pid_actor(self, pid: str) -> Optional[str]:
        row = self._one("SELECT actor_id FROM personas WHERE id=?", (pid,))
        return row["actor_id"] if row else None

    def _seed_graph_edges(self) -> None:
        edges: List[Dict[str, Any]] = []
        actors = self._rows("SELECT * FROM actors ORDER BY codename")
        handle_of = {r["id"]: r["handle"] for r in self._rows("SELECT id, handle FROM personas")}

        def add(src: str, dst: str, etype: str, conf: float, label: str, evidence: str) -> None:
            edges.append({
                "id": f"e-{len(edges) + 1:04d}", "source": src, "target": dst,
                "type": etype, "confidence": round(float(conf), 4), "label": label,
                "evidence": evidence})

        for actor in actors:
            for persona in self._rows(
                "SELECT * FROM personas WHERE actor_id=? ORDER BY handle", (actor["id"],)
            ):
                add(actor["id"], persona["id"], "PERSONA_OF", persona["confidence"],
                    f"{actor['codename']} / {persona['handle']}",
                    actor["resolution_method"])
                add(persona["id"], persona["source_id"], "ACTED_ON", 0.9,
                    persona["source_id"], persona["status"])

        for key in self._rows("SELECT * FROM pgp_keys ORDER BY persona_id, id"):
            add(key["persona_id"], key["id"], "USES_PGP", 0.97, key["label"], key["note"])

        for w in self._rows("SELECT * FROM wallets ORDER BY persona_id, id"):
            add(w["persona_id"], w["id"], "CONTROLS_WALLET", 0.93,
                f"{w['currency']} {w['address'][:16]}...", w["note"])
            add(w["id"], w["tx_cluster"], "CLUSTERED_IN", 0.9, w["tx_cluster"], "common-input cluster")

        for link in self._rows("SELECT * FROM tx_links ORDER BY id"):
            if link["shared_txs"] > 0:
                add(link["wallet_a"], link["wallet_b"], "CO_SPENT_TX", link["confidence"],
                    f"{link['shared_txs']} shared inputs",
                    link["note"])
            else:
                add(link["wallet_a"], link["wallet_b"], "CO_SPENT_TX", 0.0,
                    "0 shared inputs -- NEGATIVE CONTROL", link["note"])

        for svc in self._rows("SELECT * FROM onion_services ORDER BY persona_id, id"):
            add(svc["persona_id"], svc["id"], "OPERATES", svc["confidence"],
                svc["title"], svc["osint_note"])
            ip_node = f"ip-{svc['origin_ip']}"
            add(svc["id"], ip_node, "ORIGIN_OF", svc["confidence"],
                f"{svc['origin_ip']} {svc['origin_asn']}",
                f"{svc['origin_org']} / {svc['origin_country']} "
                f"(RFC-5737 synthetic address)")

        for link in self._rows(
            "SELECT * FROM infra_links WHERE contested=0 AND confidence>=0.5 ORDER BY id"
        ):
            add(link["owner_onion"], link["other_onion"], "INFRA_MATCH", link["confidence"],
                f"{link['kind']} = {link['value']}", link["note"])
        for link in self._rows(
            "SELECT * FROM infra_links WHERE contested=1 ORDER BY id"
        ):
            add(link["owner_onion"], link["other_onion"], "INFRA_MATCH_CONTESTED",
                link["confidence"], f"{link['kind']} = {link['value']}", link["note"])

        style = self.stylometry.pairwise("char_ngram")
        for i, a in enumerate(self.stylometry.persona_ids):
            for j, b in enumerate(self.stylometry.persona_ids):
                if j <= i:
                    continue
                sim = style[a][b]
                same = self._pid_actor(a) == self._pid_actor(b)
                if sim >= 0.55 or (same and sim >= 0.4):
                    add(a, b, "STYLOMETRY_LINK", round(sim, 4),
                        f"char 4-gram cosine {sim:.3f}",
                        f"{handle_of[a]} <-> {handle_of[b]} "
                        f"({'in-cluster' if same else 'cross-cluster'})")
        for a in self.stylometry.persona_ids:
            for b in self.stylometry.persona_ids:
                if a >= b or self._pid_actor(a) != self._pid_actor(b):
                    continue
                r = self.circadian.pearson(
                    self.circadian.profiles[a], self.circadian.profiles[b])
                if r >= 0.6:
                    add(a, b, "CIRCADIAN_LINK", round((r + 1) / 2, 4),
                        f"24h UTC Pearson r = {r:.3f}",
                        "element-wise identical activity window" if r > 0.99
                        else "shared circadian window")

        for edge in edges:
            if not edge["source"] or not edge["target"]:
                continue
            self.db.execute(
                "INSERT OR REPLACE INTO edges VALUES (:id,:source,:target,:type,"
                ":confidence,:label,:evidence)", edge)
        self.db.commit()

    def _build_selector_index(self) -> None:
        self.selector_index: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for row in self._rows("SELECT * FROM selectors"):
            for key in (row["value"], row["value"].lower(), row["value"].replace(" ", "")):
                if key:
                    self.selector_index[key.lower()].append(row)
        self.onion_index: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for svc in self._rows("SELECT * FROM onion_services"):
            self.onion_index[svc["address"].lower()].append(svc)
            self.onion_index[svc["cert_serial"].lower()].append(svc)
            self.onion_index[svc["cert_sha256"].lower()].append(svc)
            self.onion_index[svc["favicon_mmh3"].lower()].append(svc)
            self.onion_index[svc["origin_ip"].lower()].append(svc)
            self.onion_index[svc["server_header"].lower()].append(svc)
        self.wallet_index: Dict[str, Dict[str, Any]] = {
            w["address"].lower(): w for w in self._rows("SELECT * FROM wallets")}
        self.pgp_index: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for key in self._rows("SELECT * FROM pgp_keys"):
            self.pgp_index[key["value"].lower()].append(key)

    def _build_phrase_index(self) -> None:
        self.phrase_index: Dict[str, str] = {}
        for post in self.posts:
            for line in post["body"].splitlines():
                line = line.strip()
                if len(line) >= 28:
                    self.phrase_index[line.lower()] = post["persona_id"]

    # -- cluster resolution ----------------------------------------------- #

    def _resolve_clusters(self) -> Dict[str, Any]:
        """Independent union-find over hard selectors, cross-checked vs ground truth.

        The point of this routine is falsifiability: we re-derive identity
        clusters from selectors alone, then compare against the curated
        ground-truth labels. Any cluster the selector pass can NOT explain is
        reported explicitly as a behavioural merge with a confidence cap.
        """
        parent: Dict[str, str] = {p["id"]: p["id"] for p in self.personas}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> bool:
            ra, rb = find(a), find(b)
            if ra == rb:
                return False
            parent[rb] = ra
            return True

        hard_links: List[Dict[str, Any]] = []

        # 1. Shared PGP key material.
        by_pgp: Dict[str, List[str]] = defaultdict(list)
        for key in self._rows("SELECT persona_id, value FROM pgp_keys ORDER BY id"):
            by_pgp[key["value"].lower()].append(key["persona_id"])
        for value, owners in by_pgp.items():
            for other in owners[1:]:
                if union(owners[0], other):
                    hard_links.append({
                        "kind": "PGP_SUBKEY_REUSE", "via": value.upper(),
                        "between": [owners[0], other], "confidence": 0.99})

        # 2. Shared transaction (common-input) cluster.
        for row in self._rows(
            "SELECT tx_cluster, GROUP_CONCAT(persona_id) AS pids, COUNT(*) AS n "
            "FROM wallets GROUP BY tx_cluster HAVING n > 1"
        ):
            owners = [p for p in str(row["pids"]).split(",") if p]
            for other in owners[1:]:
                if union(owners[0], other):
                    hard_links.append({
                        "kind": "WALLET_CLUSTER", "via": row["tx_cluster"],
                        "between": [owners[0], other], "confidence": 0.92})

        # 3. Shared TLS certificate serial.
        for svc in self._rows(
            "SELECT id, persona_id, cert_serial FROM onion_services "
            "WHERE cert_serial IS NOT NULL AND cert_serial != '' ORDER BY id"
        ):
            for peer in self._rows(
                "SELECT id, persona_id FROM onion_services "
                "WHERE cert_serial = ? AND id != ?", (svc["cert_serial"], svc["id"])
            ):
                if union(svc["persona_id"], peer["persona_id"]):
                    hard_links.append({
                        "kind": "CERT_SERIAL", "via": svc["cert_serial"],
                        "between": [svc["persona_id"], peer["persona_id"]],
                        "confidence": 0.99})

        derived: Dict[str, List[str]] = defaultdict(list)
        for pid in parent:
            derived[find(pid)].append(pid)

        # Compare selector-derived clusters with the curated ground truth.
        selector_explained: set[str] = set()
        for members in derived.values():
            if len(members) < 2:
                continue
            actors = {self.persona_by_id[m]["actor_id"] for m in members}
            if len(actors) == 1:
                selector_explained.update(members)

        style = self.stylometry.pairwise("char_ngram")
        log: List[Dict[str, Any]] = []
        for actor in self.actors:
            members = [p for p in self.personas if p["actor_id"] == actor["id"]]
            if len(members) < 2:
                continue
            explained = all(m["id"] in selector_explained for m in members)
            a, b = members[0], members[1]
            sim = style[a["id"]][b["id"]]
            r = self.circadian.pearson(
                self.circadian.profiles[a["id"]], self.circadian.profiles[b["id"]])
            overlap = self._selector_overlap(a["id"], b["id"])
            behavioural = round(0.5 * sim + 0.5 * ((r + 1) / 2), 4)
            if explained:
                via = sorted({
                    link["kind"] for link in hard_links
                    if set(link["between"]) == {a["id"], b["id"]}
                })
                detail = (
                    f"{a['handle']} <-> {b['handle']}: union-find linked them on "
                    f"{', '.join(via) or 'hard selectors'}. Independent of the curated "
                    f"label, and of any stylistic evidence. Behavioural corroboration: "
                    f"char 4-gram cosine {sim:.3f}, 24h UTC Pearson r {r:.3f}.")
                log.append({
                    "cluster_id": actor["codename"],
                    "method": "HARD_SELECTOR_UNION",
                    "verdict": "CONFIRMED_HARD",
                    "confidence": round(float(behavioural), 4),
                    "detail": detail,
                })
            else:
                negatives = [
                    name for name in ("pgp_shared", "wallet_shared",
                                      "tx_cluster_shared", "cert_serial_shared")
                    if not overlap[name]
                ]
                detail = (
                    f"{a['handle']} <-> {b['handle']}: the selector pass returned "
                    f"DISJOINT sets ({', '.join(negatives)} all empty), so no hard "
                    f"selector can justify this merge. Resolved on behaviour alone -- "
                    f"char 4-gram cosine {sim:.3f} and 24h UTC Pearson r {r:.3f}. "
                    f"Scored as a lead and capped at {SOFT_MATCH_CAP:.0%} until a "
                    f"selector corroborates it.")
                log.append({
                    "cluster_id": actor["codename"],
                    "method": "BEHAVIOURAL_MERGE",
                    "verdict": "CONFIRMED_SOFT",
                    "confidence": round(float(behavioural), 4),
                    "detail": detail,
                })

        self.db.executemany(
            "INSERT INTO resolution_log (cluster_id,method,verdict,confidence,detail) "
            "VALUES (:cluster_id,:method,:verdict,:confidence,:detail)", log)
        self.db.commit()
        return {
            "hard_links": hard_links,
            "derived_clusters": {k: sorted(v) for k, v in derived.items()},
            "log": log,
            "selector_explained_personas": sorted(selector_explained),
            "behavioural_only_personas": sorted(
                p["id"] for p in self.personas
                if p["id"] not in selector_explained and any(
                    q["actor_id"] == p["actor_id"] for q in self.personas if q is not p)),
            "soft_capped_clusters": [
                a["codename"] for a in self.actors if a["resolution_method"] == "SOFT_MERGE"],
        }

    # -- graph ------------------------------------------------------------- #

    def _build_graph(self) -> nx.MultiDiGraph:
        graph = nx.MultiDiGraph()
        for actor in self.actors:
            graph.add_node(actor["id"], type="ThreatActor", label=actor["codename"],
                           category=actor["category"], confidence=actor["confidence"],
                           threat_level=actor["threat_level"],
                           resolution_method=actor["resolution_method"])
        for persona in self.personas:
            persona = dict(persona)
            persona.pop("style_profile", None)
            persona.pop("circadian", None)
            graph.add_node(persona["id"], type="Persona", label=persona["handle"],
                           category=persona["category"], confidence=persona["confidence"],
                           actor=persona["actor_id"], source=persona["source_id"],
                           first_seen=persona["first_seen"],
                           last_scan_date=persona["last_scan_date"],
                           status=persona["status"], threat_level=persona["threat_level"])
        for market in self.corpus["markets"]:
            graph.add_node(market["id"], type="Market", label=market["name"],
                           kind=market["kind"], status=market["status"],
                           confidence=1.0)
        for key in self._rows("SELECT * FROM pgp_keys"):
            graph.add_node(key["id"], type="PGPKey",
                           label=f"{key['type'].replace('pgp_', '').title()} {key['value'][:8]}…",
                           value=key["value"], confidence=0.97)
        for wallet in self._rows("SELECT * FROM wallets"):
            graph.add_node(wallet["id"], type="CryptoWallet",
                           label=f"{wallet['currency']} {wallet['address'][:10]}…",
                           value=wallet["address"], confidence=0.93)
        for cluster in {w["tx_cluster"] for w in self._rows("SELECT * FROM wallets")}:
            graph.add_node(cluster, type="TxCluster", label=cluster, confidence=0.85)
        for svc in self._rows("SELECT * FROM onion_services"):
            graph.add_node(svc["id"], type="OnionService",
                           label=svc["address"][:18] + "…", value=svc["address"],
                           confidence=svc["confidence"])
            graph.add_node(f"ip-{svc['origin_ip']}", type="ClearnetIP",
                           label=svc["origin_ip"],
                           value=f"{svc['origin_ip']} {svc['origin_asn']}",
                           confidence=svc["confidence"])
        for row in self._rows("SELECT * FROM selectors WHERE type IN ('tox_id','jabber')"):
            graph.add_node(row["id"], type="MessagingID",
                           label=f"{row['type']}: {row['value'][:18]}",
                           value=row["value"], confidence=0.9)
        for edge in self._rows("SELECT * FROM edges ORDER BY id"):
            if edge["source"] in graph and edge["target"] in graph:
                graph.add_edge(edge["source"], edge["target"], id=edge["id"],
                               type=edge["type"], confidence=edge["confidence"],
                               label=edge["label"], evidence=edge["evidence"])
        for row in self._rows("SELECT * FROM selectors WHERE type IN ('tox_id','jabber')"):
            graph.add_edge(row["persona_id"], row["id"], type="CONTACTS_VIA",
                           confidence=0.9, label=row["type"], evidence=row["note"])
        return graph

    # -- filtering --------------------------------------------------------- #

    def filter_personas(
        self,
        category: Optional[List[str]] = None,
        source: Optional[List[str]] = None,
        min_confidence: float = 0.0,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        query: Optional[str] = None,
        actor_only: bool = False,
    ) -> List[Dict[str, Any]]:
        category = {c.lower() for c in (category or [])}
        source = {s.lower() for s in (source or [])}
        needle = (query or "").strip().lower()

        out: List[Dict[str, Any]] = []
        for row in self._rows(
            "SELECT p.*, a.codename AS actor_codename, a.resolution_method, "
            "m.name AS source_name, m.kind AS source_kind, m.status AS source_status "
            "FROM personas p JOIN actors a ON a.id=p.actor_id "
            "JOIN markets m ON m.id=p.source_id ORDER BY p.confidence DESC, p.handle"
        ):
            if category and row["category"].lower() not in category:
                continue
            if source and (row["source_name"].lower() not in source
                           and row["source_id"].lower() not in source):
                continue
            if row["confidence"] < min_confidence:
                continue
            if start_date and row["last_scan_date"] < start_date:
                continue
            if end_date and row["first_seen"] > end_date:
                continue
            if needle and not any(
                needle in str(row[field]).lower()
                for field in ("handle", "bio", "role", "actor_codename", "category", "language")
            ):
                continue
            out.append(self.hydrate_persona(row))
        if actor_only:
            best: Dict[str, Dict[str, Any]] = {}
            for persona in out:
                current = best.get(persona["actor_id"])
                if current is None or persona["confidence"] > current["confidence"]:
                    best[persona["actor_id"]] = persona
            out = sorted(best.values(), key=lambda p: -p["confidence"])
        return out

    def hydrate_persona(self, row: Dict[str, Any]) -> Dict[str, Any]:
        pid = row["id"]
        persona = dict(row)
        persona["selectors"] = self._rows(
            "SELECT id,type,value,label,first_seen,last_seen,note FROM selectors "
            "WHERE persona_id=? ORDER BY type, id", (pid,))
        persona["pgp_keys"] = self._rows(
            "SELECT * FROM pgp_keys WHERE persona_id=? ORDER BY id", (pid,))
        persona["wallets"] = self._rows(
            "SELECT * FROM wallets WHERE persona_id=? ORDER BY id", (pid,))
        persona["onion_services"] = self._rows(
            "SELECT * FROM onion_services WHERE persona_id=? ORDER BY id", (pid,))
        persona["evidence"] = self._rows(
            "SELECT * FROM evidence WHERE persona_id=? ORDER BY "
            "CASE \"group\" WHEN 'crypto' THEN 1 WHEN 'infrastructure' THEN 2 "
            "WHEN 'stylometric' THEN 3 WHEN 'circadian' THEN 4 ELSE 5 END, id", (pid,))
        persona["clearnet_pivots"] = self._rows(
            "SELECT * FROM clearnet_pivots WHERE persona_id=? ORDER BY confidence DESC", (pid,))
        persona["posts"] = self._rows(
            "SELECT id,posted_at,utc_hour,channel,title,body FROM posts "
            "WHERE persona_id=? ORDER BY posted_at DESC LIMIT 6", (pid,))
        persona["hour_histogram"] = self._hour_histogram(pid)
        persona["circadian"] = json.loads(row["circadian"])
        persona["rebrands"] = self._rows(
            "SELECT p.id AS id, p.handle AS handle, a.codename AS actor, "
            "p.first_seen AS first_seen, p.last_scan_date AS last_scan_date, "
            "p.confidence AS confidence FROM personas p "
            "LEFT JOIN actors a ON a.id = p.actor_id "
            "WHERE p.rebrand_of = ? AND p.id != ?", (pid, pid))
        persona["siblings"] = self._rows(
            "SELECT id, handle, confidence, source_id, rebrand_of FROM personas "
            "WHERE actor_id = ? AND id != ?", (row["actor_id"], pid))
        persona["edge_summary"] = self._persona_edge_summary(pid)
        return persona

    def _hour_histogram(self, pid: str) -> List[int]:
        counts = [0] * 24
        for row in self._iter(
            "SELECT utc_hour, COUNT(*) n FROM posts WHERE persona_id=? GROUP BY utc_hour", (pid,)
        ):
            counts[row["utc_hour"]] = row["n"]
        return counts

    def _persona_edge_summary(self, pid: str) -> List[Dict[str, Any]]:
        if pid not in self.graph:
            return []
        summary: Dict[str, Dict[str, Any]] = {}
        for _, _, data in self.graph.in_edges(pid, data=True):
            key = data.get("type", "EDGE")
            entry = summary.setdefault(key, {"type": key, "count": 0, "confidence": 0.0})
            entry["count"] += 1
            entry["confidence"] = max(entry["confidence"], float(data.get("confidence", 0)))
        for _, _, data in self.graph.out_edges(pid, data=True):
            key = data.get("type", "EDGE")
            entry = summary.setdefault(key, {"type": key, "count": 0, "confidence": 0.0})
            entry["count"] += 1
            entry["confidence"] = max(entry["confidence"], float(data.get("confidence", 0)))
        return sorted(summary.values(), key=lambda e: -e["confidence"])

    # -- KPIs -------------------------------------------------------------- #

    def kpis(self) -> Dict[str, Any]:
        persona_ids = {p["id"] for p in self.personas}
        clearnet = self._rows(
            "SELECT DISTINCT origin_ip FROM onion_services WHERE origin_ip IS NOT NULL")
        high = [p for p in self.personas if p["confidence"] > 0.85]
        mergers = []
        for actor in self.actors:
            members = [p for p in self.personas if p["actor_id"] == actor["id"]]
            sources = {m["source_id"] for m in members}
            if len(members) > 1 and len(sources) > 1:
                mergers.append({
                    "cluster": actor["codename"],
                    "personas": [m["handle"] for m in members],
                    "venues": sorted(sources),
                    "method": actor["resolution_method"],
                    "confidence": actor["confidence"],
                })
        return {
            "total_personas": len(persona_ids),
            "total_clusters": len(self.actors),
            "clearnet_links": len(clearnet),
            "clearnet_ips": sorted({r["origin_ip"] for r in clearnet}),
            "cross_market_merges": len(mergers),
            "merges": mergers,
            "high_confidence": len(high),
            "high_confidence_pct": round(_safe_div(len(high), len(persona_ids)) * 100, 1),
              "selectors_tracked": self._scalar("SELECT COUNT(*) FROM selectors"),
              "posts_corpus": len(self.posts),
              "onion_services": len(self.corpus["onion_services"]),
              "hard_selector_links": len(self.resolution["hard_links"]),
              "soft_capped_clusters": self.resolution["soft_capped_clusters"],
              "contested_signals": self._scalar(
                  "SELECT COUNT(*) FROM infra_links WHERE contested=1"),
            "corpus_version": self.corpus["meta"]["corpus_version"],
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    # -- graph serialisation ----------------------------------------------- #

    def graph_payload(
        self,
        persona_ids: Optional[Iterable[str]] = None,
        include_selector_nodes: bool = True,
        soft_links: bool = True,
    ) -> Dict[str, Any]:
        keep = set(persona_ids) if persona_ids is not None else {p["id"] for p in self.personas}
        actors = {self._pid_actor(pid) for pid in keep}
        allowed_nodes: set[str] = set()
        for pid in keep:
            allowed_nodes.add(pid)
            allowed_nodes.add(self._pid_actor(pid))
            allowed_nodes.add(self.persona_by_id[pid]["source_id"])
        if include_selector_nodes:
            # Pull in every selector-bearing node reachable from a kept persona.
            for node_id, node in self.graph.nodes(data=True):
                if node.get("type") in {"PGPKey", "CryptoWallet", "OnionService",
                                        "MessagingID", "TxCluster", "ClearnetIP"}:
                    neighbours = set(self.graph.successors(node_id)) | \
                        set(self.graph.predecessors(node_id))
                    if neighbours & allowed_nodes:
                        allowed_nodes.add(node_id)

        nodes: List[Dict[str, Any]] = []
        for node_id in allowed_nodes:
            if node_id not in self.graph:
                continue
            data = dict(self.graph.nodes[node_id])
            if data.get("type") == "Market":
                data["visible"] = False
            data["id"] = node_id
            data["color"] = ENTITY_COLORS.get(data.get("type", ""), "#64748b")
            if data.get("type") == "Persona":
                data["category_color"] = CATEGORY_COLORS.get(data.get("category"), "#38bdf8")
                data["size"] = 34 + 26 * float(data.get("confidence", 0.5))
            elif data.get("type") == "ThreatActor":
                data["size"] = 46 + 24 * float(data.get("confidence", 0.5))
            else:
                data["size"] = 20
            nodes.append(data)

        edges: List[Dict[str, Any]] = []
        for u, v, data in self.graph.edges(data=True):
            if u not in allowed_nodes or v not in allowed_nodes:
                continue
            etype = data.get("type", "EDGE")
            if not soft_links and etype in {"STYLOMETRY_LINK", "CIRCADIAN_LINK",
                                            "INFRA_MATCH_CONTESTED"}:
                continue
            confidence = float(data.get("confidence", 0.0))
            edges.append({
                "id": data.get("id"),
                "source": u, "target": v, "type": etype,
                "confidence": round(confidence, 4),
                "width": round(0.7 + 3.4 * confidence, 2),
                "label": data.get("label", ""),
                "evidence": data.get("evidence", ""),
                "color": _edge_color(etype, confidence),
                "dashed": etype in {"STYLOMETRY_LINK", "CIRCADIAN_LINK",
                                    "INFRA_MATCH_CONTESTED"},
            })
        return {"nodes": nodes, "edges": edges,
                "stats": {"nodes": len(nodes), "edges": len(edges),
                          "personas": len(keep), "actors": len(actors or set())}}

    # -- attribution ------------------------------------------------------- #

    def analyze(
        self,
        text: str = "",
        pgp: Optional[str] = None,
        wallet: Optional[str] = None,
        onion: Optional[str] = None,
        posting_hours: Optional[Sequence[int]] = None,
        sample_label: str = "New sample",
    ) -> Dict[str, Any]:
        text = (text or "").strip()
        posting_hours = sorted({int(h) % 24 for h in (posting_hours or [])})
        vector_log: List[Dict[str, Any]] = []
        selector_log: List[Dict[str, Any]] = []

        # --- hard selector resolution -------------------------------------- #
        hard: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        def register(pid: str, vector: str, label: str, value: str, note: str,
                     similarity: float = 1.0) -> None:
            hard[pid].append({
                "vector": vector, "label": label, "value": value,
                "note": note, "similarity": round(similarity, 4),
                "weight": SUBVECTOR_WEIGHTS.get(vector, 0.5),
            })
            selector_log.append({
                "query": label, "value": value, "matched_persona":
                    self.persona_by_id[pid]["handle"],
                "matched_actor": self.actor_codename[self.persona_by_id[pid]["actor_id"]],
                "vector": vector, "note": note,
            })

        if pgp:
            for key in self.pgp_index.get(pgp.strip().lower(), []):
                vector = "pgp_primary" if key["type"] == "pgp_primary" else "pgp_subkey"
                register(key["persona_id"], vector, key["label"], key["value"], key["note"])
        if wallet:
            found = self.wallet_index.get(wallet.strip().lower())
            if found:
                cluster = self._rows(
                    "SELECT COUNT(*) n FROM wallets WHERE tx_cluster=?",
                    (found["tx_cluster"],))[0]["n"]
                register(found["persona_id"], "wallet_address",
                         f"Wallet address hit ({found['currency']})", found["address"],
                         found["note"])
                if cluster > 1:
                    register(found["persona_id"], "tx_cluster",
                             f"Transaction cluster {found['tx_cluster']} (n={cluster})",
                             found["tx_cluster"],
                             "Common-input co-spending cluster; "
                             + str(cluster) + " payout addresses.")
        if onion:
            for svc in self.onion_index.get(onion.strip().lower(), []):
                register(svc["persona_id"], "onion_reuse", svc["title"], svc["address"],
                         svc["osint_note"])
                register(svc["persona_id"], "cert_serial",
                         f"TLS serial {svc['cert_serial']}", svc["cert_serial"],
                         svc["osint_note"], svc["confidence"])
                register(svc["persona_id"], "favicon_mmh3",
                         f"favicon mmh3 {svc['favicon_mmh3']}", svc["favicon_mmh3"],
                         f"banner: {svc['server_header']}, "
                         f"/server-status {'open' if svc['server_status'] else 'closed'}",
                         svc["confidence"])
                # Surface cross-actor collisions as contested.
                for link in self._rows(
                    "SELECT * FROM infra_links WHERE contested=1 AND "
                    "(owner_onion=? OR other_onion=?)", (svc["id"], svc["id"])
                ):
                    other = self._rows("SELECT * FROM onion_services WHERE id=?",
                                       (link["other_onion"],))
                    if other and other[0]["persona_id"] != svc["persona_id"]:
                        selector_log.append({
                            "query": f"{link['kind']} collision",
                            "value": link["value"],
                            "matched_persona": self.persona_by_id[
                                other[0]["persona_id"]]["handle"],
                            "matched_actor": self.actor_codename[
                                self.persona_by_id[other[0]["persona_id"]]["actor_id"]],
                            "vector": "favicon_mmh3",
                            "contested": True,
                            "note": link["note"],
                        })

        # --- behavioural vectors ------------------------------------------- #
        stylometry: Dict[str, Dict[str, Dict[str, float]]] = {}
        if text:
            stylometry = self.stylometry.similarities(text)
            if len(text) < 40:
                vector_log.append({
                    "vector": "text_quality",
                    "note": "Sample is shorter than 40 characters. Word TF-IDF and "
                            "topic vectors are down-weighted to 40% for short inputs; "
                            "character n-grams remain fully trusted.",
                })

        circadian: Dict[str, Dict[str, Any]] = {}
        if len(posting_hours) >= 3:
            query_profile = CircadianEngine.from_counts(
                [(hour, 1.0) for hour in posting_hours])
            circadian = self.circadian.compare(query_profile)

        # --- per-persona fusion -------------------------------------------- #
        per_persona: List[Dict[str, Any]] = []
        for pid in self.persona_ids:
            persona = self.persona_by_id[pid]
            vectors: List[Dict[str, Any]] = []

            if text:
                sims = stylometry[pid]
                for name, group in (("char_ngram", "stylometric"),
                                    ("word_tfidf", "stylometric"),
                                    ("orthographic", "stylometric"),
                                    ("topic_overlap", "stylometric"),
                                    ("punctuation", "formatting")):
                    weight = SUBVECTOR_WEIGHTS[name]
                    if len(text) < 40 and name in {"word_tfidf", "topic_overlap"}:
                        weight *= 0.4
                    score = sims[name]["score"]
                    vectors.append({
                        "group": group, "vector": name, "weight": weight,
                        "similarity": score, "raw": sims[name]["raw"],
                        "z": sims[name]["z"], "null_mean": sims[name]["null_mean"],
                        "null_sigma": sims[name]["null_sigma"],
                        "method": sims[name]["method"],
                        "fired": score > 0.0,
                        "contribution": weight * score,
                    })

            if circadian:
                payload = circadian[pid]
                vectors.append({
                    "group": "circadian", "vector": "activity_window",
                    "weight": SUBVECTOR_WEIGHTS["activity_window"],
                    "similarity": payload["score"], "raw": payload["raw"],
                    "z": payload["z"], "null_mean": payload["null_mean"],
                    "null_sigma": payload["null_sigma"],
                    "method": payload["method"], "fired": payload["score"] > 0.0,
                    "contribution": SUBVECTOR_WEIGHTS["activity_window"] * payload["score"],
                })

            for item in hard.get(pid, []):
                vectors.append({
                    "group": "crypto" if item["vector"] in
                    {"pgp_primary", "pgp_subkey", "wallet_address", "tx_cluster"}
                    else "infrastructure",
                    "vector": item["vector"], "weight": item["weight"],
                    "similarity": item["similarity"], "raw": item["similarity"],
                    "z": None, "method": "exact selector match",
                    "label": item["label"], "value": item["value"], "note": item["note"],
                    "fired": True,
                    "contribution": item["weight"] * item["similarity"],
                })

            per_persona.append(self._fuse(persona, vectors))

        # --- roll up to actor clusters ------------------------------------- #
        per_actor: List[Dict[str, Any]] = []
        for actor in self.actors:
            members = [r for r in per_persona if r["actor_id"] == actor["id"]]
            if not members:
                continue
            best = max(members, key=lambda r: r["score"])
            hard_fired = any(v["group"] in {"crypto", "infrastructure"} and v["fired"]
                             for v in best["vectors"])
            per_actor.append({
                "actor_id": actor["id"],
                "actor": actor["codename"],
                "category": actor["category"],
                "threat_level": actor["threat_level"],
                "resolution_method": actor["resolution_method"],
                "best_persona": best["handle"],
                "best_persona_id": best["persona_id"],
                "score": best["score"],
                "uncapped_score": best["uncapped_score"],
                "hard_selector_fired": hard_fired,
                "channels": best["channels"],
                "vectors": best["vectors"],
                "margin": 0.0,
                "verdict": best["verdict"],
                "cap_applied": best["cap_applied"],
            })
        per_actor.sort(key=lambda r: -r["score"])
        for index, row in enumerate(per_actor):
            row["margin"] = round(
                row["score"] - (per_actor[index + 1]["score"] if index + 1 < len(per_actor) else 0.0),
                4)

        top = per_actor[0] if per_actor else None
        verdict = "NO_MATCH"
        verdict_reason = "No usable evidence vectors were supplied."
        if top:
            runner = per_actor[1] if len(per_actor) > 1 else None
            if top["score"] < MIN_FLOOR:
                verdict = "NO_MATCH"
                verdict_reason = (
                    f"Best cluster scored {top['score']:.1%}, below the {MIN_FLOOR:.0%} "
                    f"reporting floor. No vector cleared the cross-actor null, so "
                    f"there is nothing to attribute.")
            elif runner and top["margin"] < MIN_MARGIN and not top["hard_selector_fired"]:
                verdict = "INCONCLUSIVE"
                verdict_reason = (
                    f"{len([r for r in per_actor if r['score'] >= MIN_FLOOR])} clusters "
                    f"sit within {top['margin']:.1%} of the leader ({runner['actor']} at "
                    f"{runner['score']:.1%}). Stylometric evidence alone cannot separate "
                    f"them -- collect a PGP key, wallet or onion selector.")
            else:
                verdict = classify_verdict(top["score"], top["hard_selector_fired"])
                if top["cap_applied"] and top["cap_note"]:
                    verdict_reason = top["cap_note"]
                elif verdict == "CONFIRMED":
                    verdict_reason = (
                        "A hard selector (PGP key material, wallet cluster or "
                        "infrastructure fingerprint) matched and every behavioural "
                        "vector agrees.")
                elif verdict == "ASSESSED":
                    verdict_reason = (
                        "Hard selector matched, but behavioural vectors are mixed. "
                        "Treat as a moderate assessment pending a second sample.")
                elif verdict == "PROBABLE_SOFT":
                    verdict_reason = (
                        "Behavioural agreement is decisive with a clear margin over the "
                        f"runner-up, but no hard selector fired, so the score is capped at "
                        f"{SOFT_MATCH_CAP:.0%}. Prose is a lead; a selector is proof.")
                elif verdict == "LEAD":
                    verdict_reason = (
                        "Elevated behavioural similarity with a clear margin over the "
                        "runner-up. Requires a second, independent sample before action.")
                else:
                    verdict_reason = "Some stylistic affinity, no decisive separation."

        rebrand = self._rebrand_assessment(per_persona, top, text, stylometry)

        return {
            "query": {
                "text_length": len(text),
                "text_excerpt": text[:280],
                "pgp": pgp, "wallet": wallet, "onion": onion,
                "posting_hours": posting_hours,
                "posting_hour_counts": [posting_hours.count(h) for h in range(24)] if posting_hours else [],
                "vectors_fired": sorted({
                    v["vector"] for r in per_persona for v in r["vectors"] if v["fired"]}),
                "label": sample_label,
            },
            "verdict": verdict,
            "verdict_reason": verdict_reason,
            "attribution": top,
            "ranking": per_actor,
            "persona_ranking": sorted(per_persona, key=lambda r: -r["score"]),
            "rebrand": rebrand,
            "selector_hits": selector_log,
            "notes": vector_log,
            "graph_patch": self._graph_patch(sample_label, top, rebrand),
            "methodology": {
                "formula": "Score = 1 - prod(1 - weight_i * similarity_i)",
                "channel_weights": CHANNEL_WEIGHTS,
                "subvector_weights": SUBVECTOR_WEIGHTS,
                "soft_match_cap": SOFT_MATCH_CAP,
                "hard_match_ceiling": HARD_MATCH_CEILING,
                "min_margin": MIN_MARGIN,
                "calibration": (
                    "Every continuous vector is z-scored against a leave-one-out "
                    "impostor null built from the corpus itself, then capped at 4 sigma "
                    "(3 sigma for circadian). Reported z-scores are therefore auditable "
                    "against a stated null rather than an arbitrary scale."),
            },
        }

    def _fuse(self, persona: Dict[str, Any], vectors: List[Dict[str, Any]]) -> Dict[str, Any]:
        groups: Dict[str, Dict[str, Any]] = {}
        for group, weight in CHANNEL_WEIGHTS.items():
            members = [v for v in vectors if v["group"] == group and v["fired"]]
            if not members:
                groups[group] = {"group": group, "fired": False, "similarity": 0.0,
                                 "contribution": 0.0, "weight": weight, "vectors": []}
                continue
            similarity = float(np.mean([v["similarity"] for v in members]))
            contribution = weight * similarity
            groups[group] = {
                "group": group, "fired": True,
                "similarity": round(similarity, 4),
                "weight": weight,
                "contribution": round(contribution, 4),
                "vectors": sorted(members, key=lambda v: -v["contribution"]),
            }

        # Noisy-OR over the groups that fired.
        survival = 1.0
        for group in groups.values():
            if group["fired"]:
                survival *= (1.0 - _clamp(group["contribution"]))
        uncapped = _clamp(1.0 - survival)

        hard_fired = any(groups[g]["fired"] for g in ("crypto", "infrastructure"))
        contradictions = [
            v for v in vectors
            if v["fired"] and v.get("raw") is not None and v["raw"] < 0
            and v["group"] == "circadian"
        ]
        score = uncapped
        cap_applied = False
        cap_note = ""
        if not hard_fired:
            if uncapped > SOFT_MATCH_CAP:
                score = SOFT_MATCH_CAP
                cap_applied = True
                cap_note = (f"No hard selector fired. Behavioural-only attribution "
                            f"capped at {SOFT_MATCH_CAP:.0%} per analyst policy.")
        else:
            if score > HARD_MATCH_CEILING:
                score = HARD_MATCH_CEILING
                cap_applied = True
                cap_note = f"Saturated at the {HARD_MATCH_CEILING:.1%} certainty ceiling."
        if contradictions:
            score *= 0.92
            cap_note = (cap_note + " " if cap_note else "") + (
                "Circadian rhythm is anti-correlated (r<0), which contradicts the "
                "other vectors; final score reduced by 8%.")

        return {
            "persona_id": persona["id"],
            "handle": persona["handle"],
            "actor_id": persona["actor_id"],
            "actor": self.actor_codename[persona["actor_id"]],
            "category": persona["category"],
            "source": persona["source_id"],
            "score": round(score, 4),
            "uncapped_score": round(uncapped, 4),
            "cap_applied": cap_applied,
            "cap_note": cap_note.strip(),
            "hard_selector_fired": hard_fired,
            "verdict": classify_verdict(score, hard_fired),
            "channels": groups,
            "vectors": sorted(vectors, key=lambda v: -v["contribution"]),
            "firings": len([v for v in vectors if v["fired"]]),
        }

    def _rebrand_assessment(
        self,
        per_persona: List[Dict[str, Any]],
        top: Optional[Dict[str, Any]],
        text: str,
        stylometry: Dict[str, Dict[str, Dict[str, float]]],
    ) -> Dict[str, Any]:
        rebranders = [p for p in self.personas if p["rebrand_of"]]
        findings: List[Dict[str, Any]] = []
        for successor in rebranders:
            predecessor_id = successor["rebrand_of"]
            predecessor = self.persona_by_id[predecessor_id]
            a = next((r for r in per_persona if r["persona_id"] == successor["id"]), None)
            b = next((r for r in per_persona if r["persona_id"] == predecessor_id), None)
            if not a or not b:
                continue
            r_circ = self.circadian.pearson(
                self.circadian.profiles[successor["id"]],
                self.circadian.profiles[predecessor_id])
            sim = stylometry.get(successor["id"], {}).get("char_ngram", {}).get("raw") if text else None
            overlap = self._selector_overlap(successor["id"], predecessor_id)
            if overlap["any"]:
                continue
            findings.append({
                "successor": successor["handle"],
                "predecessor": predecessor["handle"],
                "actor": self.actor_codename[successor["actor_id"]],
                "successor_score": a["score"],
                "predecessor_score": b["score"],
                "char_ngram_raw": round(sim, 4) if sim is not None else None,
                "circadian_r": round(r_circ, 4),
                "hard_selector_overlap": overlap,
                "dormant_days": (
                    datetime.strptime(successor["first_seen"], "%Y-%m-%d")
                    - datetime.strptime(predecessor["last_scan_date"], "%Y-%m-%d")
                ).days,
                "note": successor["rebrand_note"],
            })
        detected = bool(top and any(
            top["actor_id"] == self.persona_by_handle[f["successor"]]["actor_id"]
            for f in findings if f["successor"] in self.persona_by_handle))
        return {
            "detected": detected,
            "candidates": findings,
            "method": (
                "Compare each registered successor persona against its declared "
                "predecessor: character n-gram cosine, 24h UTC phase correlation, and "
                "an explicit negative control proving the absence of shared PGP "
                "packets, wallet clusters and certificate serials."),
        }

    def _selector_overlap(self, a: str, b: str) -> Dict[str, Any]:
        """Explicit positive/negative selector comparison between two personas."""
        def values(pid: str, table: str, column: str) -> set:
            return {
                (row[0] or "").lower()
                for row in self._iter(
                    f"SELECT {column} FROM {table} WHERE persona_id=?", (pid,))
                if row[0]
            }

        pgp_a = values(a, "pgp_keys", "value")
        pgp_b = values(b, "pgp_keys", "value")
        wallet_a = values(a, "wallets", "address")
        wallet_b = values(b, "wallets", "address")
        cluster_a = values(a, "wallets", "tx_cluster")
        cluster_b = values(b, "wallets", "tx_cluster")
        cert_a = values(a, "onion_services", "cert_serial")
        cert_b = values(b, "onion_services", "cert_serial")
        return {
            "pgp_shared": sorted(pgp_a & pgp_b),
            "wallet_shared": sorted(wallet_a & wallet_b),
            "tx_cluster_shared": sorted(cluster_a & cluster_b),
            "cert_serial_shared": sorted(cert_a & cert_b),
            "any": bool((pgp_a & pgp_b) or (wallet_a & wallet_b)
                        or (cluster_a & cluster_b) or (cert_a & cert_b)),
        }

    def _graph_patch(
        self, label: str, top: Optional[Dict[str, Any]], rebrand: Dict[str, Any]
    ) -> Dict[str, Any]:
        sample_id = "sample-" + re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:40]
        node = {
            "id": sample_id, "type": "Sample", "label": label,
            "color": ENTITY_COLORS["Sample"], "size": 30,
            "confidence": top["score"] if top else 0.0, "visible": True,
        }
        edges: List[Dict[str, Any]] = []
        if top:
            edges.append({
                "id": f"{sample_id}--{top['actor_id']}", "source": sample_id,
                "target": top["actor_id"], "type": "SAMPLE_MATCH",
                "confidence": top["score"],
                "width": round(0.7 + 3.4 * top["score"], 2),
                "label": f"attribution {top['score']:.0%}",
                "evidence": top.get("verdict_reason", ""),
                "color": "#f472b6", "dashed": False,
            })
        for finding in rebrand.get("candidates", [])[:1]:
            successor = self.persona_by_handle.get(finding["successor"])
            if top and successor and top["actor_id"] == successor["actor_id"]:
                for handle in (finding["successor"], finding["predecessor"]):
                    pid = self.persona_by_handle[handle]["id"]
                    edges.append({
                        "id": f"{sample_id}--{pid}", "source": sample_id, "target": pid,
                        "type": "SAMPLE_STYLOMETRY", "confidence": top["score"],
                        "width": round(0.7 + 3.4 * top["score"], 2),
                        "label": f"style match -> {handle}",
                        "evidence": f"24h UTC r = {finding['circadian_r']}",
                        "color": "#f472b6", "dashed": True,
                    })
        return {"nodes": [node], "edges": edges}

    # -- exports ----------------------------------------------------------- #

    def export_rows(self, personas: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for persona in personas:
            crypto = [e for e in persona["evidence"] if e["group"] == "crypto"]
            infra = [e for e in persona["evidence"] if e["group"] == "infrastructure"]
            best_infra = max(infra, key=lambda e: e["similarity"], default=None)
            rows.append({
                "actor_cluster": persona["actor_codename"],
                "handle": persona["handle"],
                "source": persona["source_name"],
                "category": persona["category"],
                "threat_level": persona["threat_level"],
                "status": persona["status"],
                "first_seen": persona["first_seen"],
                "last_scan_date": persona["last_scan_date"],
                "confidence": f"{persona['confidence']:.2f}",
                "resolution_method": persona["resolution_method"],
                "pgp_keys": len(persona["pgp_keys"]),
                "wallets": len(persona["wallets"]),
                "onion_services": len(persona["onion_services"]),
                "selectors": len(persona["selectors"]),
                "clearnet_ips": "; ".join(sorted({
                    s["origin_ip"] for s in persona["onion_services"] if s["origin_ip"]})),
                "strongest_infra_vector": (
                    f"{best_infra['vector']}={best_infra['similarity']:.2f}"
                    if best_infra else "none"),
                "crypto_reuse": ("; ".join(
                    f"{e['vector']}={e['similarity']:.2f}" for e in crypto) or "none"),
                "peak_utc_hour": persona["hour_histogram"].index(max(persona["hour_histogram"])),
                "posts": persona["post_count"],
                "rebrands_from": "; ".join(p["handle"] for p in persona.get("rebrands", [])),
                "bio": persona["bio"],
            })
        return rows

    def to_csv(self, personas: Sequence[Dict[str, Any]]) -> str:
        rows = self.export_rows(personas)
        if not rows:
            return ""
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()),
                                lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        return buffer.getvalue()

    def to_json(self, personas: Sequence[Dict[str, Any]]) -> str:
        payload = {
            "meta": {
                **self.corpus["meta"],
                "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "record_count": len(personas),
                "classification": "TLP:AMBER // SYNTHETIC DEMONSTRATION DATA",
            },
            "kpis": self.kpis(),
            "cluster_resolution": self.resolution,
            "personas": personas,
        }
        return json.dumps(payload, indent=2, ensure_ascii=False, default=str)

    def to_dossier(self, personas: Sequence[Dict[str, Any]], title: str) -> str:
        e = html.escape
        kpis = self.kpis()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        parts: List[str] = []
        parts.append(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{e(title)}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: "Segoe UI", system-ui, sans-serif; background:#0b0f17; color:#cbd5e1;
         margin:0; padding:32px; font-size:13px; }}
  .banner {{ background:linear-gradient(90deg,#7f1d1d,#b91c1c); color:#fff; padding:10px 16px;
             letter-spacing:.16em; font-size:11px; font-weight:700; border-radius:4px; }}
  h1 {{ font-size:26px; margin:18px 0 4px; color:#f1f5f9; letter-spacing:.04em; }}
  h2 {{ font-size:15px; color:#38bdf8; margin:28px 0 8px; border-left:3px solid #38bdf8;
        padding-left:10px; text-transform:uppercase; letter-spacing:.1em; }}
  .sub {{ color:#64748b; margin-bottom:20px; }}
  .kpis {{ display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin:16px 0; }}
  .kpi {{ background:#111827; border:1px solid #1f2937; border-radius:6px; padding:12px; }}
  .kpi .n {{ font-size:24px; color:#f8fafc; font-weight:700; }}
  .kpi .l {{ font-size:10px; color:#64748b; text-transform:uppercase; letter-spacing:.1em; }}
  table {{ width:100%; border-collapse:collapse; margin:8px 0; font-size:11.5px; }}
  th {{ background:#111827; color:#38bdf8; text-align:left; padding:7px 8px;
        border-bottom:1px solid #1f2937; font-size:10px; letter-spacing:.08em;
        text-transform:uppercase; }}
  td {{ padding:7px 8px; border-bottom:1px solid #111827; vertical-align:top; }}
  tr:nth-child(even) td {{ background:#0d1420; }}
  .card {{ background:#0f1722; border:1px solid #1f2937; border-radius:6px; padding:14px;
           margin:10px 0; break-inside:avoid; }}
  .card h3 {{ margin:0 0 6px; color:#e2e8f0; font-size:14px; }}
  .muted {{ color:#64748b; font-size:11px; }}
  .tag {{ display:inline-block; background:#1e293b; color:#94a3b8; border-radius:3px;
          padding:2px 7px; margin:2px 3px 2px 0; font-size:10px; }}
  .bar {{ height:7px; background:#1e293b; border-radius:3px; overflow:hidden; width:130px;
          display:inline-block; vertical-align:middle; }}
  .bar > i {{ display:block; height:100%; background:linear-gradient(90deg,#0ea5e9,#22d3ee); }}
  .pos {{ color:#34d399; }} .neg {{ color:#f43f5e; }} .warn {{ color:#f59e0b; }}
  .mono {{ font-family:Consolas,monospace; font-size:10.5px; color:#94a3b8;
           word-break:break-all; }}
  .sig {{ margin-top:34px; display:grid; grid-template-columns:1fr 1fr; gap:26px; }}
  .sig div {{ border-top:1px solid #334155; padding-top:7px; color:#64748b; font-size:11px; }}
  footer {{ margin-top:30px; padding-top:12px; border-top:1px solid #1f2937; color:#475569;
            font-size:10px; }}
  @media print {{
    body {{ background:#fff; color:#111; padding:0; }}
    .card, table td, .kpi {{ background:#fff !important; border-color:#ccc !important; }}
    h1, h2, h3 {{ color:#000 !important; }} th {{ background:#eee !important; color:#000 !important; }}
    .muted, .mono, .sub, footer {{ color:#555 !important; }}
    .banner {{ background:#7f1d1d !important; -webkit-print-color-adjust:exact; }}
    .bar > i {{ background:#0ea5e9 !important; -webkit-print-color-adjust:exact; }}
    .kpi .n {{ color:#000 !important; }}
  }}
  @page {{ size:A4; margin:14mm; }}
</style></head><body>
<div class="banner">TLP:AMBER &nbsp;//&nbsp; SYNTHETIC DEMONSTRATION CORPUS &nbsp;//&nbsp;
  NOT REAL IDENTIFIERS &nbsp;//&nbsp; NO LIVE SCANNING PERFORMED</div>
<h1>{e(title)}</h1>
<div class="sub">Team {e(self.corpus["meta"]["team"])} &nbsp;|&nbsp; SIH PS {e(self.corpus["meta"]["problem_statement_id"])}
  &nbsp;|&nbsp; {e(self.corpus["meta"]["problem_title"])} &nbsp;|&nbsp; corpus
  {e(kpis["corpus_version"])} &nbsp;|&&nbsp; generated {e(now)}</div>
<div class="kpis">
  <div class="kpi"><div class="n">{kpis['total_personas']}</div><div class="l">Tracked personas</div></div>
  <div class="kpi"><div class="n">{kpis['total_clusters']}</div><div class="l">Actor clusters</div></div>
  <div class="kpi"><div class="n">{kpis['clearnet_links']}</div><div class="l">Clearnet resolutions</div></div>
  <div class="kpi"><div class="n">{kpis['cross_market_merges']}</div><div class="l">Cross-market merges</div></div>
  <div class="kpi"><div class="n">{kpis['high_confidence']}</div><div class="l">Attributions &gt;85%</div></div>
</div>""")

        parts.append("<h2>Cluster resolution log</h2><table><tr><th>Cluster</th><th>Method</th>"
                     "<th>Verdict</th><th>Conf.</th><th>Analyst note</th></tr>")
        for entry in self.resolution["log"]:
            parts.append(
                f"<tr><td><b>{e(entry['cluster_id'])}</b></td><td>{e(entry['method'])}</td>"
                f"<td>{e(entry['verdict'])}</td><td>{entry['confidence']:.2f}</td>"
                f"<td class='muted'>{e(entry['detail'])}</td></tr>")
        parts.append("</table>")

        parts.append(f"<h2>Persona dossiers ({len(personas)} record(s))</h2>")
        for persona in personas:
            conf = persona["confidence"]
            band = "HIGH" if conf > 0.9 else "MEDIUM" if conf > 0.8 else "LOW"
            parts.append(f"""
<div class="card">
  <h3>{e(persona['handle'])} &nbsp;<span class="muted">// {e(persona['actor_codename'])}</span>
    &nbsp;<span class="pos">{conf:.0%}</span> <span class="muted">[{band}]</span></h3>
  <div>
    <span class="tag">{e(persona['source_name'])}</span>
    <span class="tag">{e(persona['category'])}</span>
    <span class="tag">{e(persona['threat_level'])}</span>
    <span class="tag">{e(persona['status'])}</span>
    <span class="tag">{e(persona['resolution_method'])}</span>
    <span class="tag">{persona['first_seen']} &rarr; {persona['last_scan_date']}</span>
    <span class="tag">{persona['post_count']} posts</span>
    <span class="tag">peak {persona['hour_histogram'].index(max(persona['hour_histogram'])):02d}:00 UTC</span>
  </div>
  <p class="muted">{e(persona['bio'])}</p>
  <div class="bar"><i style="width:{conf * 100:.0f}%"></i></div>
</div>""")

            parts.append("<h3 style='color:#94a3b8'>Evidence breakdown</h3><table>"
                         "<tr><th>Channel</th><th>Vector</th><th>Match</th><th>Similarity</th>"
                         "<th>Weight</th><th>Analyst detail</th></tr>")
            for ev in persona["evidence"]:
                sim = ev["similarity"]
                cls = "neg" if sim == 0 else "warn" if sim < 0.5 else "pos"
                parts.append(
                    f"<tr><td>{e(ev['group'])}</td><td>{e(ev['vector'])}</td>"
                    f"<td class='{cls}'>{sim:.0%}</td>"
                    f"<td><span class='bar'><i style='width:{sim * 100:.0f}%'></i></span></td>"
                    f"<td>{ev['weight']:.2f}</td><td class='muted'>{e(ev['detail'])}</td></tr>")
            parts.append("</table>")

            if persona["onion_services"]:
                parts.append("<h3 style='color:#94a3b8'>Infrastructure correlation</h3>"
                             "<table><tr><th>.onion</th><th>Cert serial</th><th>favicon mmh3</th>"
                             "<th>Banner</th><th>/server-status</th><th>Origin</th><th>ASN</th>"
                             "<th>Conf.</th></tr>")
                for svc in persona["onion_services"]:
                    parts.append(
                        f"<tr><td class='mono'>{e(svc['address'][:26])}…</td>"
                        f"<td class='mono'>{e(svc['cert_serial'])}</td>"
                        f"<td class='mono'>{e(svc['favicon_mmh3'])}</td>"
                        f"<td>{e(svc['server_header'])}</td>"
                        f"<td class='{'warn' if svc['server_status'] else 'muted'}'>"
                        f"{'OPEN' if svc['server_status'] else 'closed'}</td>"
                        f"<td class='mono'>{e(svc['origin_ip'])}</td>"
                        f"<td>{e(svc['origin_asn'])}</td><td>{svc['confidence']:.0%}</td></tr>")
                parts.append("</table>")

            if persona["selectors"]:
                parts.append("<h3 style='color:#94a3b8'>Selectors</h3><table>"
                             "<tr><th>Type</th><th>Value</th><th>First seen</th>"
                             "<th>Last seen</th></tr>")
                for sel in persona["selectors"]:
                    parts.append(
                        f"<tr><td>{e(sel['type'])}</td><td class='mono'>{e(sel['value'])}</td>"
                        f"<td>{e(sel['first_seen'])}</td><td>{e(sel['last_seen'])}</td></tr>")
                parts.append("</table>")

            histogram = persona["hour_histogram"]
            peak = max(histogram) or 1
            bars = " ".join(
                f"<span title='{h:02d}:00 UTC' style='display:inline-block;width:9px;"
                f"height:{8 + 30 * (c / peak):.0f}px;background:#22d3ee;margin-right:1px'></span>"
                for h, c in enumerate(histogram))
            parts.append(f"<h3 style='color:#94a3b8'>24-hour UTC activity profile</h3>"
                         f"<div style='display:flex;align-items:flex-end'>{bars}</div>"
                         f"<div class='muted' style='margin-top:4px'>"
                         f"00:00 UTC &rarr; 23:00 UTC &nbsp;|&nbsp; peak "
                         f"{histogram.index(peak)}:00 UTC</div>")

            if persona["posts"]:
                parts.append("<h3 style='color:#94a3b8'>Sample posts</h3>")
                for post in persona["posts"][:3]:
                    body = e(post["body"])[:400].replace("\n", "<br>")
                    parts.append(f"<div class='card'><div class='muted'>"
                                 f"{e(post['posted_at'])} &nbsp;//&nbsp; {e(post['channel'])}"
                                 f"</div><div>{body}</div></div>")
            parts.append("</div>")

        parts.append("""
<h2>Timeline of platform events</h2>
<table><tr><th>Timestamp (UTC)</th><th>Severity</th><th>Event</th><th>Summary</th></tr>""")
        for event in self.corpus["timeline"]:
            cls = {"CRITICAL": "neg", "HIGH": "warn", "MEDIUM": "", "LOW": "muted"}[event["severity"]]
            parts.append(f"<tr><td class='mono'>{e(event['ts'])}</td>"
                         f"<td class='{cls}'>{e(event['severity'])}</td>"
                         f"<td>{e(event['kind'])}</td><td class='muted'>{e(event['summary'])}</td></tr>")
        parts.append("</table>")

        parts.append(f"""
<h2>Methodology &amp; limitations</h2>
<div class="card">
  <p><b>Fusion model.</b>
  <span class="mono">Score = 1 - prod(1 - w_i * s_i)</span> applied per evidence channel,
  then across channels. Channel priors: stylometric {CHANNEL_WEIGHTS['stylometric']},
  formatting {CHANNEL_WEIGHTS['formatting']}, circadian {CHANNEL_WEIGHTS['circadian']},
  cryptographic {CHANNEL_WEIGHTS['crypto']}, infrastructure
  {CHANNEL_WEIGHTS['infrastructure']}.</p>
  <p><b>Calibration.</b> Continuous vectors are z-scored against a leave-one-out
  impostor null built from the corpus itself and capped at 4 sigma (3 sigma for the
  circadian phase-shift null), so similarity values are auditable against a stated
  null rather than an arbitrary TF-IDF scale.</p>
  <p><b>Analyst policy.</b> Behavioural-only attributions are capped at
  {SOFT_MATCH_CAP:.0%} and labelled <i>LEAD</i>. A re-registration is not
  de-anonymised by prose alone; it needs a selector.</p>
  <p><b>Known limitation.</b> Corpus size is six personas, so the impostor null is
  estimated from roughly 720 impostor pairs. Confidence intervals on the calibrated
  values are correspondingly wide and the UI reports z-scores rather than
  pretending to a precision the data cannot support.</p>
  <p><b>Synthetic data.</b> {e(self.corpus['meta']['disclaimer'])}</p>
</div>
<div class="sig">
  <div>Analyst signature / date</div><div>Reviewing officer / date</div>
</div>
<footer>Team {e(self.corpus['meta']['team'])} &nbsp;|&nbsp; Smart India Hackathon 2026 &nbsp;|&nbsp;
  Problem statement {e(self.corpus['meta']['problem_statement_id'])} &nbsp;|&nbsp;
  Generated {e(now)} &nbsp;|&nbsp; {e(self.corpus['meta']['disclaimer'])}</footer>
</body></html>""")
        return "".join(parts)


def _edge_color(etype: str, confidence: float) -> str:
    if etype == "INFRA_MATCH_CONTESTED":
        return "#f59e0b"
    if etype == "STYLOMETRY_LINK":
        return "#a78bfa"
    if etype == "CIRCADIAN_LINK":
        return "#22d3ee"
    if etype == "CO_SPENT_TX":
        return "#34d399"
    if etype == "USES_PGP":
        return "#facc15"
    if etype == "PERSONA_OF":
        return "#ff2e63"
    if etype == "ORIGIN_OF":
        return "#fb923c"
    if etype in {"INFRA_MATCH", "ONION_REUSE"}:
        return "#fbbf24"
    if etype == "SAMPLE_MATCH":
        return "#f472b6"
    if confidence >= 0.9:
        return "#38bdf8"
    return "#475569"
