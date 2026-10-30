"""Search your notes with BM25 (the classic ranking algorithm behind many search engines)."""
import math
import re
from collections import Counter
from pathlib import Path

NOTE_EXTENSIONS = {".md", ".txt", ".markdown", ".rst", ".conf", ".py", ".sh", ".ps1"}
TOKEN_RE = re.compile(r"[a-z0-9_]+(?:[.\-/][a-z0-9_]+)*|[\u0600-\u06ff]+")  # notes may be non-English


def tokenize(text):
    return TOKEN_RE.findall(text.lower())


def chunk_text(text, max_chars=1200):
    """Split a file into readable chunks along blank lines and headings."""
    parts = re.split(r"\n\s*\n|(?=\n#{1,6} )", text)
    chunks, current = [], ""
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if current and len(current) + len(part) > max_chars:
            chunks.append(current)
            current = ""
        while len(part) > max_chars:
            chunks.append(part[:max_chars])
            part = part[max_chars:]
        current = f"{current}\n\n{part}" if current else part
    if current:
        chunks.append(current)
    return chunks


class NotesIndex:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.build()

    def build(self):
        self.chunks, self.tfs = [], []
        df = Counter()
        if self.folder.is_dir():
            for path in sorted(self.folder.rglob("*")):
                if not (path.is_file() and path.suffix.lower() in NOTE_EXTENSIONS):
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for chunk in chunk_text(text):
                    tf = Counter(tokenize(chunk))
                    if tf:
                        self.chunks.append((str(path.relative_to(self.folder)), chunk))
                        self.tfs.append(tf)
                        df.update(tf.keys())
        n = len(self.chunks)
        self.lengths = [sum(tf.values()) for tf in self.tfs]
        self.avg_len = (sum(self.lengths) / n) if n else 1
        self.idf = {w: math.log(1 + (n - d + 0.5) / (d + 0.5)) for w, d in df.items()}
        self.files = len({src for src, _ in self.chunks})

    def search(self, query, k=4, k1=1.5, b=0.75):
        words = set(tokenize(query))
        scored = []
        for i, tf in enumerate(self.tfs):
            score = 0.0
            for w in words:
                f = tf.get(w)
                if f:
                    norm = k1 * (1 - b + b * self.lengths[i] / self.avg_len)
                    score += self.idf[w] * f * (k1 + 1) / (f + norm)
            if score > 0:
                scored.append((score, i))
        scored.sort(reverse=True)
        if not scored:
            return []
        top = scored[0][0]
        # drop weak matches (less than 35% of the best one)
        return [(self.chunks[i][0], self.chunks[i][1], s) for s, i in scored[:k] if s >= 0.35 * top]
