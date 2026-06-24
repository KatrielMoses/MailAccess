"""Cluster platform bios by fuzzy text similarity."""

from __future__ import annotations

from typing import Any


class BioClusterer:
    """Group bio observations using union-find transitive closure."""

    def __init__(self, similarity_threshold: int = 85) -> None:
        self.similarity_threshold = similarity_threshold

    def _pairwise_similarities(self, bios: list[str]) -> list[list[float]]:
        """Return N×N similarity matrix using token_set_ratio scores.

        Uses rapidfuzz.process.cdist for ≥ 20 bios (C-accelerated); falls back
        to a nested Python loop for smaller inputs.
        """
        from rapidfuzz import fuzz

        n = len(bios)
        if n >= 20:
            try:
                from rapidfuzz import process

                raw = process.cdist(bios, bios, scorer=fuzz.token_set_ratio)
                return [list(row) for row in raw]
            except Exception:
                pass

        matrix = [[0.0] * n for _ in range(n)]
        for i in range(n):
            matrix[i][i] = 100.0
            for j in range(i + 1, n):
                score = float(fuzz.token_set_ratio(bios[i], bios[j]))
                matrix[i][j] = score
                matrix[j][i] = score
        return matrix

    def _average_pairwise(self, indexes: list[int], matrix: list[list[float]]) -> float:
        """Return average pairwise similarity within a cluster."""
        if not indexes:
            return 0.0
        if len(indexes) == 1:
            return 100.0
        total = 0.0
        count = 0
        for i, a in enumerate(indexes):
            for b in indexes[i + 1 :]:
                total += matrix[a][b]
                count += 1
        return total / count if count else 0.0

    def cluster(self, pairs: list[tuple[str, str]]) -> list[dict[str, Any]]:
        """Return non-singleton clusters for ``(platform_name, bio_text)`` observations."""
        if len(pairs) < 2:
            return []

        from backend.core.bio_similarity import normalize_bio

        indexed: list[tuple[int, str, str]] = []
        for i, (platform, bio) in enumerate(pairs):
            nbio = normalize_bio(bio)
            if len(nbio.replace(" ", "")) >= 5:
                indexed.append((i, platform, nbio))

        if len(indexed) < 2:
            return []

        platforms = [platform for _, platform, _ in indexed]
        bios = [nbio for _, _, nbio in indexed]
        n = len(indexed)

        matrix = self._pairwise_similarities(bios)

        parent = list(range(n))

        def find(idx: int) -> int:
            while parent[idx] != idx:
                parent[idx] = parent[parent[idx]]
                idx = parent[idx]
            return idx

        def union(left: int, right: int) -> None:
            left_root, right_root = find(left), find(right)
            if left_root != right_root:
                parent[right_root] = left_root

        for i in range(n):
            for j in range(i + 1, n):
                if matrix[i][j] >= self.similarity_threshold:
                    union(i, j)

        groups: dict[int, list[int]] = {}
        for idx in range(n):
            groups.setdefault(find(idx), []).append(idx)

        clusters: list[dict[str, Any]] = []
        for group_indexes in groups.values():
            if len(group_indexes) < 2:
                continue
            avg_sim = self._average_pairwise(group_indexes, matrix)
            group_bios = [bios[i] for i in group_indexes]
            bio_excerpt = min(
                (b for b in group_bios if b),
                key=len,
                default="",
            )
            clusters.append({
                "platforms": [platforms[i] for i in group_indexes],
                "similarity_score": round(avg_sim, 1),
                "bio_excerpt": bio_excerpt[:80],
                "cluster_size": len(group_indexes),
            })
        return clusters
