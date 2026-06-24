"""Cluster platform avatars by exact URL and perceptual-hash similarity."""

from __future__ import annotations

from typing import Any


class AvatarClusterer:
    """Group avatar observations using union-find transitive closure."""

    def __init__(self, max_hamming_distance: int = 5) -> None:
        self.max_hamming_distance = max_hamming_distance

    @staticmethod
    def _hamming(a: str, b: str) -> int:
        """Return the bitwise Hamming distance between two 64-bit hex hashes."""
        return bin(int(a, 16) ^ int(b, 16)).count("1")

    def cluster(self, pairs: list[tuple[str, str]]) -> list[dict[str, Any]]:
        """Return non-singleton clusters for ``(platform, avatar_url)`` observations."""
        if len(pairs) < 2:
            return []

        parent = list(range(len(pairs)))

        def find(index: int) -> int:
            while parent[index] != index:
                parent[index] = parent[parent[index]]
                index = parent[index]
            return index

        def union(left: int, right: int) -> None:
            left_root, right_root = find(left), find(right)
            if left_root != right_root:
                parent[right_root] = left_root

        urls: dict[str, list[int]] = {}
        for index, (_, url) in enumerate(pairs):
            urls.setdefault(url, []).append(index)
        for indexes in urls.values():
            for index in indexes[1:]:
                union(indexes[0], index)

        # Importing the network/image stack is deferred until distinct URLs need hashing.
        hashes: dict[str, str | None] = {}
        if len(urls) > 1:
            from backend.core.avatar_hasher import _fetch_phashes

            hashes = _fetch_phashes(list(urls))
        distinct_urls = list(urls)
        for left_pos, left_url in enumerate(distinct_urls):
            left_hash = hashes.get(left_url)
            if left_hash is None:
                continue
            for right_url in distinct_urls[left_pos + 1 :]:
                right_hash = hashes.get(right_url)
                if (
                    right_hash is not None
                    and self._hamming(left_hash, right_hash) <= self.max_hamming_distance
                ):
                    union(urls[left_url][0], urls[right_url][0])

        groups: dict[int, list[int]] = {}
        for index in range(len(pairs)):
            groups.setdefault(find(index), []).append(index)

        clusters: list[dict[str, Any]] = []
        for indexes in groups.values():
            if len(indexes) < 2:
                continue
            cluster_hash = next(
                (
                    hashes.get(pairs[index][1])
                    for index in indexes
                    if hashes.get(pairs[index][1])
                ),
                "",
            )
            clusters.append(
                {
                    "phash": cluster_hash,
                    "platforms": [pairs[index][0] for index in indexes],
                    "cluster_size": len(indexes),
                }
            )
        return clusters
