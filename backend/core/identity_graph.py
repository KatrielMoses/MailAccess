from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

_USERNAME_KEYS = frozenset({"username", "login", "user", "handle", "matched_username"})
_DISPLAY_KEYS = frozenset({"display_name", "name", "full_name", "real_name"})
_PHOTO_KEYS = frozenset({
    "photo_url",
    "thumbnail_url",
    "avatar_url",
    "image",
    "profile_photo",
    "image_url",
})
_BREACH_MODULES = frozenset({
    "hibp",
    "breachdirectory",
    "haveibeenpwned",
    "breach_deep",
    "xposedornot",
})
_MAX_COMPLETE_CLUSTER_SIZE = 25


def _node_id(node_type: str, value: str) -> str:
    digest = hashlib.sha256(f"{node_type}:{value}".encode()).hexdigest()[:12]
    return f"{node_type}_{digest}"


@dataclass
class GraphNode:
    id: str
    type: str
    label: str
    value: str
    metadata: dict[str, Any] = field(default_factory=dict)
    degree: int = 0
    high_confidence_node: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "value": self.value,
            "metadata": self.metadata,
            "degree": self.degree,
            "high_confidence_node": self.high_confidence_node,
        }


@dataclass
class GraphEdge:
    source: str
    target: str
    type: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "metadata": self.metadata,
        }


@dataclass
class IdentityGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    clusters: list[list[str]] = field(default_factory=list)
    shadow_findings: list[dict[str, Any]] = field(default_factory=list)
    _edge_keys: set[tuple[str, str, str]] = field(
        default_factory=set,
        init=False,
        repr=False,
    )

    def _ensure_node(
        self,
        node_type: str,
        value: str,
        label: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        value = value.strip()
        if not value:
            return ""
        nid = _node_id(node_type, value.lower())
        if nid not in self.nodes:
            self.nodes[nid] = GraphNode(
                id=nid,
                type=node_type,
                label=label or value[:40],
                value=value,
                metadata=metadata or {},
            )
        elif metadata:
            self.nodes[nid].metadata.update(metadata)
        return nid

    def _add_edge(self, source: str, target: str, edge_type: str, **meta: Any) -> None:
        if not source or not target or (source == target and edge_type != "same_avatar"):
            return
        key = (source, target, edge_type)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append(GraphEdge(source=source, target=target, type=edge_type, metadata=meta))

    def _add_cluster_edges(
        self,
        node_ids: list[str],
        edge_type: str,
        **meta: Any,
    ) -> None:
        """Connect a cluster without materialising an unbounded clique."""
        unique = list(dict.fromkeys(node_ids))
        if len(unique) <= _MAX_COMPLETE_CLUSTER_SIZE:
            for index, source in enumerate(unique):
                for target in unique[index + 1 :]:
                    self._add_edge(source, target, edge_type, **meta)
            return

        # A star preserves cluster connectivity and evidence coverage with O(n)
        # edges.  Large username-enumeration results can otherwise create
        # hundreds of thousands of pairwise edges.
        anchor = unique[0]
        for target in unique[1:]:
            self._add_edge(anchor, target, edge_type, **meta)

    def _link_shared(
        self,
        attr_type: str,
        value: str,
        platform_nid: str,
        edge_type: str,
    ) -> None:
        attr_nid = self._ensure_node(attr_type, value)
        if not attr_nid or not platform_nid:
            return
        self._add_edge(platform_nid, attr_nid, edge_type)

    @classmethod
    def build(
        cls,
        investigation_result: dict[str, Any],
        name_consensus: dict[str, Any] | None = None,
    ) -> IdentityGraph:
        """
        Build an identity graph from investigation findings.

        investigation_result expects:
          - email: str
          - findings: list of {module_name, data} or flat finding dicts

        ``name_consensus`` is the resolved NameConsensusResult dict
        (``confirmed_name`` / ``name_confidence``).  When supplied, the
        Phase 6B.2 shadow-profile V2 detector runs in addition to V1.
        """
        graph = cls()
        email = investigation_result.get("email", "")
        if email:
            graph._ensure_node("email", email, label=email)

        raw_findings = investigation_result.get("findings", [])
        # `name_consensus` is already a dict by the time it reaches us
        # (engine.py serialises the dataclass via dataclasses.asdict).
        # Backwards compat: accept the dataclass too.
        consensus_dict: dict[str, Any] | None
        if name_consensus is None:
            consensus_dict = None
        elif isinstance(name_consensus, dict):
            consensus_dict = name_consensus
        else:
            consensus_dict = {
                "confirmed_name": getattr(name_consensus, "confirmed_name", None),
                "name_confidence": getattr(name_consensus, "name_confidence", None),
            }
        flat: list[tuple[str, dict[str, Any]]] = []
        for item in raw_findings:
            if isinstance(item, dict) and "data" in item:
                flat.append((item.get("module_name", ""), item["data"]))
            elif isinstance(item, dict):
                flat.append((item.get("module_name", ""), item))

        # attr_value -> list of platform node ids (for shared-attribute edges)
        attr_index: dict[tuple[str, str], list[str]] = {}
        platform_nodes: list[str] = []
        avatar_pairs: list[tuple[str, str]] = []
        bio_pairs: list[tuple[str, str]] = []
        temporal_pairs: list[tuple[str, Any]] = []

        for module_name, finding in flat:
            if not isinstance(finding, dict):
                continue
            platform = str(finding.get("platform") or module_name or "unknown")
            platform_nid = graph._ensure_node(
                "platform",
                platform,
                label=platform,
                metadata={"module": module_name},
            )
            platform_nodes.append(platform_nid)

            if email:
                graph._add_edge(
                    graph._ensure_node("email", email), platform_nid, "same_platform_group"
                )

            payloads = [finding]
            meta = finding.get("metadata")
            if isinstance(meta, dict):
                payloads.append(meta)

            username: str | None = None
            display_name: str | None = None
            photo_url: str | None = None
            domain: str | None = None

            for payload in payloads:
                if not isinstance(payload, dict):
                    continue
                for key in _USERNAME_KEYS:
                    val = payload.get(key)
                    if isinstance(val, str) and val.strip():
                        username = val.strip()
                for key in _DISPLAY_KEYS:
                    val = payload.get(key)
                    if isinstance(val, str) and val.strip():
                        display_name = val.strip()
                for key in _PHOTO_KEYS:
                    val = payload.get(key)
                    if isinstance(val, str) and val.strip().startswith("http"):
                        photo_url = val.strip()
                for key in ("domain", "breach_domain"):
                    val = payload.get(key)
                    if isinstance(val, str) and val.strip():
                        domain = val.strip()

            profile_url = finding.get("profile_url") or finding.get("url")
            if isinstance(profile_url, str) and profile_url.startswith("http"):
                parsed = urlparse(profile_url)
                if parsed.netloc and not domain:
                    domain = parsed.netloc.lstrip("www.")

            if username:
                graph._link_shared("username", username, platform_nid, "shared_username")
                attr_index.setdefault(("username", username.lower()), []).append(platform_nid)
            if display_name:
                graph._link_shared(
                    "display_name", display_name, platform_nid, "shared_display_name"
                )
                attr_index.setdefault(("display_name", display_name.lower()), []).append(
                    platform_nid
                )
            if photo_url:
                graph._link_shared("photo_url", photo_url, platform_nid, "shared_photo")
                attr_index.setdefault(("photo_url", photo_url), []).append(platform_nid)
                avatar_pairs.append((platform, photo_url))
            if domain:
                dom_nid = graph._ensure_node("domain", domain)
                graph._add_edge(platform_nid, dom_nid, "same_platform_group")

            phone = None
            for key in ("phone_number", "phone_hint", "phone"):
                val = (meta or {}).get(key) if isinstance(meta, dict) else None
                if isinstance(val, str) and val:
                    phone = val
            if phone:
                phone_nid = graph._ensure_node("phone", phone, metadata={"masked": True})
                graph._add_edge(platform_nid, phone_nid, "same_platform_group")

            bio_text = None
            for key in ("bio", "description", "about"):
                val = (meta or {}).get(key) if isinstance(meta, dict) else None
                if isinstance(val, str) and val.strip():
                    bio_text = val.strip()
                    break
            if bio_text:
                bio_pairs.append((platform, bio_text))

            temporal_pairs.append((platform, finding))

            if module_name in _BREACH_MODULES or finding.get("severity") in ("critical", "high"):
                if email:
                    graph._add_edge(
                        graph._ensure_node("email", email),
                        platform_nid,
                        "breach_confirmed",
                        module=module_name,
                    )

        # Platform-to-attribute edges above already connect platforms through
        # the shared attribute node.  A second pairwise platform clique is
        # redundant and becomes quadratic for broad username enumerations.

        if avatar_pairs:
            from .enrichment.avatar_clusters import AvatarClusterer

            for avatar_cluster in AvatarClusterer().cluster(avatar_pairs):
                if avatar_cluster["cluster_size"] < 3:
                    continue
                cluster_platforms = avatar_cluster["platforms"]
                cluster_nids = [
                    _node_id("platform", str(platform).lower()) for platform in cluster_platforms
                ]
                graph._add_cluster_edges(
                    cluster_nids,
                    "same_avatar",
                    phash=avatar_cluster["phash"],
                    cluster_size=avatar_cluster["cluster_size"],
                )

        if bio_pairs:
            from .enrichment.bio_clusters import BioClusterer

            for bio_cluster in BioClusterer().cluster(bio_pairs):
                if bio_cluster["cluster_size"] < 3:
                    continue
                cluster_platforms = bio_cluster["platforms"]
                cluster_nids = [
                    _node_id("platform", str(p).lower()) for p in cluster_platforms
                ]
                graph._add_cluster_edges(
                    cluster_nids,
                    "same_bio",
                    similarity_score=bio_cluster["similarity_score"],
                    bio_excerpt=bio_cluster["bio_excerpt"],
                    cluster_size=bio_cluster["cluster_size"],
                )

        if temporal_pairs:
            from .enrichment.temporal_cluster import (
                TemporalClusterer,
                extract_creation_date,
            )

            dated = [(p, extract_creation_date(f)) for p, f in temporal_pairs]
            for tc in TemporalClusterer().cluster(dated):
                cluster_platforms = tc["platforms"]
                cluster_nids = [
                    _node_id("platform", str(p).lower()) for p in cluster_platforms
                ]
                graph._add_cluster_edges(
                    cluster_nids,
                    "same_signup_window",
                    earliest=tc["earliest"].isoformat(),
                    latest=tc["latest"].isoformat(),
                    span_days=tc["span_days"],
                    score=tc["score"],
                    cluster_size=tc["cluster_size"],
                )

        from .enrichment.shadow_profiles import ShadowProfileDetector

        for sp in ShadowProfileDetector().find_shadow_pairs(raw_findings, anchor_email=email):
            graph.shadow_findings.append({"type": "shadow_profile", **sp})

        # Phase 6B.2 — V2 shadow profiles: same confirmed name on a
        # different email AND ≥ 2 shared platforms.  Only runs when the
        # primary investigation produced a non-null confirmed_name.
        if consensus_dict and consensus_dict.get("confirmed_name"):
            for sp in ShadowProfileDetector().find_shadow_v2_pairs(
                raw_findings,
                name_consensus=consensus_dict,
                primary_email=email,
            ):
                graph.shadow_findings.append({"type": "shadow_profile_v2", **sp})

        # Phase 6B.1 — shared infrastructure: pairs of platforms that
        # the domain_cluster module grouped under the same registrar +
        # /24 IP subnet.  Edges are added between every pair of member
        # platforms so the cluster shows up under cluster_confidence.
        infra_clusters: list[dict[str, Any]] = []
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            payload = item.get("data") if "data" in item else item
            if not isinstance(payload, dict):
                continue
            if str(payload.get("platform") or "").lower() != "infra_cluster":
                continue
            meta = payload.get("metadata") or {}
            if not isinstance(meta, dict):
                continue
            platforms = meta.get("platforms")
            if isinstance(platforms, list) and len(platforms) >= 2:
                infra_clusters.append({
                    "platforms": [str(p) for p in platforms],
                    "registrar": meta.get("shared_registrar"),
                    "subnet": meta.get("shared_subnet")
                    or meta.get("shared_ip_subnet"),
                    "cluster_id": meta.get("cluster_id"),
                    "signal": meta.get("signal"),
                })

        for cluster in infra_clusters:
            cluster_platforms = cluster["platforms"]
            cluster_nids = [
                _node_id("platform", str(platform).lower())
                for platform in cluster_platforms
            ]
            graph._add_cluster_edges(
                cluster_nids,
                "shared_infrastructure",
                registrar=cluster["registrar"],
                subnet=cluster["subnet"],
                cluster_id=cluster["cluster_id"],
                cluster_size=len(cluster_platforms),
                weight=0.4,
            )

        graph._score_nodes()
        graph._identify_clusters()
        return graph

    def _score_nodes(self) -> None:
        degree: dict[str, int] = {nid: 0 for nid in self.nodes}
        for edge in self.edges:
            if edge.source in degree:
                degree[edge.source] += 1
            if edge.target in degree:
                degree[edge.target] += 1
        for nid, deg in degree.items():
            self.nodes[nid].degree = deg
            self.nodes[nid].high_confidence_node = deg >= 3

    def _identify_clusters(self) -> None:
        """Union-find platform nodes connected via shared-attribute edges."""
        parent: dict[str, str] = {nid: nid for nid in self.nodes}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        shared_types = frozenset({
            "shared_username",
            "shared_photo",
            "shared_display_name",
            "same_avatar",
            "same_bio",
            "same_signup_window",
            "shared_infrastructure",
        })
        for edge in self.edges:
            if edge.type in shared_types:
                if edge.source in parent and edge.target in parent:
                    union(edge.source, edge.target)

        groups: dict[str, list[str]] = {}
        for nid, node in self.nodes.items():
            if node.type != "platform":
                continue
            root = find(nid)
            groups.setdefault(root, []).append(nid)

        self.clusters = [g for g in groups.values() if len(g) >= 2]

    def to_dict(self) -> dict[str, Any]:
        # ``links`` matches the D3 schema (see /graph endpoint) so the
        # persisted graph_data is consumed uniformly by the API and the
        # CLI's IDENTITY ANALYSIS section.  ``clusters`` and
        # ``shadow_findings`` ride along for the latter.
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "links": [
                {
                    "source": e.source,
                    "target": e.target,
                    "type": e.type,
                    "metadata": e.metadata,
                }
                for e in self.edges
            ],
            "clusters": self.clusters,
            "shadow_findings": self.shadow_findings,
        }

    def to_d3(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type,
                    "label": n.label,
                    "value": n.value,
                    "degree": n.degree,
                    "high_confidence_node": n.high_confidence_node,
                    "metadata": n.metadata,
                }
                for n in self.nodes.values()
            ],
            "links": [
                {
                    "source": e.source,
                    "target": e.target,
                    "type": e.type,
                    "metadata": e.metadata,
                }
                for e in self.edges
            ],
        }

    def to_neo4j_cypher(self) -> str:
        lines: list[str] = ["// MailAccess identity graph export"]
        for node in self.nodes.values():
            safe_label = re.sub(r"[^a-zA-Z0-9_]", "_", node.type)
            props = {
                "id": node.id,
                "label": node.label,
                "value": node.value,
                "degree": node.degree,
                "high_confidence_node": node.high_confidence_node,
            }
            props_str = ", ".join(f"{k}: {repr(v)}" for k, v in props.items())
            lines.append(f"CREATE (:{safe_label} {{{props_str}}})")
        for edge in self.edges:
            lines.append(
                f"MATCH (a {{id: {edge.source!r}}}), (b {{id: {edge.target!r}}}) "
                f"CREATE (a)-[:{edge.type.upper()}]->(b)"
            )
        return "\n".join(lines)

    def cluster_confidence(self) -> list[dict[str, Any]]:
        """Score clusters, boosting same-avatar, same-bio, and temporal evidence.

        same-avatar boost:        ≥ 3 platforms → 1.5×, 2 platforms → 1.2×, dual-source → 1.1×.
        same-bio boost:           ≥ 3 platforms → 1.4×, 2 platforms → 1.15×.
        same-signup-window boost: ≥ 5 platforms → 1.3×, 3–4 platforms → 1.15×.
        Boosts stack multiplicatively. Confidence is capped at 1.0.

        Reasoning is collected in two lists (boosts and base signals) so the
        boost entries are surfaced first under the 3-entry truncation cap.
        """
        results = []
        email_domain = ""
        for node in self.nodes.values():
            if node.type == "email":
                email_domain = node.value.split("@")[-1] if "@" in node.value else ""
                break

        for cluster_nodes in self.clusters:
            score = 0.0
            base_reasoning: list[str] = []
            boost_reasoning: list[str] = []

            platforms = cluster_nodes
            platform_count = len(platforms)

            attr_counts: dict[str, dict[str, set[str]]] = {
                "username": {},
                "display_name": {},
                "photo_url": {},
                "domain": {}
            }
            breach_confirmed = False

            for edge in self.edges:
                if edge.source in platforms:
                    target_node = self.nodes.get(edge.target)
                    if not target_node:
                        continue
                    if edge.type == "shared_username" and target_node.type == "username":
                        attr_counts["username"].setdefault(target_node.value, set()).add(
                            edge.source
                        )
                    elif edge.type == "shared_display_name" and target_node.type == "display_name":
                        attr_counts["display_name"].setdefault(target_node.value, set()).add(
                            edge.source
                        )
                    elif edge.type == "shared_photo" and target_node.type == "photo_url":
                        attr_counts["photo_url"].setdefault(target_node.value, set()).add(
                            edge.source
                        )
                    elif edge.type == "same_platform_group" and target_node.type == "domain":
                        attr_counts["domain"].setdefault(target_node.value, set()).add(edge.source)

                if edge.target in platforms and edge.type == "breach_confirmed":
                    breach_confirmed = True

            max_shared_username = max([len(s) for s in attr_counts["username"].values()] + [0])
            max_shared_display = max([len(s) for s in attr_counts["display_name"].values()] + [0])
            max_shared_photo = max([len(s) for s in attr_counts["photo_url"].values()] + [0])

            if max_shared_username >= 3:
                score += 0.30
                for u, s in attr_counts["username"].items():
                    if len(s) == max_shared_username:
                        base_reasoning.append(
                            f"username {u} shared on {max_shared_username} platforms"
                        )
                        break

            if max_shared_display >= 2:
                score += 0.20
                base_reasoning.append(
                    f"display name matches across {max_shared_display} platforms"
                )

            if max_shared_photo >= 2:
                score += 0.20
                base_reasoning.append(
                    f"photo_url matches across {max_shared_photo} platforms"
                )

            has_domain_match = False
            matched_dom = ""
            for dom, s in attr_counts["domain"].items():
                if dom == email_domain or (email_domain and dom.endswith(email_domain)):
                    has_domain_match = True
                    matched_dom = dom
                    break

            if has_domain_match:
                score += 0.15
                base_reasoning.append(f"email domain {matched_dom} found in profile")

            if breach_confirmed:
                score += 0.10
                base_reasoning.append("breach confirmed account")

            if platform_count > 3:
                score += 0.05 * (platform_count - 3)

            avatar_edges = [
                edge
                for edge in self.edges
                if edge.type == "same_avatar"
                and edge.source in platforms
                and edge.target in platforms
            ]
            avatar_platforms = {
                nid for edge in avatar_edges for nid in (edge.source, edge.target)
            }
            avatar_multiplier = 1.0
            if len(avatar_platforms) >= 3:
                avatar_multiplier = 1.5
            elif len(avatar_platforms) == 2:
                avatar_multiplier = 1.2
            elif any(edge.source == edge.target for edge in avatar_edges):
                avatar_multiplier = 1.1
            if avatar_multiplier > 1.0:
                score *= avatar_multiplier
                boost_reasoning.append(
                    f"same avatar evidence ({avatar_multiplier:.1f}x boost)"
                )

            bio_edges = [
                edge
                for edge in self.edges
                if edge.type == "same_bio"
                and edge.source in platforms
                and edge.target in platforms
            ]
            bio_platform_ids = {
                nid for edge in bio_edges for nid in (edge.source, edge.target)
            }
            bio_multiplier = 1.0
            if len(bio_platform_ids) >= 3:
                # 3+ platforms sharing similar bio text: strong corroborating signal
                bio_multiplier = 1.4
            elif len(bio_platform_ids) == 2:
                # 2 platforms sharing similar bio: moderate signal
                bio_multiplier = 1.15
            if bio_multiplier > 1.0:
                score *= bio_multiplier
                boost_reasoning.append(f"same bio evidence ({bio_multiplier}x boost)")

            temporal_edges = [
                edge
                for edge in self.edges
                if edge.type == "same_signup_window"
                and edge.source in platforms
                and edge.target in platforms
            ]
            temporal_platform_ids = {
                nid for edge in temporal_edges for nid in (edge.source, edge.target)
            }
            temporal_multiplier = 1.0
            if len(temporal_platform_ids) >= 5:
                # 5+ platforms in a coordinated signup window: strong temporal signal
                temporal_multiplier = 1.3
            elif len(temporal_platform_ids) >= 3:
                # 3–4 platforms: moderate temporal corroboration
                temporal_multiplier = 1.15
            if temporal_multiplier > 1.0:
                score *= temporal_multiplier
                boost_reasoning.append(
                    f"coordinated signup window ({temporal_multiplier:.2f}x boost)"
                )

            # Shared-infrastructure boost: Phase 6B.1 — the domain
            # clusterer found ≥ 3 platforms sharing a registrar + /24
            # subnet.  Weaker than the avatar/bio boosts because
            # infrastructure sharing is a corroborating signal, not an
            # identity claim.  3+ platforms → 1.10x, 5+ → 1.15x.
            infra_edges = [
                edge
                for edge in self.edges
                if edge.type == "shared_infrastructure"
                and edge.source in platforms
                and edge.target in platforms
            ]
            infra_platform_ids = {
                nid for edge in infra_edges for nid in (edge.source, edge.target)
            }
            infra_multiplier = 1.0
            if len(infra_platform_ids) >= 5:
                infra_multiplier = 1.15
            elif len(infra_platform_ids) >= 3:
                infra_multiplier = 1.10
            if infra_multiplier > 1.0:
                score *= infra_multiplier
                boost_reasoning.append(
                    f"shared infrastructure ({infra_multiplier:.2f}x boost)"
                )

            score = min(score, 1.0)

            # Boost reasoning is surfaced first so the strongest signals
            # survive the 3-entry truncation, even when many base signals exist.
            reasoning = (boost_reasoning + base_reasoning)[:3]

            label = "likely target"
            if score < 0.40:
                label = "likely name collision"
                if not reasoning:
                    reasoning.append(
                        f"{platform_count} platforms matched username only, "
                        "no corroborating signals"
                    )
            elif score < 0.70:
                label = "possible match"

            results.append({
                "cluster_nids": cluster_nodes,
                "confidence": round(score, 2),
                "label": label,
                "reasoning": reasoning,
                "is_collision": label == "likely name collision"
            })

        return results

    def to_cli(self, raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings_by_platform: dict[str, list[dict[str, Any]]] = {}
        for f in raw_findings:
            if not isinstance(f, dict):
                continue
            item = f.get("data") if "data" in f else f
            if not isinstance(item, dict):
                continue
            platform = str(item.get("platform") or f.get("module_name") or "unknown")
            findings_by_platform.setdefault(platform, []).append(f)
            
        clusters_data = self.cluster_confidence()
        
        output = []
        for cd in clusters_data:
            c_findings = []
            for nid in cd["cluster_nids"]:
                platform_node = self.nodes.get(nid)
                if platform_node:
                    pf_name = platform_node.value
                    if pf_name in findings_by_platform:
                        for finding in findings_by_platform[pf_name]:
                            if finding not in c_findings:
                                c_findings.append(finding)
            
            c_findings.sort(
                key=lambda x: str((x.get("data") or x).get("confidence", "high")),
                reverse=True,
            )
            
            output.append({
                "confidence": cd["confidence"],
                "label": cd["label"],
                "reasoning": cd["reasoning"],
                "findings": c_findings,
                "finding_count": len(c_findings),
                "is_collision": cd["is_collision"]
            })
            
        output.sort(key=lambda x: x["confidence"], reverse=True)
        return output
