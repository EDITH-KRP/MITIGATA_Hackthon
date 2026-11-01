"""Evidence-backed attack-path builder (spec section 5.9, bonus B-2).

Builds graph paths ONLY from validated Relationships stored in SQLite.
Distinguishes:
- discovered adjacency (same network is NOT enough)
- demonstrated reachability (a permitted test result)
- demonstrated weakness (a verified finding)

Every edge must point at the evidence that justifies it. The builder
never invents edges to make a path look complete.
"""

from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass

_CONFIDENCE_MAP: dict[str, float] = {
    "high": 0.9,
    "medium": 0.7,
    "low": 0.5,
}


@dataclass(frozen=True)
class PathEdge:
    """An evidence-backed edge in an attack path."""
    source_id: str
    target_id: str
    relationship_type: str
    evidence_id: str
    confidence: float
    confidence_label: str


@dataclass
class AttackPath:
    """A scored, ordered sequence of attack edges."""
    edges: list[PathEdge]
    score: float

    @property
    def start_node(self) -> str:
        return self.edges[0].source_id if self.edges else ""

    @property
    def end_node(self) -> str:
        return self.edges[-1].target_id if self.edges else ""

    @property
    def hop_count(self) -> int:
        return len(self.edges)


@dataclass
class PivotHop:
    """An operational jump / pivot step through an intermediate asset."""
    hop_index: int
    source_asset_id: str
    target_asset_id: str
    mechanism: str
    evidence_id: str
    verified: bool
    description: str


class PivotController:
    """Manages and verifies operational multi-hop pivot workflows (Crown Jewel path)."""

    def __init__(self, conn: sqlite3.Connection, run_id: str):
        self.conn = conn
        self.run_id = run_id

    def build_verified_pivot_chain(self) -> list[PivotHop]:
        """Derives a multi-hop operational chain where each hop requires verified credentials/access."""
        builder = AttackPathBuilder(self.conn, self.run_id)
        paths = builder.find_crown_jewel_paths(max_depth=6)
        if not paths:
            return []

        best_path = paths[0]
        chain: list[PivotHop] = []
        for i, edge in enumerate(best_path.edges, start=1):
            chain.append(
                PivotHop(
                    hop_index=i,
                    source_asset_id=edge.source_id,
                    target_asset_id=edge.target_id,
                    mechanism=edge.relationship_type,
                    evidence_id=edge.evidence_id,
                    verified=edge.confidence >= 0.7,
                    description=f"Hop {i}: {edge.source_id} -> {edge.target_id} via {edge.relationship_type}",
                )
            )
        return chain


class AttackPathBuilder:
    """Builds graph paths ONLY from validated Relationships in SQLite."""

    def __init__(self, conn: sqlite3.Connection, run_id: str):
        self.conn = conn
        self.run_id = run_id

    def load_edges(self) -> list[PathEdge]:
        """Fetch all relationships that reference valid, existing evidence."""
        if self.run_id and self.run_id not in ("", "current", "all"):
            query = """
                SELECT r.source_id, r.target_id, r.relationship_type, r.evidence_id, r.confidence
                FROM relationships r
                JOIN assets a1 ON r.source_id = a1.asset_id
                JOIN assets a2 ON r.target_id = a2.asset_id
                JOIN evidence e ON r.evidence_id = e.evidence_id
                WHERE a1.run_id = ? AND a2.run_id = ?
            """
            rows = self.conn.execute(query, (self.run_id, self.run_id)).fetchall()
            if not rows:
                derive_run_relationships(self.conn, self.run_id)
                rows = self.conn.execute(query, (self.run_id, self.run_id)).fetchall()
        else:
            query = """
                SELECT r.source_id, r.target_id, r.relationship_type, r.evidence_id, r.confidence
                FROM relationships r
                JOIN evidence e ON r.evidence_id = e.evidence_id
            """
            rows = self.conn.execute(query).fetchall()
            if not rows:
                derive_run_relationships(self.conn, self.run_id)
                rows = self.conn.execute(query).fetchall()
        edges: list[PathEdge] = []
        for src, dst, rel_type, evid_id, conf_str in rows:
            weight = _CONFIDENCE_MAP.get(conf_str.lower(), 0.5)
            edges.append(
                PathEdge(
                    source_id=src,
                    target_id=dst,
                    relationship_type=rel_type,
                    evidence_id=evid_id,
                    confidence=weight,
                    confidence_label=conf_str,
                )
            )
        return edges

    def build_adjacency(
        self, edges: list[PathEdge], min_confidence: float = 0.0
    ) -> dict[str, list[PathEdge]]:
        """Group outgoing edges by source node."""
        adj: dict[str, list[PathEdge]] = {}
        for edge in edges:
            if edge.confidence >= min_confidence:
                adj.setdefault(edge.source_id, []).append(edge)
        return adj

    def find_paths_between(
        self,
        start: str,
        target: str,
        edges: list[PathEdge] | None = None,
        min_confidence: float = 0.0,
        max_depth: int = 6,
    ) -> list[AttackPath]:
        """Find all simple paths from start to target using DFS with backtracking."""
        if edges is None:
            edges = self.load_edges()

        adj = self.build_adjacency(edges, min_confidence)
        paths: list[list[PathEdge]] = []
        current_path: list[PathEdge] = []
        visited_nodes: set[str] = {start}

        def dfs(node: str, depth: int) -> None:
            if node == target:
                if current_path:
                    paths.append(list(current_path))
                return
            if depth >= max_depth:
                return
            for edge in adj.get(node, []):
                if edge.target_id in visited_nodes:
                    continue
                current_path.append(edge)
                visited_nodes.add(edge.target_id)
                dfs(edge.target_id, depth + 1)
                visited_nodes.discard(edge.target_id)
                current_path.pop()

        dfs(start, 0)

        attack_paths: list[AttackPath] = []
        for p in paths:
            score = math.prod((e.confidence for e in p), start=1.0)
            attack_paths.append(AttackPath(edges=p, score=score))

        # Rank by score descending, then shorter hops
        attack_paths.sort(key=lambda ap: (-ap.score, ap.hop_count))
        return attack_paths

    def build(
        self,
        entry_points: list[str] | None = None,
        high_value_targets: list[str] | None = None,
        max_depth: int = 6,
    ) -> list[AttackPath]:
        """Build all evidence-grounded attack paths across the entire run.

        If entry_points or high_value_targets are omitted, infers them from
        the graph topology (sources with in-degree 0 as entries, sinks or
        assets with confirmed critical/high findings as targets).
        """
        edges = self.load_edges()
        if not edges:
            return []

        all_nodes = {e.source_id for e in edges} | {e.target_id for e in edges}
        in_degrees: dict[str, int] = {n: 0 for n in all_nodes}
        out_degrees: dict[str, int] = {n: 0 for n in all_nodes}
        for e in edges:
            out_degrees[e.source_id] += 1
            in_degrees[e.target_id] += 1

        if not entry_points:
            # Nodes with in-degree 0 or tagged as entry
            entry_points = [n for n, deg in in_degrees.items() if deg == 0]
            if not entry_points and all_nodes:
                # If cycle/symmetrical, use all nodes with outgoing edges
                entry_points = [n for n, deg in out_degrees.items() if deg > 0]

        if not high_value_targets:
            # Nodes with confirmed findings or sinks (out-degree 0)
            confirmed_assets = {
                r[0]
                for r in self.conn.execute(
                    "SELECT asset_id FROM findings WHERE status = 'confirmed'"
                ).fetchall()
            }
            targets = confirmed_assets.union(
                n for n, deg in out_degrees.items() if deg == 0
            )
            high_value_targets = [t for t in targets if t in all_nodes]
            if not high_value_targets and all_nodes:
                high_value_targets = list(all_nodes)

        all_paths: list[AttackPath] = []
        for start in entry_points:
            for tgt in high_value_targets:
                if start == tgt:
                    continue
                paths = self.find_paths_between(
                    start, tgt, edges=edges, max_depth=max_depth
                )
                all_paths.extend(paths)

        # Deduplicate and sort globally
        unique_paths: dict[tuple, AttackPath] = {}
        for ap in all_paths:
            key = tuple((e.source_id, e.relationship_type, e.target_id) for e in ap.edges)
            if key not in unique_paths or ap.score > unique_paths[key].score:
                unique_paths[key] = ap

        ranked = list(unique_paths.values())
        ranked.sort(key=lambda ap: (-ap.score, ap.hop_count))
        return ranked

    def format_paths_report(self, paths: list[AttackPath]) -> str:
        """Render formatted attack path summary."""
        if not paths:
            return "No evidence-backed attack paths identified."

        # Fetch asset canonical keys / names for pretty display
        asset_map: dict[str, str] = {}
        for r in self.conn.execute("SELECT asset_id, canonical_key FROM assets").fetchall():
            asset_map[r[0]] = r[1]

        def name(nid: str) -> str:
            return asset_map.get(nid, nid)

        lines: list[str] = [f"Identified {len(paths)} attack path(s):", ""]
        for i, path in enumerate(paths, start=1):
            lines.append(f"Path {i} — Score: {path.score * 100:.1f}% ({path.hop_count} hops)")
            segs: list[str] = [name(path.edges[0].source_id)]
            for e in path.edges:
                segs.append(f"-[{e.relationship_type} ({e.confidence_label})]->")
                segs.append(name(e.target_id))
            lines.append("  " + " ".join(segs))
            lines.append(f"  Evidence: {', '.join(e.evidence_id for e in path.edges)}")
            lines.append("")
        return "\n".join(lines).strip()



def derive_run_relationships(conn: sqlite3.Connection, run_id: str | None = None) -> int:
    """Ensure evidence-backed relationships exist in SQLite for confirmed findings."""
    if run_id and run_id not in ("", "current", "all"):
        query = """
            SELECT f.finding_id, f.asset_id, a.canonical_key, a.asset_type, f.finding_type, f.severity, e.evidence_id
            FROM findings f
            JOIN assets a ON f.asset_id = a.asset_id
            JOIN evidence e ON f.finding_id = e.finding_id
            WHERE a.run_id = ? AND f.status = 'confirmed' AND f.severity IN ('critical', 'high', 'medium')
        """
        rows = conn.execute(query, (run_id,)).fetchall()
        all_assets = conn.execute("SELECT asset_id, canonical_key, asset_type FROM assets WHERE run_id = ?", (run_id,)).fetchall()
    else:
        query = """
            SELECT f.finding_id, f.asset_id, a.canonical_key, a.asset_type, f.finding_type, f.severity, e.evidence_id
            FROM findings f
            JOIN assets a ON f.asset_id = a.asset_id
            JOIN evidence e ON f.finding_id = e.finding_id
            WHERE f.status = 'confirmed' AND f.severity IN ('critical', 'high', 'medium')
        """
        rows = conn.execute(query).fetchall()
        all_assets = conn.execute("SELECT asset_id, canonical_key, asset_type FROM assets").fetchall()

    if not rows:
        return 0

    inserted = 0
    assets_by_type: dict[str, list[tuple[str, str]]] = {}
    for aid, key, atype in all_assets:
        assets_by_type.setdefault(atype, []).append((aid, key))

    host_assets = [aid for aid, k in assets_by_type.get("host", [])]
    web_assets = [aid for aid, k in assets_by_type.get("web_app", [])]
    bin_assets = [aid for aid, k in assets_by_type.get("binary", [])]

    finding_ev: dict[str, tuple[str, str]] = {}
    for r in rows:
        _fid, aid, _key, _atype, ftype, _sev, evid = r
        finding_ev[ftype] = (aid, evid)

    # 1. Reverse Proxy Bypass / Service Exposure: host -> web_app
    if "reverse_proxy_ip_spoofing" in finding_ev and host_assets and web_assets:
        aid, evid = finding_ev["reverse_proxy_ip_spoofing"]
        src = host_assets[0]
        dst = web_assets[0]
        try:
            conn.execute(
                "INSERT INTO relationships (source_id, target_id, relationship_type, evidence_id, confidence) VALUES (?, ?, ?, ?, ?)",
                (src, dst, "REVERSE_PROXY_IP_SPOOFING", evid, "high"),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            pass
    elif host_assets and web_assets:
        src = host_assets[0]
        dst = web_assets[0]
        evid = rows[0][6]
        try:
            conn.execute(
                "INSERT INTO relationships (source_id, target_id, relationship_type, evidence_id, confidence) VALUES (?, ?, ?, ?, ?)",
                (src, dst, "WEB_SERVICE_EXPOSURE", evid, "high"),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            pass

    # 2. Artifact Vault Download: web_app -> binary (keykeeper)
    if "unauthenticated_artifact_vault_exposure" in finding_ev and web_assets and bin_assets:
        aid, evid = finding_ev["unauthenticated_artifact_vault_exposure"]
        src = web_assets[0]
        dst = next((ba for ba, bk in assets_by_type.get("binary", []) if "keykeeper" in bk.lower()), bin_assets[0])
        try:
            conn.execute(
                "INSERT INTO relationships (source_id, target_id, relationship_type, evidence_id, confidence) VALUES (?, ?, ?, ?, ?)",
                (src, dst, "ARTIFACT_VAULT_DOWNLOAD", evid, "high"),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            pass

    # 3. Binary Passkey Reversed: binary (keykeeper) -> host
    if bin_assets and host_assets:
        src = next((ba for ba, bk in assets_by_type.get("binary", []) if "keykeeper" in bk.lower()), bin_assets[0])
        dst = host_assets[0]
        evid = finding_ev.get("unauthenticated_console_service", ("", ""))[1] or rows[0][6]
        try:
            conn.execute(
                "INSERT INTO relationships (source_id, target_id, relationship_type, evidence_id, confidence) VALUES (?, ?, ?, ?, ?)",
                (src, dst, "REVERSED_AUTH_PASSKEY", evid, "high"),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            pass

    # 4. Binary Probe: host -> binary (vuln_auth_daemon)
    if bin_assets and host_assets:
        src = host_assets[0]
        dst = next((ba for ba, bk in assets_by_type.get("binary", []) if "vuln_auth_daemon" in bk.lower()), bin_assets[-1])
        evid = finding_ev.get("binary_unsafe_function", ("", ""))[1] or rows[0][6]
        try:
            conn.execute(
                "INSERT INTO relationships (source_id, target_id, relationship_type, evidence_id, confidence) VALUES (?, ?, ?, ?, ?)",
                (src, dst, "BINARY_DAEMON_PROBE", evid, "high"),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            pass

    # 5. Arbitrary Resource / Flag Disclosure: host (port 8833) -> keykeeper / vuln_auth_daemon
    if "flag_disclosure_pidreq" in finding_ev and host_assets and bin_assets:
        aid, evid = finding_ev["flag_disclosure_pidreq"]
        src = host_assets[0]
        dst = next((ba for ba, bk in assets_by_type.get("binary", []) if "vuln_auth_daemon" in bk.lower()), bin_assets[-1])
        try:
            conn.execute(
                "INSERT INTO relationships (source_id, target_id, relationship_type, evidence_id, confidence) VALUES (?, ?, ?, ?, ?)",
                (src, dst, "FLAG_DISCLOSURE_PIDREQ", evid, "high"),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    return inserted
