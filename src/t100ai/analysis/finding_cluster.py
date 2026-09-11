"""Finding Clustering - Groups related findings to identify root causes."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass
class Finding:
    """A security finding for clustering."""
    id: str
    title: str
    severity: str
    category: str
    target: str
    description: str = ""
    cvss: float = 0.0
    mitre_id: str = ""
    cluster_id: int = -1


class FindingCluster:
    """Clusters related findings using similarity analysis.

    Groups findings by target, category, and content similarity to
    identify root causes and reduce noise.

    Usage:
        cluster = FindingCluster()
        cluster.add_finding(Finding(...))
        clusters = cluster.cluster(epsilon=0.5)
    """

    def __init__(self) -> None:
        self._findings: list[Finding] = []

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the clusterer."""
        self._findings.append(finding)

    def add_findings(self, findings: list[Finding]) -> None:
        """Add multiple findings."""
        self._findings.extend(findings)

    def cluster(self, epsilon: float = 0.5) -> list[dict[str, Any]]:
        """Cluster findings using a simple DBSCAN-like approach.

        Groups findings by: target (exact match), category (exact match),
        and title similarity (Levenshtein-based).

        Args:
            epsilon: Similarity threshold (0.0-1.0)

        Returns:
            List of clusters with findings and root cause analysis.
        """
        if not self._findings:
            return []

        visited: set[int] = set()
        clusters: list[list[Finding]] = []
        noise: list[Finding] = []

        for i, finding in enumerate(self._findings):
            if i in visited:
                continue

            neighbors = self._find_neighbors(i, epsilon)
            if len(neighbors) < 2:
                noise.append(finding)
                visited.add(i)
                continue

            cluster = [finding]
            visited.add(i)
            for j in neighbors:
                if j not in visited:
                    visited.add(j)
                    cluster.append(self._findings[j])
                    cluster.extend(
                        [self._findings[k] for k in self._find_neighbors(j, epsilon) if k not in visited]
                    )
                    visited.update(self._find_neighbors(j, epsilon))

            clusters.append(cluster)

        return [
            {
                "cluster_id": idx,
                "size": len(c),
                "max_severity": max(f.severity for f in c),
                "targets": list({f.target for f in c}),
                "categories": list({f.category for f in c}),
                "root_cause": self._infer_root_cause(c),
                "findings": [f.id for f in c],
            }
            for idx, c in enumerate(clusters)
        ]

    def _find_neighbors(self, idx: int, epsilon: float) -> list[int]:
        """Find similar findings within epsilon distance."""
        neighbors = []
        target_a = self._findings[idx].target
        category_a = self._findings[idx].category

        for j, other in enumerate(self._findings):
            if j == idx:
                continue
            if other.target != target_a:
                continue
            if other.category != category_a:
                continue
            similarity = self._title_similarity(self._findings[idx].title, other.title)
            if similarity >= epsilon:
                neighbors.append(j)

        return neighbors

    def _title_similarity(self, a: str, b: str) -> float:
        """Calculate similarity between two finding titles."""
        if not a or not b:
            return 0.0
        a_lower = a.lower()
        b_lower = b.lower()
        if a_lower == b_lower:
            return 1.0

        words_a = set(a_lower.split())
        words_b = set(b_lower.split())
        if not words_a or not words_b:
            return 0.0
        intersection = words_a & words_b
        union = words_a | words_b
        return len(intersection) / len(union)

    def _infer_root_cause(self, cluster: list[Finding]) -> str:
        """Infer the most likely root cause for a cluster."""
        categories = defaultdict(int)
        for f in cluster:
            categories[f.category] += 1

        most_common = max(categories.items(), key=lambda x: x[1])
        return f"Likely root cause: {most_common[0]} affecting {most_common[1]} finding(s)"

    def get_stats(self) -> dict[str, Any]:
        """Return clustering statistics."""
        return {
            "total_findings": len(self._findings),
            "by_severity": {s: sum(1 for f in self._findings if f.severity == s)
                          for s in ["CRIT", "HIGH", "MED", "LOW", "INFO"]},
            "by_category": {c: sum(1 for f in self._findings if f.category == c)
                          for c in {f.category for f in self._findings}},
            "avg_cvss": round(
                sum(f.cvss for f in self._findings) / max(len(self._findings), 1), 1
            ),
        }
