# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Topology Auto-Layout Algorithms
==============================================

Pure Python layout algorithms for computing node positions
in network topology visualizations.

Supports:
- Hierarchical (Sugiyama-style) layout for tree-like topologies
- Force-directed (spring-electric) layout for mesh topologies
- Auto-selection based on topology density
"""

import math
import random
from collections import defaultdict, deque
from typing import Any


class TopologyLayoutEngine:
    """Computes 2D positions for topology graph nodes."""

    # ──────────────────────────────────────────────────────────────────────
    # Hierarchical (Sugiyama-style) Layout
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def hierarchical_layout(
        nodes: list[dict[str, Any]],
        links: list[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        """
        Sugiyama-style layered layout.

        Algorithm:
          1. Build adjacency list from links.
          2. Identify root nodes — devices typed as ``gateway`` or ``router``,
             or nodes with no incoming edges when treating the graph as directed
             (source → target).
          3. BFS from roots to assign each node a *layer* (depth).
          4. Position nodes evenly within each layer.
             - Vertical spacing: 200 px between layers.
             - Horizontal spacing: 180 px between siblings in the same layer.
             - Layers are centred around x = 0.

        Parameters
        ----------
        nodes : list[dict]
            Each dict must contain ``"id"`` (str) and optionally
            ``"device_type"`` (str).
        links : list[dict]
            Each dict must contain ``"source"`` and ``"target"`` (str node ids).

        Returns
        -------
        dict[str, dict]
            Mapping of ``node_id`` → ``{"x": float, "y": float}``.
        """
        if not nodes:
            return {}

        node_ids = {n["id"] for n in nodes}
        node_types = {n["id"]: n.get("device_type", "") for n in nodes}

        # 1. Build undirected adjacency + track directed in-degree
        adjacency: dict[str, set[str]] = defaultdict(set)
        in_degree: dict[str, int] = defaultdict(int)
        for link in links:
            src, tgt = str(link["source"]), str(link["target"])
            if src in node_ids and tgt in node_ids:
                adjacency[src].add(tgt)
                adjacency[tgt].add(src)
                in_degree.setdefault(src, 0)
                in_degree[tgt] = in_degree.get(tgt, 0) + 1

        # 2. Find roots: gateways / routers first, then zero in-degree, then any remaining
        ROOT_TYPES = {"gateway", "router", "core_switch", "firewall"}
        roots: list[str] = [nid for nid in node_ids if node_types.get(nid, "") in ROOT_TYPES]
        if not roots:
            roots = [nid for nid in node_ids if in_degree.get(nid, 0) == 0]
        if not roots:
            # Fall back to the first node
            roots = [next(iter(node_ids))]

        # 3. BFS to assign layers
        layers: dict[str, int] = {}
        queue: deque[str] = deque()
        for r in roots:
            if r not in layers:
                layers[r] = 0
                queue.append(r)

        while queue:
            current = queue.popleft()
            for neighbour in adjacency.get(current, set()):
                if neighbour not in layers:
                    layers[neighbour] = layers[current] + 1
                    queue.append(neighbour)

        # Assign any disconnected nodes to layer 0
        for n in nodes:
            if n["id"] not in layers:
                layers[n["id"]] = 0

        # 4. Group nodes by layer
        layer_groups: dict[int, list[str]] = defaultdict(list)
        for nid, layer in layers.items():
            layer_groups[layer].append(nid)

        # Sort within each layer for deterministic output
        for layer in layer_groups:
            layer_groups[layer].sort()

        # 5. Compute positions
        LAYER_SPACING_Y = 200.0
        NODE_SPACING_X = 180.0
        positions: dict[str, dict[str, Any]] = {}

        for layer_idx in sorted(layer_groups.keys()):
            members = layer_groups[layer_idx]
            count = len(members)
            # Centre the layer horizontally
            total_width = (count - 1) * NODE_SPACING_X
            start_x = -total_width / 2.0
            y = layer_idx * LAYER_SPACING_Y

            for i, nid in enumerate(members):
                positions[nid] = {
                    "x": round(start_x + i * NODE_SPACING_X, 2),
                    "y": round(y, 2),
                }

        return positions

    # ──────────────────────────────────────────────────────────────────────
    # Force-Directed (Spring-Electric) Layout
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def force_directed_layout(
        nodes: list[dict[str, Any]],
        links: list[dict[str, Any]],
        iterations: int = 100,
        *,
        width: float = 1200.0,
        height: float = 800.0,
        seed: int | None = 42,
    ) -> dict[str, dict[str, Any]]:
        """
        Spring-electric (Fruchterman-Reingold style) force-directed layout.

        Forces:
          - **Repulsion** (Coulomb): every pair of nodes repels with
            force ``k_repel / distance^2``.
          - **Attraction** (Hooke): linked nodes attract with
            force ``k_attract * distance``.
          - **Damping**: velocity is multiplied by a damping factor
            (starts at 0.9, decays to 0.3) each iteration to aid convergence.
          - **Gravity**: gentle pull toward the centre to prevent drift.

        Parameters
        ----------
        nodes : list[dict]
            Each dict must contain ``"id"`` (str).
        links : list[dict]
            Each dict must contain ``"source"`` and ``"target"`` (str node ids).
        iterations : int
            Number of simulation steps (default 100).
        width, height : float
            Bounding area for initial random placement.
        seed : int | None
            Random seed for reproducibility.

        Returns
        -------
        dict[str, dict]
            Mapping of ``node_id`` → ``{"x": float, "y": float}``.
        """
        if not nodes:
            return {}

        # Cap node count to prevent excessive computation
        if len(nodes) > 500:
            return TopologyLayoutEngine.hierarchical_layout(nodes, links)

        rng = random.Random(seed)
        n = len(nodes)

        # Optimal distance between nodes (Fruchterman-Reingold heuristic)
        area = width * height
        k = math.sqrt(area / max(n, 1))

        # Force constants
        k_repel = k * k  # Coulomb constant numerator
        k_attract = 1.0 / max(k, 1e-6)  # Hooke spring constant

        # Build lookup
        id_to_idx = {node["id"]: i for i, node in enumerate(nodes)}
        node_ids = [node["id"] for node in nodes]

        # Edge list as index pairs
        edge_list: list[tuple[int, int]] = []
        for link in links:
            src_idx = id_to_idx.get(str(link["source"]))
            tgt_idx = id_to_idx.get(str(link["target"]))
            if src_idx is not None and tgt_idx is not None:
                edge_list.append((src_idx, tgt_idx))

        # Initial random positions
        pos_x = [rng.uniform(-width / 2, width / 2) for _ in range(n)]
        pos_y = [rng.uniform(-height / 2, height / 2) for _ in range(n)]

        # Velocity arrays
        vel_x = [0.0] * n
        vel_y = [0.0] * n

        # Simulation constants
        MIN_DIST = 1.0  # Avoid division-by-zero
        GRAVITY = 0.02  # Gentle gravity toward centre
        MAX_DISPLACEMENT = k * 0.5  # Cap per-step displacement

        for step in range(iterations):
            # Temperature / damping decays linearly
            t = 1.0 - step / max(iterations, 1)
            damping = 0.3 + 0.6 * t  # 0.9 → 0.3

            # Reset forces
            fx = [0.0] * n
            fy = [0.0] * n

            # Repulsion (all pairs)
            for i in range(n):
                for j in range(i + 1, n):
                    dx = pos_x[i] - pos_x[j]
                    dy = pos_y[i] - pos_y[j]
                    dist_sq = dx * dx + dy * dy
                    dist = math.sqrt(dist_sq) if dist_sq > 0 else MIN_DIST
                    if dist < MIN_DIST:
                        dist = MIN_DIST
                        dist_sq = dist * dist

                    # Coulomb repulsion: F = k_repel / dist^2
                    force = k_repel / dist_sq
                    force_x = (dx / dist) * force
                    force_y = (dy / dist) * force

                    fx[i] += force_x
                    fy[i] += force_y
                    fx[j] -= force_x
                    fy[j] -= force_y

            # Attraction (linked pairs)
            for src_idx, tgt_idx in edge_list:
                dx = pos_x[src_idx] - pos_x[tgt_idx]
                dy = pos_y[src_idx] - pos_y[tgt_idx]
                dist = math.sqrt(dx * dx + dy * dy)
                if dist < MIN_DIST:
                    dist = MIN_DIST

                # Hooke attraction: F = k_attract * dist
                force = k_attract * dist
                force_x = (dx / dist) * force
                force_y = (dy / dist) * force

                fx[src_idx] -= force_x
                fy[src_idx] -= force_y
                fx[tgt_idx] += force_x
                fy[tgt_idx] += force_y

            # Gravity (pull toward origin)
            for i in range(n):
                fx[i] -= GRAVITY * pos_x[i]
                fy[i] -= GRAVITY * pos_y[i]

            # Apply forces with damping and displacement cap
            for i in range(n):
                vel_x[i] = (vel_x[i] + fx[i]) * damping
                vel_y[i] = (vel_y[i] + fy[i]) * damping

                # Cap displacement
                disp = math.sqrt(vel_x[i] ** 2 + vel_y[i] ** 2)
                max_disp = MAX_DISPLACEMENT * t  # Shrinks over time
                if max_disp < 1.0:
                    max_disp = 1.0
                if disp > max_disp:
                    scale = max_disp / disp
                    vel_x[i] *= scale
                    vel_y[i] *= scale

                pos_x[i] += vel_x[i]
                pos_y[i] += vel_y[i]

        # Build result
        positions: dict[str, dict[str, Any]] = {}
        for i, nid in enumerate(node_ids):
            positions[nid] = {
                "x": round(pos_x[i], 2),
                "y": round(pos_y[i], 2),
            }

        return positions

    # ──────────────────────────────────────────────────────────────────────
    # Auto-Select
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def auto_select(
        nodes: list[dict[str, Any]],
        links: list[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        """
        Pick the best layout algorithm based on topology shape.

        Heuristic:
          - Compute graph density = 2 * |E| / (|V| * (|V| - 1)).
          - If density < 0.3 **and** the graph is tree-like (no cycles or
            very few cross-links) → use hierarchical layout.
          - Otherwise → use force-directed layout.

        A graph is considered tree-like when |E| <= |V| * 1.2 (allowing
        ~20% extra edges beyond a spanning tree).

        Parameters
        ----------
        nodes : list[dict]
            Node list (same format as other methods).
        links : list[dict]
            Link list (same format as other methods).

        Returns
        -------
        dict[str, dict]
            Mapping of ``node_id`` → ``{"x": float, "y": float}``.
        """
        if not nodes:
            return {}

        v = len(nodes)
        e = len(links)

        if v <= 1:
            return TopologyLayoutEngine.hierarchical_layout(nodes, links)

        # Graph density for undirected graph
        max_edges = v * (v - 1) / 2.0
        density = e / max_edges if max_edges > 0 else 0.0

        # Tree-like heuristic: a tree has exactly V-1 edges
        tree_ratio = e / max(v - 1, 1)

        if density < 0.3 and tree_ratio <= 1.2:
            return TopologyLayoutEngine.hierarchical_layout(nodes, links)
        else:
            return TopologyLayoutEngine.force_directed_layout(nodes, links)
