import { Graph, GNode, GEdge, SimResult, Tick } from '../../../shared/types';
import { formatHopLog } from './timeline';

export function simulate(graph: Graph, opts?: { entry?: string[] }): SimResult {
  const nodeMap = new Map<string, GNode>(graph.nodes.map((n) => [n.id, n]));
  const totalNodes = graph.nodes.filter((n) => !n.is_decoy).length;

  // Rule 1: Start set is every node with status 'compromised' (or opts.entry)
  const startIds = opts?.entry?.length
    ? opts.entry.filter((id) => nodeMap.has(id))
    : graph.nodes.filter((n) => n.status === 'compromised').map((n) => n.id);

  // Fallback if no node is compromised yet so What-If preview still works from initial entry point
  const effectiveStartIds =
    startIds.length > 0
      ? startIds
      : graph.nodes.find((n) => n.id === 'node-printer-01')
      ? ['node-printer-01']
      : graph.nodes.slice(0, 1).map((n) => n.id);

  if (effectiveStartIds.length === 0) {
    return {
      reachedCrownJewel: false,
      path: [],
      edgesUsed: [],
      timeline: [],
      blastRadius: { compromised: 0, total: totalNodes },
      timeToCrownSec: null,
    };
  }

  // Build adjacency list
  const adj = new Map<string, GEdge[]>();
  for (const edge of graph.edges) {
    if (!adj.has(edge.source)) adj.set(edge.source, []);
    adj.get(edge.source)!.push(edge);
  }

  const dist = new Map<string, number>();
  const prevNode = new Map<string, string | null>();
  const prevEdge = new Map<string, GEdge | null>();
  const visited = new Set<string>();

  for (const id of effectiveStartIds) {
    const n = nodeMap.get(id);
    if (n && n.status !== 'isolated') {
      dist.set(id, 0);
      prevNode.set(id, null);
      prevEdge.set(id, null);
    }
  }

  // Multi-source Dijkstra
  while (true) {
    let u: string | null = null;
    let bestDist = Infinity;

    for (const [id, d] of dist.entries()) {
      if (!visited.has(id) && d < bestDist) {
        bestDist = d;
        u = id;
      }
    }

    if (u === null) break;
    visited.add(u);

    const uNode = nodeMap.get(u)!;
    // If attacker hits a decoy, they are trapped there and do not pivot out of it
    if (uNode.is_decoy) continue;

    for (const edge of adj.get(u) || []) {
      // Rule 2: Firewalled edges are skipped
      if (edge.status === 'firewalled') continue;

      const target = nodeMap.get(edge.target);
      // Rule 2: Isolated nodes are skipped
      if (!target || target.status === 'isolated') continue;

      // Rule 4: Patched node (no vulnerabilities) cannot be entered via exploit edges (IAM_Trust still works)
      const isPatched = target.vulnerabilities.length === 0 && !target.is_decoy;
      if (isPatched && edge.protocol !== 'IAM_Trust' && target.status !== 'compromised') {
        continue;
      }

      // Rule 2 & 5: Weight = exploit_time_sec * (10 / max(target.cvss_score, 1))
      const weight =
        target.status === 'compromised'
          ? 0.01
          : Number((edge.exploit_time_sec * (10 / Math.max(target.cvss_score, 1))).toFixed(1));

      const alt = bestDist + weight;
      if (alt < (dist.get(target.id) ?? Infinity)) {
        dist.set(target.id, alt);
        prevNode.set(target.id, u);
        prevEdge.set(target.id, edge);
      }
    }
  }

  // Rule 5: Decoys are treated like crown jewels so attacker's shortest path hits them first if closer
  const candidateTargets = graph.nodes.filter(
    (n) => (n.is_crown_jewel || n.is_decoy) && dist.has(n.id)
  );

  let chosenTarget: GNode | null = null;
  let minTargetDist = Infinity;
  for (const t of candidateTargets) {
    const d = dist.get(t.id)!;
    if (d < minTargetDist) {
      minTargetDist = d;
      chosenTarget = t;
    }
  }

  // Fallback: If no crown jewel or decoy is reachable, trace the furthest reached node
  // so What-If defense playback clearly visualizes the attacker hitting a dead end / firewall.
  if (!chosenTarget && visited.size > 0) {
    let maxDist = -1;
    for (const vid of visited) {
      const d = dist.get(vid) ?? 0;
      if (d > maxDist) {
        maxDist = d;
        chosenTarget = nodeMap.get(vid) || null;
      }
    }
  }

  const path: string[] = [];
  const edgesUsed: string[] = [];
  const timeline: Tick[] = [];

  if (chosenTarget) {
    let curr: string | null = chosenTarget.id;
    while (curr !== null) {
      path.unshift(curr);
      const e = prevEdge.get(curr);
      if (e) edgesUsed.unshift(e.id);
      curr = prevNode.get(curr) ?? null;
    }

    for (let i = 0; i < path.length; i++) {
      const nid = path[i];
      const node = nodeMap.get(nid)!;
      const tSec = Math.round(dist.get(nid) || 0);
      if (i === 0) {
        timeline.push({
          t: 0,
          nodeId: nid,
          viaEdge: null,
          log: `Initial foothold established on ${node.label} (${node.refs?.ip || node.id})`,
        });
      } else {
        const edge = prevEdge.get(nid)!;
        const srcNode = nodeMap.get(path[i - 1])!;
        timeline.push({
          t: tSec,
          nodeId: nid,
          viaEdge: edge.id,
          log: formatHopLog(srcNode, node, edge),
        });
      }
    }
  }

  const reachableNonDecoys = Array.from(visited).filter((id) => !nodeMap.get(id)?.is_decoy);
  const reachedCrown = Boolean(chosenTarget && chosenTarget.is_crown_jewel && !chosenTarget.is_decoy);
  const trappedByDecoy = Boolean(chosenTarget && chosenTarget.is_decoy);

  return {
    reachedCrownJewel: reachedCrown,
    trappedByDecoy,
    path,
    edgesUsed,
    timeline,
    blastRadius: {
      compromised: trappedByDecoy
        ? Math.min(path.length - 1, totalNodes)
        : reachableNonDecoys.length,
      total: totalNodes,
    },
    timeToCrownSec: reachedCrown ? Math.round(minTargetDist) : null,
  };
}