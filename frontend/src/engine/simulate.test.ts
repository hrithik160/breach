import { describe, it, expect } from 'vitest';
import { simulate } from './simulate';
import { Graph } from '../../../shared/types';
import sampleTopology from '../../../shared/topology.sample.json';

describe('simulate() engine contract', () => {
  it('1. Finds shortest path to Crown Jewel on sample topology', () => {
    const graph: Graph = JSON.parse(JSON.stringify(sampleTopology));
    const res = simulate(graph, { entry: ['node-printer'] });
    expect(res.reachedCrownJewel).toBe(true);
    expect(res.path[0]).toBe('node-printer');
    expect(res.path[res.path.length - 1]).toBe('node-prod-crown-jewel');
    expect(res.timeToCrownSec).toBeGreaterThan(0);
  });

  it('2. Blocks exploit path when target node is patched, except via IAM_Trust', () => {
    const graph: Graph = JSON.parse(JSON.stringify(sampleTopology));
    const db = graph.nodes.find((n) => n.id === 'node-prod-crown-jewel')!;
    db.vulnerabilities = [];
    // Firewall the IAM_Trust edge to ensure exploit routes are blocked by patching
    const iamEdge = graph.edges.find((e) => e.id === 'e-iam-admin-crown')!;
    iamEdge.status = 'firewalled';
    const res = simulate(graph, { entry: ['node-printer'] });
    expect(res.reachedCrownJewel).toBe(false);
    expect(res.timeToCrownSec).toBeNull();
  });

  it('3. Traps attacker when a low-weight Decoy honeypot is deployed', () => {
    const graph: Graph = JSON.parse(JSON.stringify(sampleTopology));
    graph.nodes.push({
      id: 'node-decoy-01',
      label: 'Decoy Honeypot',
      type: 'Decoy',
      cvss_score: 10,
      vulnerabilities: ['CVE-HONEY'],
      is_crown_jewel: false,
      is_decoy: true,
      status: 'secure',
    });
    graph.edges.push({
      id: 'edge-trap',
      source: 'node-printer',
      target: 'node-decoy-01',
      protocol: 'SSH',
      exploit_time_sec: 1,
      status: 'open',
    });

    const res = simulate(graph, { entry: ['node-printer'] });
    expect(res.trappedByDecoy).toBe(true);
    expect(res.reachedCrownJewel).toBe(false);
    expect(res.path).toEqual(['node-printer', 'node-decoy-01']);
  });
});
