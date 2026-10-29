// ============================================================================
// Breach Domino Simulator - Shared Contracts (Section 4)
// Owned by Person B (Engine and State)
// ============================================================================

// ----------------------------------------------------------------------------
// Graph Types
// ----------------------------------------------------------------------------

export type NodeType = 'IoT' | 'Workstation' | 'Server' | 'IAM' | 'Database' | 'Decoy';

export interface GNode {
  id: string;
  label: string;
  type: NodeType;
  cvss_score: number; // 0-10
  vulnerabilities: string[]; // CVE ids
  is_crown_jewel: boolean;
  is_decoy?: boolean;
  status: 'secure' | 'compromised' | 'isolated';
  refs?: { ip?: string; hostname?: string; cloud_id?: string }; // used by asset resolver
  pos?: { x: number; y: number };
  lastSource?: string;
}

export interface GEdge {
  id: string;
  source: string;
  target: string;
  protocol: 'SSH' | 'HTTPS' | 'SMB' | 'IAM_Trust' | 'Telnet';
  exploit_time_sec: number;
  status: 'open' | 'active_attack' | 'firewalled';
}

export interface Graph {
  nodes: GNode[];
  edges: GEdge[];
}

// ----------------------------------------------------------------------------
// Event + Wire Format
// ----------------------------------------------------------------------------

export interface GraphEvent {
  type:
    | 'node_added'
    | 'node_removed'
    | 'node_updated'
    | 'edge_added'
    | 'edge_removed'
    | 'edge_updated'
    | 'node_compromised'
    | 'cve_found'
    | 'edge_active_attack';
  id: string; // node or edge id
  payload?: Partial<GNode> | Partial<GEdge>;
  ts: number; // epoch ms
  source: 'cloud' | 'ws' | 'siem' | 'replay';
}

// Backend -> Browser messages
export type SnapshotMessage = {
  kind: 'snapshot';
  graph: Graph;
};

export type EventMessage = {
  kind: 'event';
  event: GraphEvent;
};

export type BackendMessage = SnapshotMessage | EventMessage;

// Browser -> Backend (replay mode only)
export interface ReplayControlMessage {
  kind: 'replay_control';
  action: 'start' | 'pause' | 'reset';
  speed?: number;
}

// ----------------------------------------------------------------------------
// Engine Contract
// ----------------------------------------------------------------------------

export interface Tick {
  t: number; // cumulative t in seconds
  nodeId: string;
  viaEdge: string | null;
  log: string;
}

export interface SimResult {
  reachedCrownJewel: boolean;
  path: string[]; // node ids, entry -> crown jewel
  edgesUsed: string[];
  timeline: Tick[]; // drives animation + kill-chain log
  blastRadius: { compromised: number; total: number };
  timeToCrownSec: number | null;
  trappedByDecoy?: boolean;
}

// ----------------------------------------------------------------------------
// Scorecard Math Types (Task B7)
// ----------------------------------------------------------------------------

export interface ScorecardMetrics {
  compromisedCount: number;
  totalCount: number;
  blastRadiusRatio: number; // compromised / total (0 to 1)
  timeToCrownSec: number | null;
  reachedCrownJewel: boolean;
  riskScore: number; // 0 - 100 simple risk score
}

export interface ScorecardData {
  before: ScorecardMetrics;
  after: ScorecardMetrics;
  blastRadiusReduction: number; // before.compromised - after.compromised
  timeDelaySec: number | null; // after.time - before.time
  riskScoreReduction: number; // before.risk - after.risk
}
