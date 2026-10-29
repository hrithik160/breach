import React from 'react';
import { Handle, Position, NodeProps } from '@xyflow/react';
import {
  Printer,
  Laptop,
  Server,
  KeyRound,
  Database,
  ShieldAlert,
  Crown,
  Crosshair,
  ShieldCheck,
  Ban,
} from 'lucide-react';
import { GNode } from '../../../shared/types';

const iconMap = {
  IoT: Printer,
  Workstation: Laptop,
  Server: Server,
  IAM: KeyRound,
  Database: Database,
  Decoy: Crosshair,
};

export const AttackNode: React.FC<NodeProps> = ({ data, selected }) => {
  const node = data as unknown as GNode & {
    isOnSimPath?: boolean;
    isSimActive?: boolean;
  };
  const Icon = iconMap[node.type] || Server;
  const isPatched = node.vulnerabilities.length === 0 && node.type !== 'IAM' && !node.is_decoy;

  // In What-If playback, any node reached along active simulation path becomes compromised
  const isSimBreached = Boolean(node.isOnSimPath && node.isSimActive);
  const isCompromised = node.status === 'compromised' || isSimBreached;

  const statusStyles = isCompromised
    ? 'bg-red-950/90 border-red-500 text-red-100 shadow-[0_0_24px_rgba(239,68,68,0.65)] animate-pulse'
    : node.status === 'isolated'
    ? 'bg-slate-950/80 border-slate-700 text-slate-400 opacity-70'
    : 'bg-slate-900/95 border-slate-700 text-slate-100';

  const selectionRing = selected
    ? 'ring-2 ring-sky-400 shadow-[0_0_24px_rgba(56,189,248,0.6)]'
    : '';

  const crownRing = node.is_crown_jewel
    ? isCompromised
      ? 'ring-4 ring-red-500 shadow-[0_0_30px_rgba(239,68,68,0.85)] animate-pulse'
      : 'ring-2 ring-amber-400 shadow-[0_0_25px_rgba(251,191,36,0.35)]'
    : node.is_decoy
    ? isSimBreached
      ? 'ring-4 ring-cyan-400 shadow-[0_0_30px_rgba(34,211,238,0.85)] animate-pulse'
      : 'ring-2 ring-cyan-400 shadow-[0_0_20px_rgba(34,211,238,0.35)]'
    : node.isOnSimPath
    ? 'ring-1 ring-red-400/60'
    : '';

  return (
    <div
      className={`relative min-w-[195px] rounded-xl border-2 px-3.5 py-2.5 backdrop-blur-md transition-all ${statusStyles} ${crownRing} ${selectionRing}`}
    >
      {/* Interactive Drag & Connect Handles */}
      <Handle
        type="target"
        position={Position.Left}
        className="!bg-sky-400 !w-3 !h-3 !border-2 !border-slate-950 hover:!scale-150 transition-all cursor-crosshair shadow"
        title="Input Handle (Drag another node's output here to link)"
      />
      <Handle
        type="source"
        position={Position.Right}
        className="!bg-emerald-400 !w-3 !h-3 !border-2 !border-slate-950 hover:!scale-150 transition-all cursor-crosshair shadow"
        title="Output Handle (Drag to another node to create link)"
      />

      {node.is_crown_jewel && (
        <div className="absolute -top-3 -right-2 flex items-center gap-1 rounded-full bg-amber-400 px-2 py-0.5 text-[10px] font-bold text-slate-950 shadow">
          <Crown className="w-3 h-3" /> CROWN JEWEL
        </div>
      )}

      {node.is_decoy && (
        <div className="absolute -top-3 -right-2 flex items-center gap-1 rounded-full bg-cyan-400 px-2 py-0.5 text-[10px] font-bold text-slate-950 shadow">
          🍯 HONEYPOT
        </div>
      )}

      {node.status === 'isolated' && (
        <div className="absolute -top-3 -left-2 flex items-center gap-1 rounded-full bg-amber-600/90 border border-amber-400 px-2 py-0.5 text-[9px] font-bold text-white shadow">
          <Ban className="w-2.5 h-2.5" /> QUARANTINED
        </div>
      )}

      <div className="flex items-center gap-2.5">
        <div
          className={`p-2 rounded-lg ${
            node.is_decoy && isSimBreached
              ? 'bg-cyan-500/30 text-cyan-300 animate-bounce'
              : isCompromised
              ? 'bg-red-500/20 text-red-400'
              : node.is_decoy
              ? 'bg-cyan-500/20 text-cyan-300'
              : 'bg-slate-800 text-sky-400'
          }`}
        >
          <Icon className="w-4 h-4" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-xs font-semibold truncate text-slate-100">{node.label}</div>
          <div className="text-[10px] text-slate-400 font-mono truncate">
            {node.refs?.ip || node.type}
          </div>
        </div>
      </div>

      <div className="mt-2 flex items-center justify-between text-[10px]">
        <span
          className={`px-1.5 py-0.5 rounded font-mono font-semibold ${
            node.cvss_score >= 8
              ? 'bg-red-500/20 text-red-300'
              : node.cvss_score >= 5
              ? 'bg-amber-500/20 text-amber-300'
              : 'bg-emerald-500/20 text-emerald-300'
          }`}
        >
          CVSS {node.cvss_score.toFixed(1)}
        </span>

        {isSimBreached ? (
          node.is_decoy ? (
            <span className="flex items-center gap-1 text-cyan-300 font-bold animate-pulse">
              🍯 Trapped!
            </span>
          ) : node.is_crown_jewel ? (
            <span className="flex items-center gap-1 text-red-400 font-bold animate-pulse">
              ⚠️ Breached!
            </span>
          ) : (
            <span className="flex items-center gap-1 text-red-400 font-medium animate-pulse">
              Infected
            </span>
          )
        ) : isPatched ? (
          <span className="flex items-center gap-1 text-emerald-400 font-medium">
            <ShieldCheck className="w-3 h-3" /> Patched
          </span>
        ) : node.vulnerabilities.length > 0 ? (
          <span className="flex items-center gap-1 text-amber-300">
            <ShieldAlert className="w-3 h-3" /> {node.vulnerabilities.length} CVE
          </span>
        ) : null}
      </div>
    </div>
  );
};
