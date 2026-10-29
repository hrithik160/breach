import React from 'react';
import { BaseEdge, EdgeLabelRenderer, EdgeProps, getBezierPath } from '@xyflow/react';
import { GEdge } from '../../../shared/types';

export const AttackEdge: React.FC<EdgeProps> = ({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  selected,
}) => {
  const edge = data as unknown as GEdge & { isOnSimPath?: boolean };
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const isFirewalled = edge.status === 'firewalled';
  const isActive = edge.status === 'active_attack';
  const isSimPath = edge.isOnSimPath && !isFirewalled;

  const strokeColor = selected
    ? '#38bdf8'
    : isFirewalled
    ? '#334155'
    : isActive
    ? '#ef4444'
    : isSimPath
    ? '#f97316'
    : '#475569';

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          stroke: strokeColor,
          strokeWidth: selected ? 3.5 : isActive || isSimPath ? 2.5 : 1.5,
          strokeDasharray: isFirewalled ? '4 4' : isActive || isSimPath ? '6 4' : undefined,
          opacity: isFirewalled ? 0.35 : 0.95,
        }}
      />

      {/* Animate active_attack or active simulated path edges */}
      {(isActive || isSimPath) && (
        <g>
          {[0, 0.7, 1.4].map((delay, idx) => (
            <circle
              key={idx}
              r={isActive ? 4 : 3}
              fill={isActive ? '#ef4444' : '#fb923c'}
              className="drop-shadow-[0_0_6px_rgba(239,68,68,0.9)]"
            >
              <animateMotion
                dur="1.8s"
                begin={`${delay}s`}
                repeatCount="indefinite"
                path={edgePath}
              />
            </circle>
          ))}
        </g>
      )}

      <EdgeLabelRenderer>
        <div
          style={{
            position: 'absolute',
            transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
            pointerEvents: 'all',
          }}
          className={`px-1.5 py-0.5 rounded text-[9px] font-mono border transition shadow cursor-pointer ${
            selected
              ? 'bg-sky-950 border-sky-400 text-sky-200 font-bold ring-2 ring-sky-400/50'
              : isFirewalled
              ? 'bg-red-950/90 border-red-700 text-red-300 line-through'
              : isActive
              ? 'bg-red-950/90 border-red-500 text-red-200 font-bold'
              : 'bg-slate-900/90 border-slate-700 text-slate-300 hover:border-slate-500'
          }`}
        >
          {isFirewalled ? '✂ CUT' : `${edge.protocol} · ${edge.exploit_time_sec}s`}
        </div>
      </EdgeLabelRenderer>
    </>
  );
};
