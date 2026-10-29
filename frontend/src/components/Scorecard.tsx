import React from 'react';
import { X, ShieldCheck, ArrowRight } from 'lucide-react';
import { useGraphStore } from '../store/graphStore';

interface Props {
  open: boolean;
  onClose: () => void;
}

export const Scorecard: React.FC<Props> = ({ open, onClose }) => {
  const { getScorecard } = useGraphStore();
  if (!open) return null;

  const { baseline, current } = getScorecard();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-2xl bg-slate-900 border border-slate-700 p-6 shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <h2 className="text-lg font-bold text-slate-100">What-If Remediation Scorecard</h2>
          </div>
          <button onClick={onClose} className="p-1 text-slate-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="mt-5 grid grid-cols-3 items-center gap-4 text-center">
          {/* Baseline */}
          <div className="rounded-xl bg-red-950/30 border border-red-800/50 p-4">
            <div className="text-xs uppercase text-red-300 font-semibold">Before (Baseline)</div>
            <div className="mt-3 text-2xl font-mono font-bold text-red-400">
              {baseline.blastRadius.compromised}/{baseline.blastRadius.total}
            </div>
            <div className="text-[11px] text-slate-400">Blast Radius</div>

            <div className="mt-3 text-lg font-mono font-semibold text-slate-200">
              {baseline.timeToCrownSec !== null ? `${baseline.timeToCrownSec}s` : 'Safe'}
            </div>
            <div className="text-[11px] text-slate-400">Time to Crown Jewel</div>

            <div className="mt-3 text-xl font-mono font-bold text-red-400">
              {baseline.riskScore}/100
            </div>
            <div className="text-[11px] text-slate-400">Risk Score</div>
          </div>

          <div className="flex flex-col items-center justify-center text-slate-500">
            <ArrowRight className="w-8 h-8 text-emerald-400" />
            <span className="text-[11px] font-mono mt-1 text-emerald-400">MITIGATED</span>
          </div>

          {/* After */}
          <div className="rounded-xl bg-emerald-950/30 border border-emerald-700/50 p-4">
            <div className="text-xs uppercase text-emerald-300 font-semibold">After Defenses</div>
            <div className="mt-3 text-2xl font-mono font-bold text-emerald-400">
              {current.blastRadius.compromised}/{current.blastRadius.total}
            </div>
            <div className="text-[11px] text-slate-400">Blast Radius</div>

            <div className="mt-3 text-lg font-mono font-semibold text-slate-200">
              {current.timeToCrownSec !== null ? `${current.timeToCrownSec}s` : 'BLOCKED'}
            </div>
            <div className="text-[11px] text-slate-400">Time to Crown Jewel</div>

            <div className="mt-3 text-xl font-mono font-bold text-emerald-400">
              {current.riskScore}/100
            </div>
            <div className="text-[11px] text-slate-400">Risk Score</div>
          </div>
        </div>
      </div>
    </div>
  );
};