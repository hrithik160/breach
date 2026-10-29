import React from 'react';
import { ShieldAlert, Clock, Terminal, SkipForward, RotateCcw } from 'lucide-react';
import { useGraphStore } from '../store/graphStore';

export const Hud: React.FC = () => {
  const { sim, mode, playbackStep, setPlaybackStep } = useGraphStore();

  const stepForward = () => {
    if (sim.timeline.length === 0) return;
    if (playbackStep === null) setPlaybackStep(0);
    else if (playbackStep < sim.timeline.length - 1) setPlaybackStep(playbackStep + 1);
    else setPlaybackStep(null);
  };

  const compromisedCount =
    mode === 'whatif' && playbackStep !== null
      ? Math.min(playbackStep + 1, sim.blastRadius.compromised)
      : sim.blastRadius.compromised;

  const currentTick =
    playbackStep !== null && sim.timeline[playbackStep]
      ? sim.timeline[playbackStep]
      : null;

  return (
    <div className="fixed bottom-5 left-5 z-20 w-96 rounded-2xl bg-slate-900/90 border border-slate-700/80 p-4 backdrop-blur-md shadow-2xl">
      {/* Top KPI Row */}
      <div className="grid grid-cols-2 gap-3 mb-3">
        <div className="rounded-xl bg-slate-950/90 border border-slate-800 p-3">
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" /> BLAST RADIUS
          </div>
          <div className="mt-1 text-2xl font-bold font-mono text-slate-100">
            {compromisedCount}
            <span className="text-sm text-slate-500"> / {sim.blastRadius.total}</span>
          </div>
        </div>

        <div className="rounded-xl bg-slate-950/90 border border-slate-800 p-3">
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
            <Clock className="w-3.5 h-3.5 text-amber-400" /> TIME TO CROWN
          </div>
          <div className="mt-1 text-2xl font-bold font-mono">
            {mode === 'whatif' && playbackStep !== null ? (
              sim.trappedByDecoy && playbackStep === sim.timeline.length - 1 ? (
                <span className="text-cyan-400 text-base">TRAPPED 🍯</span>
              ) : sim.reachedCrownJewel && playbackStep === sim.timeline.length - 1 ? (
                <span className="text-red-400 text-base animate-pulse">BREACHED!</span>
              ) : sim.timeToCrownSec !== null ? (
                <span className="text-amber-400 text-lg">+{currentTick?.t ?? 0}s <span className="text-xs text-slate-500 font-normal">/ {sim.timeToCrownSec}s</span></span>
              ) : (
                <span className="text-emerald-400 text-base">BLOCKED 🛡️</span>
              )
            ) : sim.trappedByDecoy ? (
              <span className="text-cyan-400 text-base">TRAPPED 🍯</span>
            ) : sim.timeToCrownSec !== null ? (
              <span className="text-red-400">{sim.timeToCrownSec}s</span>
            ) : (
              <span className="text-emerald-400 text-base">PROTECTED</span>
            )}
          </div>
        </div>
      </div>

      {/* Kill-Chain Log Header + What-If Step Controller */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-300">
          <Terminal className="w-3.5 h-3.5 text-sky-400" /> Kill-Chain Narrative
        </div>
        {mode === 'whatif' && sim.timeline.length > 0 && (
          <div className="flex items-center gap-1">
            <button
              onClick={stepForward}
              className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[11px] text-slate-200"
            >
              <SkipForward className="w-3 h-3" /> Step ({playbackStep === null ? 'All' : playbackStep + 1}/{sim.timeline.length})
            </button>
            {playbackStep !== null && (
              <button
                onClick={() => setPlaybackStep(null)}
                className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400"
              >
                <RotateCcw className="w-3 h-3" />
              </button>
            )}
          </div>
        )}
      </div>

      {/* Narrative Feed */}
      <div className="max-h-44 overflow-y-auto space-y-1.5 pr-1 font-mono text-[11px]">
        {sim.timeline.length === 0 ? (
          <div className="text-slate-500 py-3 text-center">No active attack path detected.</div>
        ) : (
          sim.timeline.map((tick, idx) => {
            const isDimmed = playbackStep !== null && idx > playbackStep;
            return (
              <div
                key={`${tick.nodeId}-${idx}`}
                className={`p-2 rounded-lg border transition ${
                  isDimmed
                    ? 'opacity-30 bg-slate-950 border-slate-900'
                    : 'bg-slate-950/80 border-slate-800 text-slate-200'
                }`}
              >
                <span className="text-sky-400 font-bold mr-2">[+{tick.t}s]</span>
                <span>{tick.log}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};