import React from 'react';
import {
  Scissors,
  ShieldPlus,
  Crosshair,
  Play,
  Pause,
  RotateCcw,
  FastForward,
  BarChart3,
  Radio,
  FlaskConical,
  Cpu,
  Flame,
  ExternalLink,
  ShieldCheck,
  PlusCircle,
  Zap,
  Globe,
  Server,
} from 'lucide-react';
import { useGraphStore } from '../store/graphStore';
import { socketClient } from '../store/socket';

interface Props {
  onOpenScorecard: () => void;
}

export const DefenseToolbar: React.FC<Props> = ({ onOpenScorecard }) => {
  const {
    mode,
    setMode,
    activeTool,
    setActiveTool,
    deployDecoy,
    connected,
    scanRealInfrastructure,
    scanWebsiteTopology,
    switchTopologyMode,
    currentTopologyType,
    triggerAttack,
    autoShieldChokePoint,
    sourceMode,
    setSourceMode,
    isScanning,
    isAttacking,
    setActiveInspectorTab,
    isSimRunning,
    simSpeed,
    startWhatIfSim,
    pauseWhatIfSim,
    resetWhatIfSim,
    resetWhatIf,
    setIsAddNodeModalOpen,
  } = useGraphStore();

  return (
    <div className="fixed top-4 left-1/2 -translate-x-1/2 z-30 flex flex-col items-center gap-2 max-w-[95vw]">
      {/* Visible Mode Banner */}
      {mode === 'whatif' && (
        <div className="px-4 py-1 rounded-full bg-amber-500/20 border border-amber-400/50 text-amber-300 text-xs font-semibold tracking-wide flex items-center gap-2 shadow-lg">
          <FlaskConical className="w-3.5 h-3.5" />
          <span>SANDBOX WHAT-IF MODE — Changes isolated from live infrastructure</span>
          {isSimRunning && (
            <span className="flex items-center gap-1 ml-2 px-2 py-0.5 rounded-full bg-red-500/30 border border-red-500/50 text-red-300 text-[10px] animate-pulse">
              <Flame className="w-3 h-3 text-red-400 animate-bounce" />
              SIMULATING HACK ({simSpeed}x)
            </span>
          )}
        </div>
      )}

      <div className="flex items-center gap-2.5 px-4 py-2 rounded-2xl bg-slate-900/90 border border-slate-700/80 backdrop-blur-md shadow-2xl flex-wrap justify-center">
        {/* Connection Status Dot */}
        <div className="flex items-center gap-2 pr-2.5 border-r border-slate-800">
          <span
            className={`w-2.5 h-2.5 rounded-full ${
              connected ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' : 'bg-red-500 animate-ping'
            }`}
          />
          <span className="text-xs font-mono text-slate-300">
            {connected ? 'WS LIVE' : 'OFFLINE'}
          </span>
        </div>

        {/* Live vs What-If Switch */}
        <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800">
          <button
            onClick={() => setMode('live')}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition ${
              mode === 'live'
                ? 'bg-red-600 text-white shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radio className="w-3.5 h-3.5" /> Live Telemetry
          </button>
          <button
            onClick={() => setMode('whatif')}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition ${
              mode === 'whatif'
                ? 'bg-amber-500 text-slate-950 font-semibold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FlaskConical className="w-3.5 h-3.5" /> What-If Sandbox
          </button>
        </div>

        {/* Dynamic Topology Scope Switcher */}
        <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs">
          <button
            onClick={() => scanWebsiteTopology()}
            className={`flex items-center gap-1 px-2.5 py-1 rounded-md transition ${
              currentTopologyType === 'website'
                ? 'bg-sky-600 text-white font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
            title="Scan & Display Dynamic Website Topology"
          >
            <Globe className="w-3.5 h-3.5" /> Website
          </button>
          <button
            onClick={() => switchTopologyMode('host')}
            className={`flex items-center gap-1 px-2.5 py-1 rounded-md transition ${
              currentTopologyType === 'host'
                ? 'bg-emerald-600 text-white font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
            title="Display Real Host PC & Docker Topology"
          >
            <Cpu className="w-3.5 h-3.5" /> PC Host
          </button>
          <button
            onClick={() => switchTopologyMode('cloud')}
            className={`flex items-center gap-1 px-2.5 py-1 rounded-md transition ${
              currentTopologyType === 'cloud'
                ? 'bg-indigo-600 text-white font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
            title="Display Sample Enterprise Cloud Topology"
          >
            <Server className="w-3.5 h-3.5" /> Cloud
          </button>
        </div>

        {/* Live Mode: Replay Stream Controls & Real Infrastructure */}
        {mode === 'live' ? (
          <>
            <div className="flex items-center gap-1.5 pl-2 border-l border-slate-800">
              <button
                onClick={() => socketClient.sendReplayControl('start', 1)}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200"
                title="Start Replay (1x)"
              >
                <Play className="w-3.5 h-3.5 text-emerald-400" /> 1x
              </button>
              <button
                onClick={() => socketClient.sendReplayControl('start', 2)}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200"
                title="Fast Replay (2x)"
              >
                <FastForward className="w-3.5 h-3.5 text-sky-400" /> 2x
              </button>
              <button
                onClick={() => socketClient.sendReplayControl('pause')}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200"
                title="Pause Stream"
              >
                <Pause className="w-3.5 h-3.5 text-amber-400" />
              </button>
              <button
                onClick={() => socketClient.sendReplayControl('reset')}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200"
                title="Reset Topology"
              >
                <RotateCcw className="w-3.5 h-3.5 text-slate-400" />
              </button>
            </div>

            {/* Real PC / Target Site Group */}
            <div className="flex items-center gap-1.5 pl-2 border-l border-slate-800">
              <button
                onClick={() => scanRealInfrastructure()}
                disabled={isScanning}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-emerald-950/70 border border-emerald-600/50 hover:bg-emerald-900 text-emerald-200 text-xs font-medium transition shadow disabled:opacity-50"
                title="Scan Host PC, LAN devices, and local Docker containers"
              >
                <Cpu className={`w-3.5 h-3.5 text-emerald-400 ${isScanning ? 'animate-spin' : ''}`} />
                {isScanning ? 'Scanning...' : 'Scan PC + Docker'}
              </button>

              <button
                onClick={() => triggerAttack('sqli')}
                disabled={isAttacking}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-red-950/60 border border-red-700/50 hover:bg-red-900 text-red-200 text-xs font-medium transition shadow disabled:opacity-50"
                title="Simulate intrusion attack via target site API"
              >
                <Flame className={`w-3.5 h-3.5 text-red-400 ${isAttacking ? 'animate-bounce' : ''}`} />
                {isAttacking ? 'Attacking...' : 'Attack /site'}
              </button>

              <button
                onClick={() => {
                  if (currentTopologyType !== 'website') {
                    scanWebsiteTopology();
                  }
                  setActiveInspectorTab('lab');
                }}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-red-950/70 border border-red-600/60 hover:bg-red-900 text-red-200 text-xs font-semibold transition shadow"
                title="Open Website Exploit Lab (switches graph to website)"
              >
                <Flame className="w-3.5 h-3.5 text-red-400" />
                Exploit Lab
              </button>

              <button
                onClick={() => setSourceMode(sourceMode === 'live' ? 'replay' : 'live')}
                className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-400 hover:text-slate-200"
                title="Toggle Backend Telemetry Source (live / replay)"
              >
                SRC: {sourceMode.toUpperCase()}
              </button>
            </div>
          </>
        ) : (
          /* What-If Mode: Simulation Outbreak Controls & Defense Action Tools */
          <div className="flex items-center gap-2 pl-2 border-l border-slate-800 flex-wrap">
            {/* Sandbox Simulation Run Controls */}
            <div className="flex items-center gap-1.5 pr-2 border-r border-slate-800">
              <button
                onClick={() => startWhatIfSim(1)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition shadow ${
                  isSimRunning && simSpeed === 1
                    ? 'bg-amber-500 text-slate-950 shadow-[0_0_12px_rgba(245,158,11,0.6)]'
                    : 'bg-amber-500/20 border border-amber-500/50 text-amber-200 hover:bg-amber-500/30'
                }`}
                title="Simulate hack outbreak across What-If network (1x speed)"
              >
                <Play className={`w-3.5 h-3.5 ${isSimRunning && simSpeed === 1 ? 'fill-current' : 'text-amber-400'}`} />
                {isSimRunning && simSpeed === 1 ? 'Simulating...' : 'Run Sim'}
              </button>

              <button
                onClick={() => startWhatIfSim(2)}
                className={`flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium transition ${
                  isSimRunning && simSpeed === 2
                    ? 'bg-amber-500 text-slate-950 font-bold'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                }`}
                title="Fast Simulation (2x speed)"
              >
                <FastForward className="w-3.5 h-3.5 text-sky-400" /> 2x
              </button>

              <button
                onClick={pauseWhatIfSim}
                disabled={!isSimRunning}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 transition"
                title="Pause Sandbox Simulation"
              >
                <Pause className="w-3.5 h-3.5 text-amber-400" />
              </button>

              <button
                onClick={resetWhatIfSim}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition"
                title="Reset Simulation Playback to Start"
              >
                <RotateCcw className="w-3.5 h-3.5 text-slate-400" />
              </button>
            </div>

            {/* Defense Action Tools */}
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setIsAddNodeModalOpen(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600/30 border border-emerald-500/50 text-emerald-200 hover:bg-emerald-600/50 transition shadow"
                title="Add a custom cyber security asset (WAF, Bastion, Database, Honeypot, etc.)"
              >
                <PlusCircle className="w-3.5 h-3.5 text-emerald-400" /> Add Node
              </button>

              <button
                onClick={() => setActiveTool(activeTool === 'scissors' ? 'select' : 'scissors')}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition ${
                  activeTool === 'scissors'
                    ? 'bg-red-500/20 border-red-400 text-red-200'
                    : 'bg-slate-800 border-slate-700 text-slate-200 hover:bg-slate-700'
                }`}
                title="Click any edge to sever connection (firewall rule)"
              >
                <Scissors className="w-3.5 h-3.5" /> Cut Edge
              </button>

              <button
                onClick={() => setActiveTool(activeTool === 'patch' ? 'select' : 'patch')}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition ${
                  activeTool === 'patch'
                    ? 'bg-emerald-500/20 border-emerald-400 text-emerald-200'
                    : 'bg-slate-800 border-slate-700 text-slate-200 hover:bg-slate-700'
                }`}
                title="Click any node to remediate vulnerabilities"
              >
                <ShieldPlus className="w-3.5 h-3.5" /> Patch Node
              </button>

              <button
                onClick={() => deployDecoy()}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-cyan-500/20 border border-cyan-500/50 text-cyan-200 hover:bg-cyan-500/30 transition"
                title="Deploy a high-interaction decoy honeypot to trap attackers"
              >
                <Crosshair className="w-3.5 h-3.5" /> Drop Decoy
              </button>

              <button
                onClick={autoShieldChokePoint}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-purple-900/60 border border-purple-500/60 text-purple-200 hover:bg-purple-800 transition shadow"
                title="AI / Dijkstra Optimal Choke-Point Sever"
              >
                <Zap className="w-3.5 h-3.5 text-purple-400" /> Auto-Shield
              </button>

              <button
                onClick={resetWhatIf}
                className="flex items-center gap-1 px-2 py-1.5 rounded-lg text-xs font-medium bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 hover:text-white transition"
                title="Revert all What-If defense changes to baseline"
              >
                <RotateCcw className="w-3.5 h-3.5 text-slate-400" /> Reset
              </button>

              <button
                onClick={onOpenScorecard}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white shadow ml-1"
                title="View Before vs After Security Impact Scorecard"
              >
                <BarChart3 className="w-3.5 h-3.5" /> Scorecard
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
