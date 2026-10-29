import React, { useEffect, useState } from 'react';
import { socketClient } from './store/socket';
import { useGraphStore } from './store/graphStore';
import { TopologyCanvas } from './components/TopologyCanvas';
import { DefenseToolbar } from './components/DefenseToolbar';
import { Hud } from './components/Hud';
import { NodeInspector } from './components/NodeInspector';
import { Scorecard } from './components/Scorecard';
import { AddNodeModal } from './components/AddNodeModal';

export function App() {
  const [scorecardOpen, setScorecardOpen] = useState(false);
  const { mode, setMode } = useGraphStore();

  useEffect(() => {
    socketClient.connect('ws://localhost:8000/ws');

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      if (e.key.toLowerCase() === 'w') {
        setMode(mode === 'live' ? 'whatif' : 'live');
      } else if (e.key.toLowerCase() === 'r') {
        socketClient.sendReplayControl('reset');
      } else if (e.key.toLowerCase() === 's') {
        setScorecardOpen((prev) => !prev);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [mode, setMode]);

  return (
    <div className="relative w-screen h-screen overflow-hidden bg-[#060911]">
      <DefenseToolbar onOpenScorecard={() => setScorecardOpen(true)} />
      <TopologyCanvas />
      <Hud />
      <NodeInspector />
      <Scorecard open={scorecardOpen} onClose={() => setScorecardOpen(false)} />
      <AddNodeModal />
    </div>
  );
}

export default App;