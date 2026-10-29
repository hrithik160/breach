import React, { useMemo, useCallback } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  Node,
  Edge,
  NodeMouseHandler,
  EdgeMouseHandler,
} from '@xyflow/react';
import { useGraphStore } from '../store/graphStore';
import { AttackNode } from './AttackNode';
import { AttackEdge } from './AttackEdge';

const nodeTypes = { attackNode: AttackNode };
const edgeTypes = { attackEdge: AttackEdge };

export const TopologyCanvas: React.FC = () => {
  const {
    mode,
    liveGraph,
    whatIfGraph,
    sim,
    activeTool,
    playbackStep,
    selectedNodeId,
    selectedEdgeId,
    selectNode,
    selectEdge,
    patchNode,
    firewallEdge,
    updateNodePosition,
    addWhatIfEdge,
  } = useGraphStore();

  const graph = mode === 'live' ? liveGraph : (whatIfGraph || liveGraph);

  const activePathNodes = useMemo(() => {
    if (playbackStep !== null) {
      return new Set(sim.timeline.slice(0, playbackStep + 1).map((t) => t.nodeId));
    }
    return mode === 'whatif' ? new Set() : new Set(sim.path);
  }, [sim, playbackStep, mode]);

  const activePathEdges = useMemo(() => {
    if (playbackStep !== null) {
      return new Set(
        sim.timeline
          .slice(0, playbackStep + 1)
          .map((t) => t.viaEdge)
          .filter(Boolean) as string[]
      );
    }
    return mode === 'whatif' ? new Set() : new Set(sim.edgesUsed);
  }, [sim, playbackStep, mode]);

  const rfNodes: Node[] = useMemo(
    () =>
      graph.nodes.map((n, idx) => ({
        id: n.id,
        type: 'attackNode',
        position: n.pos || { x: 120 + (idx % 5) * 210, y: 100 + Math.floor(idx / 5) * 150 },
        selected: n.id === selectedNodeId,
        data: {
          ...n,
          isOnSimPath: activePathNodes.has(n.id),
          isSimActive: playbackStep !== null,
        },
      })),
    [graph.nodes, activePathNodes, playbackStep, selectedNodeId]
  );

  const rfEdges: Edge[] = useMemo(
    () =>
      graph.edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        type: 'attackEdge',
        selected: e.id === selectedEdgeId,
        data: {
          ...e,
          isOnSimPath: activePathEdges.has(e.id),
        },
      })),
    [graph.edges, activePathEdges, selectedEdgeId]
  );

  const onNodeClick: NodeMouseHandler = (_, node) => {
    if (mode === 'whatif' && activeTool === 'patch') {
      patchNode(node.id);
    } else {
      selectNode(node.id);
      selectEdge(null);
    }
  };

  const onEdgeClick: EdgeMouseHandler = (_, edge) => {
    if (mode === 'whatif' && activeTool === 'scissors') {
      firewallEdge(edge.id);
    } else {
      selectEdge(edge.id);
      selectNode(null);
    }
  };

  const onNodeDragStop = useCallback(
    (_: any, node: Node) => {
      updateNodePosition(node.id, node.position);
    },
    [updateNodePosition]
  );

  const onConnect = useCallback(
    (connection: any) => {
      if (connection.source && connection.target) {
        addWhatIfEdge(connection.source, connection.target, 'HTTPS', 2.0);
      }
    },
    [addWhatIfEdge]
  );

  const cursorClass =
    mode === 'whatif' && activeTool === 'scissors'
      ? 'cursor-crosshair'
      : mode === 'whatif' && activeTool === 'patch'
      ? 'cursor-pointer'
      : '';

  return (
    <div className={`w-full h-screen bg-[#060911] ${cursorClass}`}>
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodeClick={onNodeClick}
        onEdgeClick={onEdgeClick}
        onNodeDragStop={onNodeDragStop}
        onConnect={onConnect}
        onPaneClick={() => {
          selectNode(null);
          selectEdge(null);
        }}
        nodesDraggable={true}
        nodesConnectable={true}
        fitView
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#1e293b" gap={24} size={1} />
        <Controls className="!bg-slate-900 !border-slate-700 !fill-slate-300" />
      </ReactFlow>
    </div>
  );
};
