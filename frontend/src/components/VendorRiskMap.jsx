import { useState, useCallback, useRef, useEffect } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { getVendorRiskMap } from '../api/client';

const severityColors = {
  critical: '#E2483C',
  high: '#D65A3C',
  elevated: '#D9B23D',
  low: '#4C8C63',
};

const severityStrokeWidth = {
  critical: 4,
  high: 3,
  elevated: 2,
  low: 1.5,
};

export default function VendorRiskMap() {
  const [selectedNode, setSelectedNode] = useState(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const graphRef = useRef(null);
  const containerRef = useRef(null);
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const data = await getVendorRiskMap();
        
        // Calculate node severity based on connected links
        const nodesWithSeverity = data.nodes.map(node => {
          if (node.type === 'customer') {
            // Customer nodes don't have severity, use riskScore instead
            return { ...node, severity: null, fx: 0, fy: 0 }; // Fix customer at center
          }
          
          // For vendor nodes, find the worst severity from connected links
          const connectedLinks = data.links.filter(link => {
            const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
            const targetId = typeof link.target === 'object' ? link.target.id : link.target;
            return sourceId === node.id || targetId === node.id;
          });
          
          if (connectedLinks.length === 0) {
            return { ...node, severity: 'low' };
          }
          
          // Find worst severity
          const severityOrder = { critical: 4, high: 3, elevated: 2, low: 1 };
          const worstLink = connectedLinks.reduce((worst, link) => {
            const linkSeverity = link.severity || 'low';
            return severityOrder[linkSeverity] > severityOrder[worst.severity] ? link : worst;
          }, { severity: 'low' });
          
          return { ...node, severity: worstLink.severity };
        });
        
        setGraphData({ ...data, nodes: nodesWithSeverity });
        setError(null);
      } catch (err) {
        console.error('Failed to load vendor risk map:', err);
        setError('Failed to load data');
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, []);

  const getNodeColor = useCallback((node) => {
    if (node.type === 'customer') return '#1E2224';
    // Use severity color for vendor nodes
    if (node.severity && severityColors[node.severity]) {
      return severityColors[node.severity];
    }
    return '#2B3032';
  }, []);

  const getLinkColor = useCallback((link) => {
    return severityColors[link.severity] || '#8B93A1';
  }, []);

  const getLinkWidth = useCallback((link) => {
    return severityStrokeWidth[link.severity] || 1;
  }, []);

  const getNodeSize = useCallback((node) => {
    if (node.type === 'customer') return 20;
    return 10 + (node.customerCount || 0) * 2;
  }, []);

  const handleNodeClick = useCallback((node) => {
    setSelectedNode(node);
  }, []);

  const handleClosePanel = useCallback(() => {
    setSelectedNode(null);
  }, []);

  const handleNodeHover = useCallback((node) => {
    setHoveredNode(node);
  }, []);

  // Center graph after initial render and when panel state changes
  useEffect(() => {
    const timer = setTimeout(() => {
      if (graphRef.current) {
        graphRef.current.zoomToFit(400);
      }
    }, 100);
    return () => clearTimeout(timer);
  }, [selectedNode]);

  // Get related findings for selected node
  const getRelatedFindings = useCallback((node) => {
    return graphData.links.filter(link => {
      const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
      const targetId = typeof link.target === 'object' ? link.target.id : link.target;
      return sourceId === node.id || targetId === node.id;
    });
  }, [graphData.links]);

  if (loading) {
    return (
      <div className="relative w-full h-full flex items-center justify-center">
        <span className="text-sm text-mist font-body">Loading...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="relative w-full h-full flex items-center justify-center">
        <span className="text-sm text-ember-bright font-body">{error}</span>
      </div>
    );
  }

  return (
    <div className="relative w-full h-full" ref={containerRef}>
      <div className="absolute top-4 left-4 z-10">
        <h2 className="text-lg font-semibold font-display text-ink">VENDOR RISK MAP</h2>
        <p className="text-sm text-mist font-body">Click a node to view details</p>
      </div>

      <ForceGraph2D
        ref={graphRef}
        graphData={graphData}
        nodeCanvasObject={(node, ctx, globalScale) => {
          const size = getNodeSize(node) / globalScale;
          ctx.beginPath();
          ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
          ctx.fillStyle = getNodeColor(node);
          ctx.fill();
          
          // No stroke for solid-filled circles matching legend style
          // Only add subtle stroke for customer node to distinguish it
          if (node.type === 'customer') {
            ctx.strokeStyle = '#E39307';
            ctx.lineWidth = 1.5 / globalScale;
            ctx.stroke();
          }

          // Draw labels for all nodes
          const fontSize = node.type === 'customer' ? 12 : 10;
          ctx.font = `${fontSize / globalScale}px "IBM Plex Sans", sans-serif`;
          ctx.fillStyle = node.type === 'customer' ? '#E8E9ED' : '#8B93A1';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'top';
          ctx.fillText(node.name, node.x, node.y + size + (fontSize + 4) / globalScale);
        }}
        linkCanvasObject={(link, ctx, globalScale) => {
          const width = getLinkWidth(link) / globalScale;
          ctx.beginPath();
          ctx.moveTo(link.source.x, link.source.y);
          ctx.lineTo(link.target.x, link.target.y);
          ctx.strokeStyle = getLinkColor(link);
          ctx.lineWidth = width;
          ctx.stroke();
        }}
        onNodeClick={handleNodeClick}
        onNodeHover={handleNodeHover}
        onNodeLeave={() => setHoveredNode(null)}
        enableNodeDrag={false}
        enableZoom={true}
        enablePan={true}
        d3AlphaDecay={0.02}
        d3VelocityDecay={0.1}
        cooldownTicks={100}
        nodeRelSize={6}
        linkDirectionalParticles={2}
        linkDirectionalParticleSpeed={0.005}
        d3ForceLink={(link) => ({
          distance: 150,
          strength: 0.5
        })}
        d3ForceCharge={-300}
        d3ForceCenter={{ x: 0, y: 0 }}
      />

      {selectedNode && (
        <div className="absolute top-0 right-0 w-80 h-full bg-panel border-l border-hairline overflow-y-auto z-20">
          {/* Panel header with legend */}
          <div className="p-4 border-b border-hairline">
            <div className="flex justify-between items-start mb-4">
              <h3 className="text-lg font-semibold font-display text-ink">{selectedNode.name}</h3>
              <button
                onClick={handleClosePanel}
                className="text-mist hover:text-ink transition-colors"
                aria-label="Close panel"
              >
                ×
              </button>
            </div>
            
            {/* Legend in panel header */}
            <div className="flex gap-3 flex-wrap">
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-sev-critical" />
                <span className="text-xs text-mist font-body">Critical</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-sev-high" />
                <span className="text-xs text-mist font-body">High</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-sev-elevated" />
                <span className="text-xs text-mist font-body">Elevated</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-sev-low" />
                <span className="text-xs text-mist font-body">Low</span>
              </div>
            </div>
          </div>

          {/* Panel content */}
          <div className="p-4 space-y-4">
            <div>
              <p className="text-xs text-mist font-body mb-1">TYPE</p>
              <p className="text-sm font-mono text-ink capitalize">{selectedNode.type}</p>
            </div>
            
            {selectedNode.type === 'customer' && (
              <div>
                <p className="text-xs text-mist font-body mb-1">RISK SCORE</p>
                <p className="text-sm font-mono text-ink">{selectedNode.riskScore}</p>
              </div>
            )}
            
            {selectedNode.type === 'vendor' && (
              <div>
                <p className="text-xs text-mist font-body mb-1">CUSTOMERS DEPENDING</p>
                <p className="text-sm font-mono text-ink">{selectedNode.customerCount}</p>
              </div>
            )}

            <div>
              <p className="text-xs text-mist font-body mb-2">RELATED FINDINGS</p>
              <div className="space-y-2">
                {getRelatedFindings(selectedNode).length > 0 ? (
                  getRelatedFindings(selectedNode).map((link, idx) => {
                    const vendorNode = graphData.nodes.find(n => 
                      (typeof link.source === 'object' ? link.source.id : link.source) === n.id ||
                      (typeof link.target === 'object' ? link.target.id : link.target) === n.id
                    );
                    const vendorName = vendorNode?.name || 'Unknown';
                    return (
                      <div 
                        key={idx}
                        className="p-2 bg-void border-l-2 rounded"
                        style={{ borderColor: severityColors[link.severity] }}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-xs font-mono font-semibold uppercase" style={{ color: severityColors[link.severity] }}>
                            [{link.severity}]
                          </span>
                          <span className="text-xs font-mono text-ink">{vendorName}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono text-mist">{link.cve}</span>
                          <span className="text-mist">·</span>
                          <span className="text-xs font-mono text-ink">risk {link.riskScore}</span>
                        </div>
                        <span className="text-xs text-mist font-body">{link.timestamp}</span>
                      </div>
                    );
                  })
                ) : (
                  <p className="text-xs text-mist font-body italic">No active findings</p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Legend when panel is closed */}
      {!selectedNode && (
        <div className="absolute top-4 right-4 z-10 flex gap-4">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-sev-critical" />
            <span className="text-xs text-mist font-body">Critical</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-sev-high" />
            <span className="text-xs text-mist font-body">High</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-sev-elevated" />
            <span className="text-xs text-mist font-body">Elevated</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-sev-low" />
            <span className="text-xs text-mist font-body">Low</span>
          </div>
        </div>
      )}
    </div>
  );
}
