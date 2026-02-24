import { useState, useEffect, useCallback, useRef } from 'react';
import { Modal, Button, Spinner, Alert, Badge, Card } from 'react-bootstrap';
import ForceGraph2D from 'react-force-graph-2d';
import fetchAttackSurfaceAssets from '../utils/fetchAttackSurfaceAssets';

const AttackSurfaceVisualizationModal = ({ show, onHide, scopeTargetId, scopeTargetName }) => {
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [nodeDetails, setNodeDetails] = useState(null);
  const [filterType, setFilterType] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const graphRef = useRef();

  const assetTypeColors = {
    asn: '#ff6b6b',
    network_range: '#4ecdc4',
    ip_address: '#45b7d1',
    live_web_server: '#96ceb4',
    cloud_asset: '#feca57',
    fqdn: '#ff9ff3'
  };

  const assetTypeLabels = {
    asn: 'ASN',
    network_range: 'Network Range',
    ip_address: 'IP Address',
    live_web_server: 'Live Web Server',
    cloud_asset: 'Cloud Asset',
    fqdn: 'Domain'
  };

  const fetchAttackSurfaceData = useCallback(async () => {
    if (!scopeTargetId) return;

    setLoading(true);
    setError(null);

    try {
      const data = await fetchAttackSurfaceAssets({ id: scopeTargetId });
      
      if (data.assets && data.assets.length > 0) {
        const nodes = data.assets.map(asset => ({
          id: asset.id,
          label: asset.asset_identifier,
          type: asset.asset_type,
          asset: asset,
          color: assetTypeColors[asset.asset_type] || '#666',
          size: getNodeSize(asset.asset_type)
        }));

        const links = [];
        const linkSet = new Set();
        const assetMap = new Map(data.assets.map(asset => [asset.id, asset]));

        // Add explicit relationships from database
        data.assets.forEach(asset => {
          if (asset.relationships) {
            asset.relationships.forEach(rel => {
              const linkKey = `${rel.parent_asset_id}-${rel.child_asset_id}-${rel.relationship_type}`;
              if (!linkSet.has(linkKey)) {
                links.push({
                  source: rel.parent_asset_id,
                  target: rel.child_asset_id,
                  type: rel.relationship_type,
                  color: getLinkColor(rel.relationship_type),
                  label: rel.relationship_type
                });
                linkSet.add(linkKey);
              }
            });
          }
        });

        // Add implicit relationships based on asset data
        data.assets.forEach(asset => {
          data.assets.forEach(otherAsset => {
            if (asset.id !== otherAsset.id) {
              // IP to FQDN relationships (resolved IPs)
              if (asset.asset_type === 'ip_address' && otherAsset.asset_type === 'fqdn') {
                if (otherAsset.resolved_ips && otherAsset.resolved_ips.includes(asset.ip_address)) {
                  const linkKey = `${otherAsset.id}-${asset.id}-resolves_to`;
                  if (!linkSet.has(linkKey)) {
                    links.push({
                      source: otherAsset.id,
                      target: asset.id,
                      type: 'resolves_to',
                      color: '#17a2b8',
                      label: 'resolves to'
                    });
                    linkSet.add(linkKey);
                  }
                }
              }
              
              // Live web server to FQDN relationships
              if (asset.asset_type === 'live_web_server' && otherAsset.asset_type === 'fqdn') {
                if (asset.domain === otherAsset.fqdn) {
                  const linkKey = `${otherAsset.id}-${asset.id}-hosts`;
                  if (!linkSet.has(linkKey)) {
                    links.push({
                      source: otherAsset.id,
                      target: asset.id,
                      type: 'hosts',
                      color: '#28a745',
                      label: 'hosts'
                    });
                    linkSet.add(linkKey);
                  }
                }
              }
              
              // Live web server to IP relationships
              if (asset.asset_type === 'live_web_server' && otherAsset.asset_type === 'ip_address') {
                if (asset.ip_address === otherAsset.ip_address) {
                  const linkKey = `${otherAsset.id}-${asset.id}-runs_on`;
                  if (!linkSet.has(linkKey)) {
                    links.push({
                      source: otherAsset.id,
                      target: asset.id,
                      type: 'runs_on',
                      color: '#28a745',
                      label: 'runs on'
                    });
                    linkSet.add(linkKey);
                  }
                }
              }
              
              // Cloud asset to FQDN relationships
              if (asset.asset_type === 'cloud_asset' && otherAsset.asset_type === 'fqdn') {
                if (asset.domain && asset.domain.includes(otherAsset.fqdn)) {
                  const linkKey = `${otherAsset.id}-${asset.id}-cloud_service`;
                  if (!linkSet.has(linkKey)) {
                    links.push({
                      source: otherAsset.id,
                      target: asset.id,
                      type: 'cloud_service',
                      color: '#ffc107',
                      label: 'cloud service'
                    });
                    linkSet.add(linkKey);
                  }
                }
              }
            }
          });
        });

        setGraphData({ nodes, links });
      } else {
        setGraphData({ nodes: [], links: [] });
      }
    } catch (err) {
      console.error('Error fetching attack surface data:', err);
      setError('Failed to load attack surface data. Please try again.');
    } finally {
      setLoading(false);
    }
  }, [scopeTargetId]);

  const getNodeSize = (assetType) => {
    const sizes = {
      asn: 8,
      network_range: 6,
      ip_address: 4,
      live_web_server: 5,
      cloud_asset: 5,
      fqdn: 4
    };
    return sizes[assetType] || 4;
  };

  const getLinkColor = (relationshipType) => {
    const colors = {
      contains: '#ff6b6b',
      hosted_on: '#4ecdc4',
      resolves_to: '#45b7d1',
      belongs_to: '#96ceb4',
      hosts: '#28a745',
      runs_on: '#fd7e14',
      cloud_service: '#ffc107',
      cloud_hosted: '#e83e8c'
    };
    return colors[relationshipType] || '#666';
  };

  const handleNodeClick = useCallback((node) => {
    setSelectedNode(node);
    setNodeDetails(node.asset);
  }, []);

  const handleBackgroundClick = useCallback(() => {
    setSelectedNode(null);
    setNodeDetails(null);
  }, []);

  const filteredGraphData = useCallback(() => {
    let filteredNodes = graphData.nodes;
    let filteredLinks = graphData.links;

    if (filterType !== 'all') {
      filteredNodes = graphData.nodes.filter(node => node.type === filterType);
      const nodeIds = new Set(filteredNodes.map(n => n.id));
      filteredLinks = graphData.links.filter(link => 
        nodeIds.has(link.source.id || link.source) && nodeIds.has(link.target.id || link.target)
      );
    }

    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      filteredNodes = filteredNodes.filter(node => 
        node.label.toLowerCase().includes(searchLower) ||
        node.type.toLowerCase().includes(searchLower)
      );
      const nodeIds = new Set(filteredNodes.map(n => n.id));
      filteredLinks = filteredLinks.filter(link => 
        nodeIds.has(link.source.id || link.source) && nodeIds.has(link.target.id || link.target)
      );
    }

    return { nodes: filteredNodes, links: filteredLinks };
  }, [graphData, filterType, searchTerm]);

  const zoomToFit = useCallback(() => {
    if (graphRef.current) {
      graphRef.current.zoomToFit(400);
    }
  }, []);

  const resetView = useCallback(() => {
    if (graphRef.current) {
      graphRef.current.zoom(1);
      graphRef.current.centerAt(0, 0);
    }
  }, []);

  useEffect(() => {
    if (show && scopeTargetId) {
      fetchAttackSurfaceData();
    }
  }, [show, scopeTargetId, fetchAttackSurfaceData]);

  const currentData = filteredGraphData();

  return (
    <Modal show={show} onHide={onHide} fullscreen>
      <Modal.Header closeButton className="bg-dark text-white">
        <Modal.Title>
          <i className="bi bi-diagram-3 me-2"></i>
          Attack Surface Visualization - {scopeTargetName}
        </Modal.Title>
      </Modal.Header>
      
      <Modal.Body className="bg-dark text-white p-0">
        <div className="d-flex justify-content-center align-items-center p-2 border-bottom border-secondary">
          <i className="bi bi-exclamation-triangle text-warning me-2"></i>
          <small className="text-warning">
            Attack Surface Visualization is experimental and will be improved throughout the open beta
          </small>
          <i className="bi bi-exclamation-triangle text-warning ms-2"></i>
        </div>
        
        {loading ? (
          <div className="d-flex justify-content-center align-items-center" style={{ height: '60vh' }}>
            <div className="text-center">
              <Spinner animation="border" variant="danger" />
              <p className="mt-3">Loading attack surface data...</p>
            </div>
          </div>
        ) : error ? (
          <div className="p-4">
            <Alert variant="danger">
              <Alert.Heading>Error</Alert.Heading>
              <p>{error}</p>
              <Button variant="outline-danger" onClick={fetchAttackSurfaceData}>
                Retry
              </Button>
            </Alert>
          </div>
        ) : (
          <div className="d-flex" style={{ height: 'calc(100vh - 120px)' }}>
            <div className="flex-grow-1 position-relative">
              <div className="position-absolute top-0 start-0 m-3 z-3">
                <Card className="bg-dark border-secondary">
                  <Card.Body className="p-3">
                    <h6 className="text-white mb-2">Controls</h6>
                    <div className="d-flex flex-column gap-2">
                      <Button size="sm" variant="outline-light" onClick={zoomToFit}>
                        <i className="bi bi-zoom-in me-1"></i>Fit View
                      </Button>
                      <Button size="sm" variant="outline-light" onClick={resetView}>
                        <i className="bi bi-arrow-clockwise me-1"></i>Reset
                      </Button>
                    </div>
                    
                    <hr className="my-3" />
                    
                    <h6 className="text-white mb-2">Filter by Type</h6>
                    <select 
                      className="form-select form-select-sm bg-dark text-white border-secondary"
                      value={filterType}
                      onChange={(e) => setFilterType(e.target.value)}
                    >
                      <option value="all">All Types</option>
                      {Object.entries(assetTypeLabels).map(([key, label]) => (
                        <option key={key} value={key}>{label}</option>
                      ))}
                    </select>
                    
                    <hr className="my-3" />
                    
                    <h6 className="text-white mb-2">Search</h6>
                    <input
                      type="text"
                      className="form-control form-control-sm bg-dark text-white border-secondary"
                      placeholder="Search assets..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                    />
                    
                    <hr className="my-3" />
                    
                    <h6 className="text-white mb-2">Legend</h6>
                    <div className="d-flex flex-column gap-1">
                      {Object.entries(assetTypeLabels).map(([key, label]) => (
                        <div key={key} className="d-flex align-items-center gap-2">
                          <div 
                            className="rounded-circle" 
                            style={{ 
                              width: '12px', 
                              height: '12px', 
                              backgroundColor: assetTypeColors[key] 
                            }}
                          ></div>
                          <small className="text-white-50">{label}</small>
                        </div>
                      ))}
                    </div>
                    
                    <hr className="my-3" />
                    
                    <div className="text-center">
                      <small className="text-white-50">
                        {currentData.nodes.length} nodes, {currentData.links.length} connections
                      </small>
                    </div>
                  </Card.Body>
                </Card>
              </div>
              
              <ForceGraph2D
                ref={graphRef}
                graphData={currentData}
                nodeLabel="label"
                nodeColor="color"
                nodeVal="size"
                linkColor="color"
                linkWidth={2}
                linkDirectional={true}
                linkDirectionalArrowLength={6}
                linkDirectionalArrowRelPos={1}
                linkDirectionalParticles={2}
                linkDirectionalParticleSpeed={0.006}
                onNodeClick={handleNodeClick}
                onBackgroundClick={handleBackgroundClick}
                cooldownTicks={200}
                d3AlphaDecay={0.02}
                d3VelocityDecay={0.3}
                linkStrength={0.5}
                nodeStrength={-400}
                chargeStrength={-200}
                nodeCanvasObject={(node, ctx, globalScale) => {
                  const label = node.label;
                  const fontSize = 12/globalScale;
                  ctx.font = `${fontSize}px Sans-Serif`;
                  const textWidth = ctx.measureText(label).width;
                  const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2);

                  ctx.fillStyle = 'rgba(0, 0, 0, 0.8)';
                  ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y - bckgDimensions[1] / 2, ...bckgDimensions);

                  ctx.textAlign = 'center';
                  ctx.textBaseline = 'middle';
                  ctx.fillStyle = node.color;
                  ctx.fillText(label, node.x, node.y);

                  node.__bckgDimensions = bckgDimensions;
                }}
                nodeCanvasObjectMode={() => 'after'}
              />
            </div>
            
            {nodeDetails && (
              <div className="w-25 border-start border-secondary">
                <Card className="h-100 rounded-0 bg-dark border-0">
                  <Card.Header className="bg-secondary text-white">
                    <div className="d-flex justify-content-between align-items-center">
                      <h6 className="mb-0">Asset Details</h6>
                      <Button 
                        size="sm" 
                        variant="outline-light" 
                        onClick={() => setNodeDetails(null)}
                      >
                        <i className="bi bi-x"></i>
                      </Button>
                    </div>
                  </Card.Header>
                  <Card.Body className="overflow-auto">
                    <div className="mb-3">
                      <Badge bg="secondary" className="mb-2">
                        {assetTypeLabels[nodeDetails.asset_type]}
                      </Badge>
                      <h6 className="text-white">{nodeDetails.asset_identifier}</h6>
                    </div>
                    
                    <div className="mb-3">
                      <h6 className="text-white-50 mb-2">Properties</h6>
                      <div className="small">
                        {nodeDetails.asn_number && (
                          <div className="mb-1">
                            <span className="text-white-50">ASN:</span> {nodeDetails.asn_number}
                          </div>
                        )}
                        {nodeDetails.asn_organization && (
                          <div className="mb-1">
                            <span className="text-white-50">Organization:</span> {nodeDetails.asn_organization}
                          </div>
                        )}
                        {nodeDetails.cidr_block && (
                          <div className="mb-1">
                            <span className="text-white-50">CIDR:</span> {nodeDetails.cidr_block}
                          </div>
                        )}
                        {nodeDetails.ip_address && (
                          <div className="mb-1">
                            <span className="text-white-50">IP:</span> {nodeDetails.ip_address}
                          </div>
                        )}
                        {nodeDetails.url && (
                          <div className="mb-1">
                            <span className="text-white-50">URL:</span> 
                            <a href={nodeDetails.url} target="_blank" rel="noopener noreferrer" className="text-danger ms-1">
                              {nodeDetails.url}
                            </a>
                          </div>
                        )}
                        {nodeDetails.domain && (
                          <div className="mb-1">
                            <span className="text-white-50">Domain:</span> {nodeDetails.domain}
                          </div>
                        )}
                        {nodeDetails.cloud_provider && (
                          <div className="mb-1">
                            <span className="text-white-50">Cloud Provider:</span> {nodeDetails.cloud_provider}
                          </div>
                        )}
                        {nodeDetails.port && (
                          <div className="mb-1">
                            <span className="text-white-50">Port:</span> {nodeDetails.port}
                          </div>
                        )}
                        {nodeDetails.protocol && (
                          <div className="mb-1">
                            <span className="text-white-50">Protocol:</span> {nodeDetails.protocol}
                          </div>
                        )}
                        {nodeDetails.status_code && (
                          <div className="mb-1">
                            <span className="text-white-50">Status:</span> {nodeDetails.status_code}
                          </div>
                        )}
                        {nodeDetails.title && (
                          <div className="mb-1">
                            <span className="text-white-50">Title:</span> {nodeDetails.title}
                          </div>
                        )}
                        {nodeDetails.web_server && (
                          <div className="mb-1">
                            <span className="text-white-50">Server:</span> {nodeDetails.web_server}
                          </div>
                        )}
                      </div>
                    </div>
                    
                    {nodeDetails.technologies && nodeDetails.technologies.length > 0 && (
                      <div className="mb-3">
                        <h6 className="text-white-50 mb-2">Technologies</h6>
                        <div className="d-flex flex-wrap gap-1">
                          {nodeDetails.technologies.slice(0, 5).map((tech, index) => (
                            <Badge key={index} bg="outline-secondary" text="white">
                              {tech}
                            </Badge>
                          ))}
                          {nodeDetails.technologies.length > 5 && (
                            <Badge bg="outline-secondary" text="white">
                              +{nodeDetails.technologies.length - 5} more
                            </Badge>
                          )}
                        </div>
                      </div>
                    )}
                    
                    {nodeDetails.relationships && nodeDetails.relationships.length > 0 && (
                      <div className="mb-3">
                        <h6 className="text-white-50 mb-2">Relationships ({nodeDetails.relationships.length})</h6>
                        <div className="small">
                          {nodeDetails.relationships.slice(0, 3).map((rel, index) => (
                            <div key={index} className="mb-1">
                              <Badge bg="outline-info" text="white" className="me-1">
                                {rel.relationship_type}
                              </Badge>
                              <span className="text-white-50">→ {rel.child_asset_id?.substring(0, 8)}...</span>
                            </div>
                          ))}
                          {nodeDetails.relationships.length > 3 && (
                            <div className="text-white-50">
                              +{nodeDetails.relationships.length - 3} more relationships
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </Card.Body>
                </Card>
              </div>
            )}
          </div>
        )}
      </Modal.Body>
      
      <Modal.Footer className="bg-dark text-white">
        <div className="d-flex justify-content-between w-100">
          <div>
            <small className="text-white-50">
              Click nodes to view details • Drag to move • Scroll to zoom
            </small>
          </div>
          <Button variant="outline-light" onClick={onHide}>
            Close
          </Button>
        </div>
      </Modal.Footer>
    </Modal>
  );
};

export default AttackSurfaceVisualizationModal; 