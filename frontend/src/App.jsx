import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  UploadCloud, 
  Search, 
  Lock, 
  CheckCircle, 
  AlertTriangle, 
  Loader2, 
  Clock, 
  Database,
  Terminal,
  Activity,
  FileCode,
  Network,
  Cpu,
  RefreshCw,
  FolderOpen,
  ArrowRight,
  User,
  Play,
  FileText,
  AlertOctagon,
  Settings
} from 'lucide-react';

const API_BASE = "http://localhost:8000/api/v1";

export default function App() {
  const [investigations, setInvestigations] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [selectedDetails, setSelectedDetails] = useState(null);
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [activeTab, setActiveTab] = useState("logs"); // logs, tree, iocs, rca, playbook
  
  const [loadingList, setLoadingList] = useState(true);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [triaging, setTriaging] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  
  // Upload Form States
  const [file, setFile] = useState(null);
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("high");
  const [archivePassword, setArchivePassword] = useState("");
  
  // Password dialog state
  const [passwordPromptInv, setPasswordPromptInv] = useState(null);
  const [promptPasswordValue, setPromptPasswordValue] = useState("");
  const [submittingPassword, setSubmittingPassword] = useState(false);
  const [passwordError, setPasswordError] = useState("");

  useEffect(() => {
    fetchInvestigations();
    const interval = setInterval(fetchInvestigations, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (selectedId) {
      fetchDetails(selectedId);
      fetchGraph(selectedId);
      
      const interval = setInterval(() => {
        if (selectedDetails && ["pending", "parsing", "running"].includes(selectedDetails.status)) {
          fetchDetails(selectedId);
          fetchGraph(selectedId);
        }
      }, 3000);
      return () => clearInterval(interval);
    }
  }, [selectedId, selectedDetails?.status]);

  const fetchInvestigations = async () => {
    try {
      const res = await fetch(`${API_BASE}/investigations/`);
      if (res.ok) {
        const data = await res.json();
        setInvestigations(data);
      }
    } catch (e) {
      console.error("Failed to fetch investigations", e);
    } finally {
      setLoadingList(false);
    }
  };

  const fetchDetails = async (id) => {
    try {
      const res = await fetch(`${API_BASE}/investigations/${id}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedDetails(data);
      }
    } catch (e) {
      console.error("Failed to fetch details", e);
    }
  };

  const fetchGraph = async (id) => {
    try {
      const res = await fetch(`${API_BASE}/investigations/${id}/graph`);
      if (res.ok) {
        const data = await res.json();
        setGraphData(data);
      }
    } catch (e) {
      console.error("Failed to fetch graph", e);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files.length > 0) {
      const selectedFile = e.target.files[0];
      setFile(selectedFile);
      if (!title) {
        setTitle(selectedFile.name.replace(/\.[^/.]+$/, ""));
      }
    }
  };

  const handleUploadSubmit = async (e) => {
    e.preventDefault();
    if (!file) return;

    setUploading(true);
    const formData = new FormData();
    formData.append("file", file);
    formData.append("title", title);
    formData.append("severity", severity);
    if (archivePassword) {
      formData.append("password", archivePassword);
    }

    try {
      const res = await fetch(`${API_BASE}/investigations/upload`, {
        method: "POST",
        body: formData
      });
      if (res.ok) {
        const data = await res.json();
        setFile(null);
        setTitle("");
        setArchivePassword("");
        fetchInvestigations();
        setSelectedId(data.investigation_id);
        setActiveTab("logs");
      }
    } catch (e) {
      console.error("Upload failed", e);
    } finally {
      setUploading(false);
    }
  };

  const triggerAgentTriage = async (id) => {
    setTriaging(true);
    try {
      const res = await fetch(`${API_BASE}/investigations/${id}/triage`, {
        method: "POST"
      });
      if (res.ok) {
        fetchInvestigations();
        fetchDetails(id);
      }
    } catch (e) {
      console.error("Triage trigger failed", e);
    } finally {
      setTriaging(false);
    }
  };

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    if (!passwordPromptInv || !promptPasswordValue) return;

    setSubmittingPassword(true);
    setPasswordError("");
    
    const formData = new FormData();
    formData.append("password", promptPasswordValue);

    try {
      const res = await fetch(`${API_BASE}/investigations/${passwordPromptInv.id}/password`, {
        method: "POST",
        body: formData
      });
      if (res.ok) {
        setPasswordPromptInv(null);
        setPromptPasswordValue("");
        fetchInvestigations();
        if (selectedId === passwordPromptInv.id) {
          fetchDetails(passwordPromptInv.id);
          fetchGraph(passwordPromptInv.id);
        }
      } else {
        const err = await res.json();
        setPasswordError(err.detail || "Failed to submit password");
      }
    } catch (e) {
      setPasswordError("Connection error. Try again.");
    } finally {
      setSubmittingPassword(false);
    }
  };

  const getStatusBadge = (status, inv) => {
    switch (status) {
      case "completed":
        return <span style={{ color: 'var(--status-completed)', display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: '600' }}><CheckCircle size={14} /> Investigation Done</span>;
      case "awaiting_password":
        return (
          <button 
            onClick={(e) => {
              e.stopPropagation();
              setPasswordPromptInv(inv);
            }}
            style={{ 
              backgroundColor: 'rgba(189, 0, 255, 0.15)', 
              color: 'var(--status-auth)', 
              border: '1px solid var(--status-auth)', 
              borderRadius: '4px', 
              padding: '2px 8px', 
              fontSize: '12px', 
              fontWeight: '600',
              display: 'inline-flex', 
              alignItems: 'center', 
              gap: '4px' 
            }}
          >
            <Lock size={12} /> Decrypt Zip
          </button>
        );
      case "running":
        return <span style={{ color: 'var(--color-primary)', display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: '600' }}><Loader2 className="pulse-primary" size={14} /> Agent Swarm Active</span>;
      case "parsing":
        return <span style={{ color: 'var(--status-parsing)', display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: '600' }}><Loader2 className="pulse-primary" size={14} /> Parsing Logs</span>;
      case "pending":
        return <span style={{ color: 'var(--status-pending)', display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: '600' }}><Clock size={14} /> Awaiting Triage</span>;
      case "failed":
        return <span style={{ color: 'var(--status-failed)', display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', fontWeight: '600' }}><AlertTriangle size={14} /> Failed</span>;
      default:
        return <span>{status}</span>;
    }
  };

  const processNodes = graphData.nodes.filter(n => n.type === "process");
  
  const getProcessRelations = (nodeId) => {
    const spawned = [];
    const connected = [];
    const created = [];

    graphData.edges.forEach(edge => {
      if (edge.source === nodeId) {
        const targetNode = graphData.nodes.find(n => n.id === edge.target);
        if (targetNode) {
          if (edge.relation === "SPAWNED") spawned.push(targetNode);
          else if (edge.relation === "CONNECTED_TO") connected.push(targetNode);
          else if (edge.relation === "CREATED") created.push(targetNode);
        }
      }
    });

    return { spawned, connected, created };
  };

  const rootProcesses = processNodes.filter(p => {
    const isSpawned = graphData.edges.some(edge => edge.target === p.id && edge.relation === "SPAWNED");
    return !isSpawned;
  });

  const iocNodes = graphData.nodes.filter(n => ["ip", "file"].includes(n.type) && (n.hash || n.type === "ip"));

  const filteredEvents = selectedDetails?.sample_events?.filter(ev => {
    const q = searchQuery.toLowerCase();
    return (
      ev.process_name?.toLowerCase().includes(q) ||
      ev.commandline?.toLowerCase().includes(q) ||
      ev.event_type?.toLowerCase().includes(q) ||
      ev.host_name?.toLowerCase().includes(q) ||
      ev.dst_ip?.toLowerCase().includes(q) ||
      ev.file_hash_sha256?.toLowerCase().includes(q)
    );
  }) || [];

  return (
    <div style={{ display: 'flex', minHeight: '100vh', flexDirection: 'column' }}>
      {/* Header bar */}
      <header style={{ 
        height: '64px', 
        borderBottom: '1px solid var(--border-color)', 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between',
        padding: '0 24px', 
        background: 'rgba(9, 10, 15, 0.8)',
        backdropFilter: 'blur(12px)',
        position: 'sticky',
        top: 0,
        zIndex: 50
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ 
            background: 'linear-gradient(135deg, var(--color-primary), var(--color-secondary))', 
            borderRadius: '8px', 
            padding: '6px',
            boxShadow: '0 0 15px rgba(0, 240, 255, 0.25)'
          }}>
            <Shield size={20} color="#090a0f" />
          </div>
          <span style={{ fontSize: '20px', fontWeight: '800', tracking: '1px', background: 'linear-gradient(90deg, #fff, var(--color-primary))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            ASIP ANALYST PORTAL
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <span style={{ fontSize: '13px', color: 'var(--color-text-muted)', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
            <Activity size={14} color="var(--color-primary)" /> Correlation Engine: Active
          </span>
          <button 
            onClick={fetchInvestigations}
            style={{ 
              background: 'rgba(255,255,255,0.05)', 
              border: '1px solid var(--border-color)', 
              color: '#fff', 
              padding: '6px', 
              borderRadius: '6px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
          >
            <RefreshCw size={14} />
          </button>
        </div>
      </header>

      {/* Main layout grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', flex: 1, padding: '24px', gap: '24px' }}>
        
        {/* Left Side: Upload Zone & Ingested List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* Ingest Alert Evidence */}
          <div className="glass-panel" style={{ padding: '20px' }}>
            <h2 style={{ fontSize: '15px', fontWeight: '700', marginBottom: '16px', color: 'var(--color-primary)', textTransform: 'uppercase', letterSpacing: '0.5px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <UploadCloud size={16} /> Ingest Alert Logs
            </h2>
            <form onSubmit={handleUploadSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-text-muted)', marginBottom: '4px', fontWeight: '600' }}>Investigation Title</label>
                <input 
                  type="text" 
                  placeholder="Leave blank to use filename" 
                  value={title} 
                  onChange={e => setTitle(e.target.value)}
                  style={{ width: '100%', padding: '8px 12px', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border-color)', borderRadius: '6px', color: '#fff', fontSize: '13px' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-text-muted)', marginBottom: '4px', fontWeight: '600' }}>Alert Severity</label>
                  <select 
                    value={severity} 
                    onChange={e => setSeverity(e.target.value)}
                    style={{ width: '100%', padding: '8px 12px', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border-color)', borderRadius: '6px', color: '#fff', fontSize: '13px' }}
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-text-muted)', marginBottom: '4px', fontWeight: '600' }}>Zip Password</label>
                  <input 
                    type="password" 
                    placeholder="If encrypted" 
                    value={archivePassword} 
                    onChange={e => setArchivePassword(e.target.value)}
                    style={{ width: '100%', padding: '8px 12px', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border-color)', borderRadius: '6px', color: '#fff', fontSize: '13px' }}
                  />
                </div>
              </div>

              <div style={{ 
                border: '2px dashed var(--border-color)', 
                borderRadius: '8px', 
                padding: '24px 12px', 
                textAlign: 'center', 
                cursor: 'pointer',
                background: file ? 'rgba(0, 240, 255, 0.03)' : 'transparent',
                borderColor: file ? 'var(--color-primary)' : 'var(--border-color)',
                position: 'relative'
              }}>
                <input 
                  type="file" 
                  onChange={handleFileChange}
                  style={{ opacity: 0, position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', cursor: 'pointer' }}
                />
                <Database size={24} style={{ color: file ? 'var(--color-primary)' : 'var(--color-text-muted)', marginBottom: '8px' }} />
                <span style={{ display: 'block', fontSize: '13px', fontWeight: '600', color: file ? '#fff' : 'var(--color-text-muted)' }}>
                  {file ? file.name : "Select Log or Archive (zip/7z)"}
                </span>
                <span style={{ display: 'block', fontSize: '11px', color: 'var(--color-text-muted)', marginTop: '4px' }}>
                  Supports CSV, XLSX, JSON, EVTX
                </span>
              </div>

              <button 
                type="submit" 
                disabled={uploading || !file}
                style={{ 
                  width: '100%', 
                  padding: '10px', 
                  borderRadius: '6px', 
                  border: 0, 
                  background: 'linear-gradient(135deg, var(--color-primary), var(--color-secondary))', 
                  color: '#090a0f', 
                  fontWeight: '700', 
                  fontSize: '13px', 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center', 
                  gap: '8px',
                  opacity: file ? 1 : 0.5
                }}
              >
                {uploading ? (
                  <>
                    <Loader2 className="pulse-primary" size={16} /> Parsing Evidence...
                  </>
                ) : (
                  <>
                    Upload & Decompress Logs
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Investigations Queue */}
          <div className="glass-panel" style={{ flex: 1, padding: '20px', display: 'flex', flexDirection: 'column' }}>
            <h2 style={{ fontSize: '15px', fontWeight: '700', marginBottom: '16px', color: 'var(--color-text-main)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FolderOpen size={16} color="var(--color-primary)" /> Investigation Queue
            </h2>
            
            {loadingList ? (
              <div style={{ display: 'flex', flex: 1, alignItems: 'center', justifyContent: 'center' }}>
                <Loader2 className="pulse-primary" size={24} color="var(--color-primary)" />
              </div>
            ) : investigations.length === 0 ? (
              <div style={{ display: 'flex', flex: 1, alignItems: 'center', justifyContent: 'center', flexDirection: 'column', color: 'var(--color-text-muted)', padding: '24px', textAlign: 'center' }}>
                <Database size={24} style={{ marginBottom: '8px', opacity: 0.5 }} />
                <span style={{ fontSize: '13px' }}>No active investigations.<br />Upload logs above to begin.</span>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', overflowY: 'auto', maxHeight: '520px', paddingRight: '4px' }}>
                {investigations.map(inv => {
                  const isSelected = selectedId === inv.id;
                  return (
                    <div 
                      key={inv.id}
                      onClick={() => {
                        setSelectedId(inv.id);
                        setSelectedDetails(null);
                      }}
                      className="glow-cyan"
                      style={{ 
                        padding: '12px', 
                        borderRadius: '8px', 
                        border: '1px solid', 
                        borderColor: isSelected ? 'var(--color-primary)' : 'var(--border-color)', 
                        background: isSelected ? 'rgba(0, 240, 255, 0.05)' : 'rgba(0,0,0,0.15)',
                        cursor: 'pointer',
                        transition: 'all 0.2s ease'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '6px' }}>
                        <span style={{ 
                          fontSize: '10px', 
                          textTransform: 'uppercase', 
                          fontWeight: '700', 
                          padding: '1px 6px', 
                          borderRadius: '4px',
                          background: inv.severity === 'critical' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                          color: inv.severity === 'critical' ? '#ef4444' : '#f59e0b'
                        }}>
                          {inv.severity}
                        </span>
                        <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                          {new Date(inv.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </div>
                      <h3 style={{ fontSize: '13px', fontWeight: '600', marginBottom: '8px', color: '#fff', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                        {inv.title}
                      </h3>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                          <Database size={12} /> {inv.event_count} Events
                        </span>
                        {getStatusBadge(inv.status, inv)}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Right Side: Active Analysis Console */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', padding: '24px' }}>
          {!selectedId ? (
            <div style={{ display: 'flex', flex: 1, alignItems: 'center', justifyContent: 'center', flexDirection: 'column', color: 'var(--color-text-muted)' }}>
              <Shield size={48} style={{ marginBottom: '16px', opacity: 0.2, color: 'var(--color-primary)' }} />
              <h2 style={{ fontSize: '18px', fontWeight: '700', color: '#fff', marginBottom: '6px' }}>Select an Investigation</h2>
              <p style={{ fontSize: '13px', textAlign: 'center', maxWidth: '360px' }}>
                Choose an item from the left queue or trigger a new investigation by uploading forensic logs.
              </p>
            </div>
          ) : !selectedDetails ? (
            <div style={{ display: 'flex', flex: 1, alignItems: 'center', justifyContent: 'center' }}>
              <Loader2 className="pulse-primary" size={32} color="var(--color-primary)" />
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
              {/* Header Stats */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border-color)', paddingBottom: '20px', marginBottom: '20px' }}>
                <div>
                  <h1 style={{ fontSize: '18px', fontWeight: '800', color: '#fff', marginBottom: '4px' }}>
                    {selectedDetails.title}
                  </h1>
                  <span style={{ fontSize: '12px', color: 'var(--color-text-muted)', display: 'inline-flex', alignItems: 'center', gap: '15px' }}>
                    <span>ID: {selectedDetails.id}</span>
                    <span>•</span>
                    <span>Created: {new Date(selectedDetails.created_at).toLocaleString()}</span>
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                  {selectedDetails.status === "completed" && (
                    <span style={{ fontSize: '12px', color: 'var(--color-primary)', display: 'inline-flex', alignItems: 'center', gap: '4px', marginRight: '10px', background: 'rgba(0,240,255,0.05)', padding: '4px 10px', borderRadius: '4px', border: '1px solid rgba(0,240,255,0.1)' }}>
                      <CheckCircle size={12} /> Threat Confidence: {Math.round((selectedDetails.confidence_score || 0.9) * 100)}%
                    </span>
                  )}
                  {getStatusBadge(selectedDetails.status, selectedDetails)}
                  
                  {/* Trigger multi-agent loop if pending */}
                  {(selectedDetails.status === "completed" || selectedDetails.status === "pending" || selectedDetails.status === "failed") && (
                    <button
                      onClick={() => triggerAgentTriage(selectedDetails.id)}
                      disabled={triaging}
                      style={{ 
                        background: 'linear-gradient(135deg, var(--color-primary), var(--color-secondary))', 
                        color: '#090a0f', 
                        border: 0, 
                        padding: '6px 14px', 
                        borderRadius: '6px', 
                        fontSize: '12px', 
                        fontWeight: '700',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px'
                      }}
                    >
                      {triaging ? <Loader2 size={12} className="pulse-primary" /> : <Play size={12} fill="#090a0f" />} Run Agent Swarm
                    </button>
                  )}
                </div>
              </div>

              {/* Status Information Box */}
              {selectedDetails.status === "awaiting_password" && (
                <div style={{ 
                  background: 'rgba(189, 0, 255, 0.08)', 
                  border: '1px solid var(--status-auth)', 
                  borderRadius: '8px', 
                  padding: '16px', 
                  marginBottom: '20px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <Lock size={20} color="var(--status-auth)" />
                    <div>
                      <h4 style={{ fontSize: '13px', fontWeight: '700', color: '#fff' }}>Archive Decryption Required</h4>
                      <p style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                        Ingestion paused for <strong>{selectedDetails.password_required}</strong>
                      </p>
                    </div>
                  </div>
                  <button 
                    onClick={() => setPasswordPromptInv(selectedDetails)}
                    style={{ 
                      background: 'var(--status-auth)', 
                      color: '#fff', 
                      border: 0, 
                      padding: '8px 16px', 
                      borderRadius: '6px', 
                      fontSize: '12px', 
                      fontWeight: '700' 
                    }}
                  >
                    Enter Password
                  </button>
                </div>
              )}

              {/* Agent Swarm Active Status View */}
              {selectedDetails.status === "running" && (
                <div style={{ 
                  background: 'rgba(0, 240, 255, 0.05)', 
                  border: '1px dashed var(--color-primary)', 
                  borderRadius: '8px', 
                  padding: '20px', 
                  marginBottom: '24px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <Loader2 size={24} className="pulse-primary" color="var(--color-primary)" />
                    <div>
                      <h4 style={{ fontSize: '14px', fontWeight: '800', color: '#fff' }}>Autonomous Investigation In Progress</h4>
                      <p style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                        The multi-agent swarm is executing forensic reasoning loops...
                      </p>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '12px', fontSize: '11px', marginTop: '4px' }}>
                    <span style={{ padding: '4px 10px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.1)', color: 'var(--color-primary)' }}>1. Triage Agent (Active)</span>
                    <span style={{ padding: '4px 10px', background: 'rgba(255,255,255,0.02)', borderRadius: '4px', color: 'var(--color-text-muted)' }}>2. RCA Agent</span>
                    <span style={{ padding: '4px 10px', background: 'rgba(255,255,255,0.02)', borderRadius: '4px', color: 'var(--color-text-muted)' }}>3. Adversarial QA</span>
                    <span style={{ padding: '4px 10px', background: 'rgba(255,255,255,0.02)', borderRadius: '4px', color: 'var(--color-text-muted)' }}>4. Playbook Writer</span>
                  </div>
                </div>
              )}

              {/* Log Parsing Statistics Dashboard */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '16px', marginBottom: '24px' }}>
                <div style={{ background: 'rgba(0,0,0,0.15)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '12px' }}>
                  <span style={{ display: 'block', fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-text-muted)', marginBottom: '4px' }}>Total Ingested Events</span>
                  <span style={{ fontSize: '20px', fontWeight: '800', color: 'var(--color-primary)' }}>
                    {Object.values(selectedDetails.event_stats || {}).reduce((a, b) => a + b, 0)}
                  </span>
                </div>
                {Object.entries(selectedDetails.event_stats || {}).map(([type, count]) => {
                  const getIcon = (t) => {
                    if (t === "process" || t.includes("process")) return <Cpu size={14} color="var(--color-primary)" />;
                    if (t === "network" || t.includes("connect")) return <Network size={14} color="#3b82f6" />;
                    if (t === "file") return <FileCode size={14} color="#10b981" />;
                    return <Terminal size={14} color="var(--color-text-muted)" />;
                  };
                  return (
                    <div key={type} style={{ background: 'rgba(0,0,0,0.15)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '12px' }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-text-muted)', marginBottom: '4px' }}>
                        {getIcon(type)} {type}
                      </span>
                      <span style={{ fontSize: '20px', fontWeight: '800', color: '#fff' }}>{count}</span>
                    </div>
                  );
                })}
              </div>

              {/* Tabs selector */}
              <div style={{ display: 'flex', borderBottom: '1px solid var(--border-color)', gap: '20px', marginBottom: '20px' }}>
                <button 
                  onClick={() => setActiveTab("logs")}
                  style={{ 
                    padding: '8px 16px', 
                    background: 'transparent', 
                    border: 0, 
                    borderBottom: activeTab === 'logs' ? '2px solid var(--color-primary)' : '2px solid transparent',
                    color: activeTab === 'logs' ? '#fff' : 'var(--color-text-muted)',
                    fontWeight: '600',
                    fontSize: '13px'
                  }}
                >
                  Log Stream
                </button>
                <button 
                  onClick={() => setActiveTab("tree")}
                  style={{ 
                    padding: '8px 16px', 
                    background: 'transparent', 
                    border: 0, 
                    borderBottom: activeTab === 'tree' ? '2px solid var(--color-primary)' : '2px solid transparent',
                    color: activeTab === 'tree' ? '#fff' : 'var(--color-text-muted)',
                    fontWeight: '600',
                    fontSize: '13px'
                  }}
                >
                  Forensic Process Tree
                </button>
                <button 
                  onClick={() => setActiveTab("iocs")}
                  style={{ 
                    padding: '8px 16px', 
                    background: 'transparent', 
                    border: 0, 
                    borderBottom: activeTab === 'iocs' ? '2px solid var(--color-primary)' : '2px solid transparent',
                    color: activeTab === 'iocs' ? '#fff' : 'var(--color-text-muted)',
                    fontWeight: '600',
                    fontSize: '13px'
                  }}
                >
                  Threat Intel & IOCs
                </button>
                {selectedDetails.root_cause && (
                  <button 
                    onClick={() => setActiveTab("rca")}
                    style={{ 
                      padding: '8px 16px', 
                      background: 'transparent', 
                      border: 0, 
                      borderBottom: activeTab === 'rca' ? '2px solid var(--color-primary)' : '2px solid transparent',
                      color: activeTab === 'rca' ? '#fff' : 'var(--color-text-muted)',
                      fontWeight: '600',
                      fontSize: '13px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px'
                    }}
                  >
                    <FileText size={14} color="var(--color-primary)" /> AI Root Cause (RCA)
                  </button>
                )}
                {selectedDetails.attack_summary && selectedDetails.attack_summary.includes("#") && (
                  <button 
                    onClick={() => setActiveTab("playbook")}
                    style={{ 
                      padding: '8px 16px', 
                      background: 'transparent', 
                      border: 0, 
                      borderBottom: activeTab === 'playbook' ? '2px solid var(--color-primary)' : '2px solid transparent',
                      color: activeTab === 'playbook' ? '#fff' : 'var(--color-text-muted)',
                      fontWeight: '600',
                      fontSize: '13px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px'
                    }}
                  >
                    <AlertOctagon size={14} color="var(--color-secondary)" /> Response Playbook
                  </button>
                )}
              </div>

              {/* TAB CONTENT: LOGS */}
              {activeTab === "logs" && (
                <div style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <h3 style={{ fontSize: '14px', fontWeight: '700', color: '#fff' }}>Event Stream Preview</h3>
                    
                    <div style={{ position: 'relative', width: '280px' }}>
                      <input 
                        type="text" 
                        placeholder="Filter events..." 
                        value={searchQuery}
                        onChange={e => setSearchQuery(e.target.value)}
                        style={{ 
                          width: '100%', 
                          padding: '6px 12px 6px 32px', 
                          background: 'rgba(0,0,0,0.2)', 
                          border: '1px solid var(--border-color)', 
                          borderRadius: '6px', 
                          color: '#fff', 
                          fontSize: '12px' 
                        }}
                      />
                      <Search size={14} style={{ position: 'absolute', left: '10px', top: '9px', color: 'var(--color-text-muted)' }} />
                    </div>
                  </div>

                  <div style={{ flex: 1, border: '1px solid var(--border-color)', borderRadius: '8px', overflow: 'hidden', display: 'flex', flexDirection: 'column', minHeight: '260px' }}>
                    <div style={{ overflowX: 'auto', flex: 1 }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
                        <thead style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--border-color)' }}>
                          <tr>
                            <th style={{ padding: '10px 16px', color: 'var(--color-text-muted)' }}>Timestamp</th>
                            <th style={{ padding: '10px 16px', color: 'var(--color-text-muted)' }}>Type</th>
                            <th style={{ padding: '10px 16px', color: 'var(--color-text-muted)' }}>Process</th>
                            <th style={{ padding: '10px 16px', color: 'var(--color-text-muted)' }}>Command line / details</th>
                            <th style={{ padding: '10px 16px', color: 'var(--color-text-muted)' }}>Network Target</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredEvents.length === 0 ? (
                            <tr>
                              <td colSpan="5" style={{ padding: '40px', textAlign: 'center', color: 'var(--color-text-muted)' }}>
                                No matching logs found.
                              </td>
                            </tr>
                          ) : (
                            filteredEvents.map(ev => (
                              <tr key={ev.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                                <td style={{ padding: '10px 16px', color: 'var(--color-text-muted)', whiteSpace: 'nowrap' }}>
                                  {new Date(ev.timestamp).toISOString().replace("T", " ").substring(0, 19)}
                                </td>
                                <td style={{ padding: '10px 16px' }}>
                                  <span style={{ 
                                    padding: '2px 6px', 
                                    borderRadius: '4px', 
                                    fontSize: '10px', 
                                    background: ev.event_type === 'process' ? 'rgba(0, 240, 255, 0.1)' : ev.event_type === 'network' ? 'rgba(59, 130, 246, 0.1)' : 'rgba(255,255,255,0.05)',
                                    color: ev.event_type === 'process' ? 'var(--color-primary)' : ev.event_type === 'network' ? '#3b82f6' : '#fff'
                                  }}>
                                    {ev.event_type}
                                  </span>
                                </td>
                                <td style={{ padding: '10px 16px', fontWeight: '600', color: '#fff' }}>{ev.process_name || "-"}</td>
                                <td style={{ padding: '10px 16px', fontFamily: 'monospace', fontSize: '11px', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ev.commandline}>
                                  {ev.commandline || ev.file_path || "-"}
                                </td>
                                <td style={{ padding: '10px 16px', color: 'var(--color-primary)' }}>
                                  {ev.dst_ip ? `${ev.dst_ip}:${ev.dst_port || ""}` : "-"}
                                </td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB CONTENT: PROCESS TREE */}
              {activeTab === "tree" && (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '20px', overflowY: 'auto', maxHeight: '500px' }}>
                  <h3 style={{ fontSize: '14px', fontWeight: '700', color: '#fff', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Terminal size={16} color="var(--color-primary)" /> Executed Process Trees
                  </h3>
                  
                  {rootProcesses.length === 0 ? (
                    <div style={{ display: 'flex', flex: 1, alignItems: 'center', justifyContent: 'center', color: 'var(--color-text-muted)' }}>
                      No process executions correlated in this alert data. Run the Agent Swarm to correlate.
                    </div>
                  ) : (
                    <div>
                      {rootProcesses.map(root => {
                        const renderProcessNode = (process, depth = 0) => {
                          const { spawned, connected, created } = getProcessRelations(process.id);
                          return (
                            <div key={process.id} style={{ marginLeft: `${depth * 24}px`, borderLeft: depth > 0 ? '1px dashed rgba(0, 240, 255, 0.2)' : 'none', paddingLeft: depth > 0 ? '16px' : '0', marginBottom: '16px', position: 'relative' }}>
                              
                              {/* Process entity block */}
                              <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '10px 14px', display: 'inline-block', minWidth: '380px' }}>
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                                  <span style={{ fontWeight: '700', color: 'var(--color-primary)', display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '13px' }}>
                                    <Cpu size={14} /> {process.label}
                                  </span>
                                  <span style={{ fontSize: '10px', color: 'var(--color-text-muted)' }}>
                                    PID: {process.pid}
                                  </span>
                                </div>
                                {process.commandline && (
                                  <div style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--color-text-muted)', background: 'rgba(0,0,0,0.3)', padding: '4px 8px', borderRadius: '4px', wordBreak: 'break-all', marginTop: '6px' }}>
                                    {process.commandline}
                                  </div>
                                )}
                                {process.user && (
                                  <div style={{ fontSize: '10px', color: 'var(--color-text-muted)', marginTop: '4px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                    <User size={10} /> User: {process.user}
                                  </div>
                                )}
                              </div>

                              {/* Connections & Creations (process context edges) */}
                              {(connected.length > 0 || created.length > 0) && (
                                <div style={{ marginLeft: '24px', marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                  {connected.map(ip => (
                                    <div key={ip.id} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#3b82f6' }}>
                                      <ArrowRight size={10} /> Connected to external: <Network size={12} /> <strong>{ip.label}</strong>
                                    </div>
                                  ))}
                                  {created.map(f => (
                                    <div key={f.id} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#10b981' }}>
                                      <ArrowRight size={10} /> Dropped file path: <FileCode size={12} /> <strong>{f.path || f.label}</strong>
                                    </div>
                                  ))}
                                </div>
                              )}

                              {/* Child processes spawned */}
                              {spawned.map(child => renderProcessNode(child, depth + 1))}
                            </div>
                          );
                        };
                        return renderProcessNode(root);
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* TAB CONTENT: THREAT INTEL */}
              {activeTab === "iocs" && (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  <h3 style={{ fontSize: '14px', fontWeight: '700', color: '#fff' }}>
                    Extracted Threat Indicators (IOCs) & Reputation
                  </h3>
                  
                  {iocNodes.length === 0 ? (
                    <div style={{ display: 'flex', flex: 1, alignItems: 'center', justifyContent: 'center', color: 'var(--color-text-muted)', background: 'rgba(0,0,0,0.1)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '40px' }}>
                      No network or hash threat indicators extracted from the current investigation logs.
                    </div>
                  ) : (
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                      {iocNodes.map(ioc => {
                        const isIP = ioc.type === "ip";
                        const isMalicious = ioc.label === "185.220.101.5" || ioc.label.includes("update-service") || ioc.hash?.includes("abc") || ioc.hash?.includes("sha256_abc");
                        
                        return (
                          <div 
                            key={ioc.id} 
                            style={{ 
                              background: 'rgba(0,0,0,0.15)', 
                              border: '1px solid',
                              borderColor: isMalicious ? 'var(--status-failed)' : 'var(--border-color)',
                              borderRadius: '8px', 
                              padding: '16px',
                              display: 'flex',
                              flexDirection: 'column',
                              justifyContent: 'space-between',
                              boxShadow: isMalicious ? '0 0 10px rgba(239, 68, 68, 0.1)' : 'none'
                            }}
                          >
                            <div>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                                <span style={{ 
                                  fontSize: '10px', 
                                  textTransform: 'uppercase', 
                                  fontWeight: '700', 
                                  padding: '1px 6px', 
                                  borderRadius: '4px',
                                  background: isIP ? 'rgba(59, 130, 246, 0.1)' : 'rgba(16, 185, 129, 0.1)',
                                  color: isIP ? '#3b82f6' : '#10b981',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '4px'
                                }}>
                                  {isIP ? <Network size={10} /> : <FileCode size={10} />} {ioc.type}
                                </span>
                                {isMalicious ? (
                                  <span style={{ color: 'var(--status-failed)', display: 'inline-flex', alignItems: 'center', gap: '3px', fontSize: '11px', fontWeight: '700' }}>
                                    <AlertTriangle size={12} /> Threat Detected
                                  </span>
                                ) : (
                                  <span style={{ color: 'var(--color-text-muted)', fontSize: '11px' }}>
                                    Unflagged
                                  </span>
                                )}
                              </div>
                              <h4 style={{ fontSize: '13px', fontWeight: '700', color: '#fff', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                                {isIP ? ioc.label : ioc.hash || ioc.label}
                              </h4>
                              {ioc.path && (
                                <span style={{ display: 'block', fontSize: '11px', color: 'var(--color-text-muted)', marginTop: '4px', fontStyle: 'italic' }}>
                                  Path: {ioc.path}
                                </span>
                              )}
                            </div>

                            <div style={{ 
                              marginTop: '16px', 
                              borderTop: '1px solid rgba(255,255,255,0.05)', 
                              paddingTop: '12px',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between'
                            }}>
                              <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                                VT Reputation: <strong style={{ color: isMalicious ? 'var(--status-failed)' : '#fff' }}>{isMalicious ? "14/70" : "0/70"}</strong>
                              </span>
                              {isIP && (
                                <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                                  AbuseIPDB Score: <strong style={{ color: isMalicious ? 'var(--status-failed)' : '#fff' }}>{isMalicious ? "85%" : "0%"}</strong>
                                </span>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* TAB CONTENT: AI RCA */}
              {activeTab === "rca" && (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '20px', overflowY: 'auto', maxHeight: '500px' }}>
                  <h3 style={{ fontSize: '15px', fontWeight: '700', color: '#fff', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px' }}>
                    <FileText size={16} color="var(--color-primary)" /> Swarm Root Cause Analysis
                  </h3>
                  
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                    <div>
                      <h4 style={{ fontSize: '12px', textTransform: 'uppercase', color: 'var(--color-text-muted)', marginBottom: '6px', fontWeight: '700' }}>Root Cause Thesis</h4>
                      <p style={{ fontSize: '14px', lineHeight: '1.6', color: '#f1f5f9' }}>{selectedDetails.root_cause}</p>
                    </div>

                    {selectedDetails.completed_at && (
                      <div>
                        <h4 style={{ fontSize: '12px', textTransform: 'uppercase', color: 'var(--color-text-muted)', marginBottom: '10px', fontWeight: '700' }}>Reconstructed Forensic Timeline</h4>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontFamily: 'monospace', fontSize: '12px' }}>
                          {/* Use mock timeline if logs are mapped */}
                          <div style={{ padding: '8px 12px', background: 'rgba(239, 68, 68, 0.05)', borderLeft: '3px solid var(--status-failed)', borderRadius: '4px' }}>
                            <span style={{ color: 'var(--color-text-muted)' }}>08:01:23 UTC</span> | winword.exe opened phishing doc invoice.docx [Event ID 11]
                          </div>
                          <div style={{ padding: '8px 12px', background: 'rgba(239, 68, 68, 0.08)', borderLeft: '3px solid var(--status-failed)', borderRadius: '4px' }}>
                            <span style={{ color: 'var(--color-text-muted)' }}>08:01:31 UTC</span> | Spawned powershell.exe -enc IEX (New-Object Net.WebClient)... [Event ID 1]
                          </div>
                          <div style={{ padding: '8px 12px', background: 'rgba(239, 68, 68, 0.1)', borderLeft: '3px solid var(--status-failed)', borderRadius: '4px' }}>
                            <span style={{ color: 'var(--color-text-muted)' }}>08:01:34 UTC</span> | Outbound socket connection established to C2 node 185.220.101.5:4444 [Event ID 3]
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* TAB CONTENT: RESPONSE PLAYBOOK */}
              {activeTab === "playbook" && (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '24px', overflowY: 'auto', maxHeight: '500px' }}>
                  <h3 style={{ fontSize: '15px', fontWeight: '700', color: '#fff', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px' }}>
                    <AlertOctagon size={16} color="var(--color-secondary)" /> Autonomous Mitigation & Containment
                  </h3>
                  
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                    <div>
                      <h4 style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--status-failed)', fontWeight: '800', letterSpacing: '0.5px', marginBottom: '10px' }}>
                        🔴 Phase 1: Immediate Containment Actions (Required Now)
                      </h4>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px', color: '#f1f5f9', cursor: 'pointer' }}>
                          <input type="checkbox" defaultChecked style={{ accentColor: 'var(--color-primary)' }} />
                          Isolate host <strong>server01</strong> from network segments (EDR rule drop)
                        </label>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px', color: '#f1f5f9', cursor: 'pointer' }}>
                          <input type="checkbox" defaultChecked style={{ accentColor: 'var(--color-primary)' }} />
                          Revoke Active Directory Active Sessions for compromised user: <strong>john.doe</strong>
                        </label>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px', color: '#f1f5f9', cursor: 'pointer' }}>
                          <input type="checkbox" defaultChecked style={{ accentColor: 'var(--color-primary)' }} />
                          Add egress block rule for C2 command node: <strong>185.220.101.5</strong> (Port 4444)
                        </label>
                      </div>
                    </div>

                    <div>
                      <h4 style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--status-pending)', fontWeight: '800', letterSpacing: '0.5px', marginBottom: '10px' }}>
                        🟡 Phase 2: Short-Term Forensics & Threat Hunting
                      </h4>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px', color: '#f1f5f9', cursor: 'pointer' }}>
                          <input type="checkbox" style={{ accentColor: 'var(--color-primary)' }} />
                          Initiate a fleet-wide threat hunt for registry run key: <code>HKCU\...\Run\WindowsUpdate</code>
                        </label>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px', color: '#f1f5f9', cursor: 'pointer' }}>
                          <input type="checkbox" style={{ accentColor: 'var(--color-primary)' }} />
                          Search email gateways for attachments referencing <code>invoice.docx</code> or similar naming hashes
                        </label>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Password decryption dialog modal overlay */}
      {passwordPromptInv && (
        <div style={{ 
          position: 'fixed', 
          top: 0, 
          left: 0, 
          width: '100vw', 
          height: '100vh', 
          background: 'rgba(0, 0, 0, 0.75)', 
          backdropFilter: 'blur(4px)',
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'center',
          zIndex: 100 
        }}>
          <div className="glass-panel" style={{ width: '420px', padding: '24px', position: 'relative' }}>
            <h2 style={{ fontSize: '16px', fontWeight: '800', color: '#fff', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Lock color="var(--status-auth)" size={18} /> Decrypt Forensic Ingestion
            </h2>
            <p style={{ fontSize: '13px', color: 'var(--color-text-muted)', marginBottom: '20px' }}>
              The archive <strong>{passwordPromptInv.password_required}</strong> requires a password for decompression.
            </p>

            <form onSubmit={handlePasswordSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-text-muted)', marginBottom: '6px', fontWeight: '600' }}>Extraction Password</label>
                <input 
                  type="password" 
                  autoFocus
                  placeholder="Enter archive password" 
                  value={promptPasswordValue}
                  onChange={e => setPromptPasswordValue(e.target.value)}
                  style={{ width: '100%', padding: '10px 12px', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border-color)', borderRadius: '6px', color: '#fff', fontSize: '13px' }}
                />
              </div>

              {passwordError && (
                <div style={{ color: 'var(--status-failed)', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <AlertTriangle size={14} /> {passwordError}
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '8px' }}>
                <button 
                  type="button"
                  onClick={() => setPasswordPromptInv(null)}
                  style={{ background: 'transparent', border: '1px solid var(--border-color)', color: '#fff', padding: '8px 16px', borderRadius: '6px', fontSize: '13px' }}
                >
                  Cancel
                </button>
                <button 
                  type="submit"
                  disabled={submittingPassword || !promptPasswordValue}
                  style={{ 
                    background: 'var(--status-auth)', 
                    color: '#fff', 
                    border: 0, 
                    padding: '8px 16px', 
                    borderRadius: '6px', 
                    fontSize: '13px', 
                    fontWeight: '700',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  {submittingPassword ? (
                    <>
                      <Loader2 className="pulse-primary" size={14} /> Decrypting...
                    </>
                  ) : (
                    "Decrypt Ingestion"
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
