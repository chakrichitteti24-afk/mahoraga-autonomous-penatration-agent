import React, { useState } from 'react';
import { 
  Shield, 
  Activity, 
  AlertCircle, 
  CheckCircle, 
  Cpu, 
  Layers,
  Sparkles,
  Terminal
} from 'lucide-react';
import type { SecurityFindingPreview } from '../types';

export const DashboardPreview: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'agent-log'>('overview');
  const [selectedFindingId, setSelectedFindingId] = useState<string>('finding-1');

  const demoFindings: SecurityFindingPreview[] = [
    {
      id: 'finding-1',
      title: 'Permissive Cross-Origin Resource Sharing (CORS) Policy',
      severity: 'HIGH',
      category: 'API Security',
      targetScope: 'api.preview-cluster.internal/v2/auth',
      cvss: '7.4',
      remediationSummary: 'Restrict Access-Control-Allow-Origin from wildcard reflection to explicitly verified domain whitelists.',
      statusBadge: 'DEMO FINDING',
    },
    {
      id: 'finding-2',
      title: 'Legacy TLS 1.0/1.1 Protocols Enabled on Ingress Edge',
      severity: 'MEDIUM',
      category: 'Cryptographic Posture',
      targetScope: 'gateway-ingress.preview-cluster.internal',
      cvss: '5.3',
      remediationSummary: 'Enforce TLS 1.2 minimum with forward-secret cipher suites (ECDHE-ECDSA-AES128-GCM-SHA256).',
      statusBadge: 'DEMO FINDING',
    },
    {
      id: 'finding-3',
      title: 'Missing Subresource Integrity (SRI) on External Assets',
      severity: 'LOW',
      category: 'Frontend Integrity',
      targetScope: 'app.preview-cluster.internal/assets',
      cvss: '3.7',
      remediationSummary: 'Inject sha384 integrity hashes into script tags loading third-party content distribution bundles.',
      statusBadge: 'DEMO FINDING',
    },
  ];

  const selectedFinding = demoFindings.find((f) => f.id === selectedFindingId) || demoFindings[0];

  return (
    <section className="py-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
      
      {/* Section Header */}
      <div className="text-center max-w-3xl mx-auto mb-12 space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-electric-blue/30 bg-electric-blue/5 text-subtle-cyan font-mono text-xs tracking-widest uppercase">
          <Layers size={12} />
          <span>FUTURE PLATFORM PREVIEW</span>
        </div>
        <h2 className="font-display font-extrabold tracking-wide text-3xl sm:text-4xl lg:text-5xl text-white">
          SECURITY ASSESSMENT INTERFACE
        </h2>
        <p className="text-text-secondary text-sm sm:text-base">
          An architectural preview of the future Mahoraga AI mission-control console, 
          designed for autonomous workflow supervision and rapid security triage.
        </p>
      </div>

      {/* Main Glass Dashboard Shell */}
      <div className="relative rounded-2xl border border-white/15 bg-[#07101A]/80 shadow-2xl backdrop-blur-2xl overflow-hidden">
        
        {/* Top Watermark & Alert Banner */}
        <div className="bg-electric-blue/15 border-b border-electric-blue/30 px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2 text-subtle-cyan font-semibold">
            <span className="w-2 h-2 rounded-full bg-subtle-cyan animate-pulse"></span>
            <span>PREVIEW — BACKEND UNDER DEVELOPMENT</span>
          </div>
          <div className="text-text-muted flex items-center gap-3">
            <span className="hidden sm:inline">DATA SOURCE: SYNTHETIC BENCHMARK SPECIFICATION</span>
            <span className="px-2 py-0.5 rounded bg-white/10 text-white font-bold text-[10px]">
              DEMO / PREVIEW
            </span>
          </div>
        </div>

        {/* Dashboard Title Bar / Toolbar */}
        <div className="border-b border-white/10 px-4 sm:px-6 py-4 flex flex-wrap items-center justify-between gap-4 bg-white/[0.01]">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/80"></span>
              <span className="font-display font-bold text-sm text-white tracking-wider">
                MAHORAGA OPERATOR CONSOLE
              </span>
            </div>
            <div className="hidden md:flex items-center gap-2 font-mono text-xs text-text-muted pl-4 border-l border-white/10">
              <span>TARGET:</span>
              <span className="text-text-secondary bg-white/[0.04] px-2 py-0.5 rounded border border-white/5">
                simulated-corp-mesh.internal
              </span>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex items-center gap-1 bg-black/40 p-1 rounded-xl border border-white/10">
            <button
              type="button"
              onClick={() => setActiveTab('overview')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                activeTab === 'overview'
                  ? 'bg-electric-blue text-white shadow-glow-blue'
                  : 'text-text-secondary hover:text-white'
              }`}
            >
              Overview
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('findings')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                activeTab === 'findings'
                  ? 'bg-electric-blue text-white shadow-glow-blue'
                  : 'text-text-secondary hover:text-white'
              }`}
            >
              Findings (Demo)
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('agent-log')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                activeTab === 'agent-log'
                  ? 'bg-electric-blue text-white shadow-glow-blue'
                  : 'text-text-secondary hover:text-white'
              }`}
            >
              Agent State
            </button>
          </div>
        </div>

        {/* Tab 1: Overview Panel */}
        {activeTab === 'overview' && (
          <div className="p-4 sm:p-6 space-y-6">
            
            {/* Top KPI Cards */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02]">
                <div className="flex items-center justify-between text-xs font-mono text-text-muted">
                  <span>AGENT STATUS</span>
                  <Activity size={14} className="text-electric-blue" />
                </div>
                <div className="text-xl font-display font-bold text-white mt-2">
                  STANDBY
                </div>
                <div className="text-[11px] font-mono text-subtle-cyan mt-1">
                  Policy Guardrails Engaged
                </div>
              </div>

              <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02]">
                <div className="flex items-center justify-between text-xs font-mono text-text-muted">
                  <span>ASSESSMENT STAGE</span>
                  <Cpu size={14} className="text-subtle-cyan" />
                </div>
                <div className="text-xl font-display font-bold text-white mt-2">
                  DISCOVERY
                </div>
                <div className="text-[11px] font-mono text-text-muted mt-1">
                  Phase 01 / 06 (Simulated)
                </div>
              </div>

              <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02]">
                <div className="flex items-center justify-between text-xs font-mono text-text-muted">
                  <span>POTENTIAL VECTORS</span>
                  <AlertCircle size={14} className="text-amber-400" />
                </div>
                <div className="text-xl font-display font-bold text-white mt-2">
                  3 DEMO FINDINGS
                </div>
                <div className="text-[11px] font-mono text-amber-400/80 mt-1">
                  1 High • 1 Med • 1 Low
                </div>
              </div>

              <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02]">
                <div className="flex items-center justify-between text-xs font-mono text-text-muted">
                  <span>CONTAINMENT</span>
                  <Shield size={14} className="text-emerald-400" />
                </div>
                <div className="text-xl font-display font-bold text-white mt-2">
                  ISOLATED
                </div>
                <div className="text-[11px] font-mono text-emerald-400/80 mt-1">
                  Zero Network Intrusion
                </div>
              </div>
            </div>

            {/* Middle Grid: Assessment Progress & Target Scope Topology */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              
              {/* Left Column: Progress & Milestones */}
              <div className="lg:col-span-6 p-5 rounded-xl border border-white/10 bg-white/[0.02] space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="font-mono text-xs uppercase tracking-wider text-white font-semibold">
                    ASSESSMENT PROGRESS // SIMULATED RUN
                  </h4>
                  <span className="text-[10px] font-mono text-text-muted">STAGE 2 OF 4</span>
                </div>

                <div className="space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between text-text-secondary">
                    <span>1. Target Scope Definition & Validation</span>
                    <span className="text-emerald-400 flex items-center gap-1">
                      <CheckCircle size={12} /> VERIFIED
                    </span>
                  </div>
                  <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-emerald-400 h-full w-full"></div>
                  </div>

                  <div className="flex items-center justify-between text-text-secondary pt-2">
                    <span>2. Service Architecture Inference</span>
                    <span className="text-electric-blue flex items-center gap-1">
                      <Activity size={12} className="animate-pulse" /> IN PROGRESS
                    </span>
                  </div>
                  <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-electric-blue h-full w-3/5"></div>
                  </div>

                  <div className="flex items-center justify-between text-text-muted pt-2">
                    <span>3. Correlation & Risk Prioritization</span>
                    <span>QUEUED</span>
                  </div>
                  <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-white/20 h-full w-0"></div>
                  </div>

                  <div className="flex items-center justify-between text-text-muted pt-2">
                    <span>4. Executive Report Synthesis</span>
                    <span>QUEUED</span>
                  </div>
                  <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-white/20 h-full w-0"></div>
                  </div>
                </div>

                <div className="pt-3 border-t border-white/5 flex items-center justify-between text-[11px] font-mono text-text-muted">
                  <span>Autonomous Policy Guard: Strict</span>
                  <span className="text-subtle-cyan">Zero Disruptive Payload Mode</span>
                </div>
              </div>

              {/* Right Column: Simulated Risk Overview Graph */}
              <div className="lg:col-span-6 p-5 rounded-xl border border-white/10 bg-white/[0.02] space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="font-mono text-xs uppercase tracking-wider text-white font-semibold">
                    RISK OVERVIEW // EXPOSURE MATRIX (DEMO)
                  </h4>
                  <span className="text-[10px] font-mono text-subtle-cyan">SYNTHETIC MODEL</span>
                </div>

                <div className="grid grid-cols-3 gap-3 text-center font-mono">
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                    <div className="text-xs text-red-400 font-bold">HIGH</div>
                    <div className="text-2xl font-display font-extrabold text-white mt-1">01</div>
                    <div className="text-[9px] text-text-muted mt-1">CORS Wildcard</div>
                  </div>
                  <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
                    <div className="text-xs text-amber-400 font-bold">MEDIUM</div>
                    <div className="text-2xl font-display font-extrabold text-white mt-1">01</div>
                    <div className="text-[9px] text-text-muted mt-1">TLS 1.0 Legacy</div>
                  </div>
                  <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
                    <div className="text-xs text-blue-400 font-bold">LOW</div>
                    <div className="text-2xl font-display font-extrabold text-white mt-1">01</div>
                    <div className="text-[9px] text-text-muted mt-1">Missing SRI</div>
                  </div>
                </div>

                <p className="text-xs text-text-muted font-mono leading-relaxed pt-2">
                  * Note: Values displayed are strictly mock benchmark presets for platform demonstration purposes. 
                  No actual target scanning has been executed.
                </p>
              </div>

            </div>

          </div>
        )}

        {/* Tab 2: Findings Panel */}
        {activeTab === 'findings' && (
          <div className="p-4 sm:p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
            
            {/* Finding List */}
            <div className="lg:col-span-5 space-y-3">
              <div className="text-xs font-mono text-text-muted mb-2">
                SELECT DEMO FINDING TO INSPECT:
              </div>
              {demoFindings.map((finding) => (
                <button
                  key={finding.id}
                  type="button"
                  onClick={() => setSelectedFindingId(finding.id)}
                  className={`w-full text-left p-3.5 rounded-xl border transition-all text-xs font-mono flex flex-col space-y-2 ${
                    selectedFindingId === finding.id
                      ? 'border-electric-blue bg-electric-blue/10 shadow-glow-blue'
                      : 'border-white/10 bg-white/[0.02] hover:bg-white/[0.05]'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      finding.severity === 'HIGH' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                      finding.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                      'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                    }`}>
                      {finding.severity} • CVSS {finding.cvss}
                    </span>
                    <span className="text-[10px] text-text-muted">
                      {finding.statusBadge}
                    </span>
                  </div>
                  <div className="font-semibold text-white text-xs line-clamp-1">
                    {finding.title}
                  </div>
                  <div className="text-[10px] text-text-muted truncate">
                    {finding.targetScope}
                  </div>
                </button>
              ))}
            </div>

            {/* Finding Detail Inspector */}
            <div className="lg:col-span-7 p-5 rounded-xl border border-white/10 bg-white/[0.02] space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="font-mono text-xs text-subtle-cyan uppercase">
                  DEMO FINDING DETAILS
                </div>
                <div className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/5 border border-white/10 text-text-muted">
                  ID: {selectedFinding.id.toUpperCase()}
                </div>
              </div>

              <div>
                <h4 className="font-display font-bold text-base text-white">
                  {selectedFinding.title}
                </h4>
                <div className="flex items-center gap-3 mt-2 text-xs font-mono text-text-muted">
                  <span>Scope: <span className="text-text-secondary">{selectedFinding.targetScope}</span></span>
                  <span>•</span>
                  <span>Category: <span className="text-text-secondary">{selectedFinding.category}</span></span>
                </div>
              </div>

              <div className="space-y-2 pt-2">
                <div className="font-mono text-xs text-white font-semibold flex items-center gap-1.5">
                  <Sparkles size={13} className="text-electric-blue" />
                  <span>AI Remediation Recommendation (Concept)</span>
                </div>
                <p className="text-xs text-text-secondary font-mono leading-relaxed bg-black/30 p-3 rounded-lg border border-white/5">
                  {selectedFinding.remediationSummary}
                </p>
              </div>

              <div className="pt-2 text-[11px] font-mono text-text-muted border-t border-white/5 flex items-center justify-between">
                <span>Verification State: Simulated Reference</span>
                <span className="text-electric-blue">Engine Under Construction</span>
              </div>
            </div>

          </div>
        )}

        {/* Tab 3: Agent State Telemetry */}
        {activeTab === 'agent-log' && (
          <div className="p-4 sm:p-6 space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between text-text-muted border-b border-white/10 pb-2">
              <span className="flex items-center gap-2">
                <Terminal size={14} className="text-subtle-cyan" />
                <span>AUTONOMOUS AGENT REASONING LOG (SIMULATED TELEMETRY)</span>
              </span>
              <span className="text-[10px] text-emerald-400">GUARDRAIL STATUS: BOUNDED</span>
            </div>

            <div className="bg-black/50 p-4 rounded-xl border border-white/10 space-y-2 text-text-secondary font-mono text-[11px] leading-relaxed">
              <div className="text-text-muted">[00:00:01] Initializing Autonomous Context Manager... OK</div>
              <div className="text-text-muted">[00:00:02] Loading Strict Safety Policy (RFC-2119 Bounded Scope)... OK</div>
              <div><span className="text-electric-blue">[00:00:03]</span> <span className="text-white">Agent Directive:</span> Read-only architectural posture evaluation.</div>
              <div><span className="text-electric-blue">[00:00:04]</span> <span className="text-subtle-cyan">Reasoning Step:</span> Validating domain boundary against explicit certificate SAN entries.</div>
              <div><span className="text-electric-blue">[00:00:05]</span> <span className="text-emerald-400">Constraint Check:</span> No active exploits or intrusive injections authorized. Proceeding with passive topology modeling.</div>
              <div className="text-text-muted pt-2">[00:00:06] Backend execution bridge: ENGINE_IN_DEVELOPMENT</div>
            </div>

            <div className="text-[11px] text-text-muted">
              * Note: The Mahoraga agent engine executes within strictly isolated environments with zero live production vulnerability exploits.
            </div>
          </div>
        )}

        {/* Bottom Status Ticker */}
        <div className="border-t border-white/10 px-4 sm:px-6 py-3 bg-white/[0.02] flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-text-muted">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-electric-blue animate-pulse"></span>
            <span>MAHORAGA PLATFORM PREVIEW // V0.1-CONCEPT</span>
          </div>
          <div className="text-subtle-cyan/80">
            ENGINE STATUS: UNDER CONSTRUCTION
          </div>
        </div>

      </div>
    </section>
  );
};
