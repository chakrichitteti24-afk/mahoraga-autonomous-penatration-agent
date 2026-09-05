import { useState } from 'react';
import { 
  FileCheck, 
  Layers, 
  CheckCircle2, 
  ShieldAlert, 
  FileText, 
  Sparkles
} from 'lucide-react';

export const ReportPreview: React.FC = () => {
  const [selectedSection, setSelectedSection] = useState<'exec' | 'risk' | 'findings' | 'recommendations'>('exec');

  const reportSections = [
    { id: 'exec', label: 'Executive Summary', icon: FileText },
    { id: 'risk', label: 'Risk Overview', icon: ShieldAlert },
    { id: 'findings', label: 'Findings Analysis', icon: Layers },
    { id: 'recommendations', label: 'Recommendations', icon: CheckCircle2 },
  ];

  return (
    <section id="reports" className="py-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
      
      {/* Section Header */}
      <div className="text-center max-w-3xl mx-auto mb-14 space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-electric-blue/30 bg-electric-blue/5 text-subtle-cyan font-mono text-xs tracking-widest uppercase">
          <FileCheck size={12} />
          <span>DELIVERABLE AUTOMATION</span>
        </div>
        <h2 className="font-display font-extrabold tracking-wide text-3xl sm:text-4xl lg:text-5xl text-white">
          AUTOMATED SECURITY REPORTS
        </h2>
        <p className="text-text-secondary text-sm sm:text-base leading-relaxed">
          Turn security assessment findings into structured, actionable reports with AI-assisted analysis.
        </p>
      </div>

      {/* Report Document Shell */}
      <div className="relative rounded-2xl border border-white/10 bg-[#07101A]/90 p-5 sm:p-8 backdrop-blur-2xl shadow-2xl">
        
        {/* Top Watermark / Status Bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-6 border-b border-white/10">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-electric-blue/10 border border-electric-blue/20 text-subtle-cyan">
              <Sparkles size={18} />
            </div>
            <div>
              <div className="font-display font-bold text-sm sm:text-base text-white">
                MAHORAGA ASSESSMENT DELIVERABLE SPECIFICATION
              </div>
              <div className="text-xs font-mono text-text-muted">
                FORMAT: ENTERPRISE AUDIT &amp; REMEDIATION GUIDE
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <span className="font-mono text-xs px-3 py-1 rounded-full bg-electric-blue/20 border border-electric-blue/40 text-subtle-cyan font-bold">
              DEMO / PREVIEW
            </span>
            <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-text-muted border-l border-white/10 pl-3">
              <span>TARGET:</span>
              <span className="text-white font-medium">preview.sample-mesh</span>
            </div>
          </div>
        </div>

        {/* Section Navigation Tabs */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 my-6">
          {reportSections.map((sec) => {
            const Icon = sec.icon;
            const isCurrent = selectedSection === sec.id;
            return (
              <button
                key={sec.id}
                type="button"
                onClick={() => setSelectedSection(sec.id as any)}
                className={`flex items-center justify-center gap-2 p-3 rounded-xl border text-xs font-mono font-medium transition-all ${
                  isCurrent
                    ? 'border-electric-blue bg-electric-blue/15 text-white shadow-glow-blue'
                    : 'border-white/5 bg-white/[0.02] text-text-secondary hover:text-white hover:bg-white/[0.04]'
                }`}
              >
                <Icon size={14} className={isCurrent ? 'text-subtle-cyan' : 'text-text-muted'} />
                <span>{sec.label}</span>
              </button>
            );
          })}
        </div>

        {/* Report Content Body */}
        <div className="rounded-xl border border-white/10 bg-black/40 p-6 sm:p-8 font-sans space-y-6 relative overflow-hidden">
          
          {/* Subtle Watermark in background */}
          <div className="absolute right-4 bottom-4 font-display font-black text-6xl sm:text-8xl text-white/[0.02] select-none pointer-events-none">
            DEMO PREVIEW
          </div>

          {/* Tab 1: Executive Summary */}
          {selectedSection === 'exec' && (
            <div className="space-y-5 animate-fadeIn">
              <div className="border-b border-white/10 pb-4">
                <span className="font-mono text-xs text-electric-blue uppercase tracking-wider">
                  SECTION 1.0
                </span>
                <h3 className="text-xl sm:text-2xl font-display font-bold text-white mt-1">
                  Executive Security Briefing
                </h3>
              </div>

              <p className="text-sm sm:text-base text-text-secondary leading-relaxed">
                During the simulated evaluation cycle, Mahoraga AI completed an automated architecture review of the designated target environment. The assessment prioritized actionable vulnerabilities that directly impact perimeter exposure and customer data sovereignty.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                <div className="p-4 rounded-lg bg-white/[0.02] border border-white/5">
                  <div className="text-xs font-mono text-text-muted">OVERALL POSTURE</div>
                  <div className="text-lg font-bold text-amber-400 mt-1">MODERATE EXPOSURE</div>
                  <div className="text-xs text-text-muted mt-1">3 Configuration Anomalies</div>
                </div>
                <div className="p-4 rounded-lg bg-white/[0.02] border border-white/5">
                  <div className="text-xs font-mono text-text-muted">CRITICAL RISK FACTOR</div>
                  <div className="text-lg font-bold text-emerald-400 mt-1">0 CRITICALS FOUND</div>
                  <div className="text-xs text-text-muted mt-1">No Active RCE Vectors</div>
                </div>
                <div className="p-4 rounded-lg bg-white/[0.02] border border-white/5">
                  <div className="text-xs font-mono text-text-muted">ESTIMATED FIX TIME</div>
                  <div className="text-lg font-bold text-white mt-1">&lt; 4 HOURS</div>
                  <div className="text-xs text-text-muted mt-1">Automated Config Diffs</div>
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Risk Overview */}
          {selectedSection === 'risk' && (
            <div className="space-y-5 animate-fadeIn">
              <div className="border-b border-white/10 pb-4">
                <span className="font-mono text-xs text-electric-blue uppercase tracking-wider">
                  SECTION 2.0
                </span>
                <h3 className="text-xl sm:text-2xl font-display font-bold text-white mt-1">
                  Risk Distribution &amp; Exposure Matrix
                </h3>
              </div>

              <p className="text-sm text-text-secondary leading-relaxed">
                Aggregated findings are categorized using environmental reachability scoring. 
                Instead of isolated CVSS metrics, risks are mapped to attack chains.
              </p>

              <div className="space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between p-3 rounded bg-white/[0.02] border border-white/5">
                  <span className="text-white font-semibold">Identity &amp; Authentication Perimeter</span>
                  <span className="text-amber-400 font-bold">1 High Risk Vector</span>
                </div>
                <div className="flex items-center justify-between p-3 rounded bg-white/[0.02] border border-white/5">
                  <span className="text-white font-semibold">Transport Layer &amp; TLS Configuration</span>
                  <span className="text-amber-300 font-bold">1 Medium Risk Vector</span>
                </div>
                <div className="flex items-center justify-between p-3 rounded bg-white/[0.02] border border-white/5">
                  <span className="text-white font-semibold">Client-Side Asset Protection &amp; Integrity</span>
                  <span className="text-blue-400 font-bold">1 Low Risk Vector</span>
                </div>
              </div>
            </div>
          )}

          {/* Tab 3: Findings */}
          {selectedSection === 'findings' && (
            <div className="space-y-5 animate-fadeIn">
              <div className="border-b border-white/10 pb-4">
                <span className="font-mono text-xs text-electric-blue uppercase tracking-wider">
                  SECTION 3.0
                </span>
                <h3 className="text-xl sm:text-2xl font-display font-bold text-white mt-1">
                  Technical Finding Dossier (Sample)
                </h3>
              </div>

              <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02] space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm font-bold text-white">
                    MH-SEC-01: Permissive Cross-Origin Resource Sharing (CORS)
                  </span>
                  <span className="font-mono text-xs text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20 font-bold">
                    HIGH SEVERITY
                  </span>
                </div>
                <div className="text-xs font-mono text-text-muted">
                  Endpoint: /api/v2/auth/session • Observed Header: Access-Control-Allow-Origin: *
                </div>
                <p className="text-xs text-text-secondary leading-relaxed">
                  The session validation endpoint allows credentialed origin reflection without strict whitelist validation, permitting cross-origin malicious scripts to invoke ambient browser credentials.
                </p>
              </div>
            </div>
          )}

          {/* Tab 4: Recommendations */}
          {selectedSection === 'recommendations' && (
            <div className="space-y-5 animate-fadeIn">
              <div className="border-b border-white/10 pb-4">
                <span className="font-mono text-xs text-electric-blue uppercase tracking-wider">
                  SECTION 4.0
                </span>
                <h3 className="text-xl sm:text-2xl font-display font-bold text-white mt-1">
                  Remediation &amp; Patch Plan
                </h3>
              </div>

              <div className="space-y-3">
                <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-500/5 space-y-2">
                  <div className="flex items-center gap-2 font-mono text-xs font-bold text-emerald-400">
                    <CheckCircle2 size={14} />
                    <span>IMMEDIATE ACTION (FIRST 24 HOURS)</span>
                  </div>
                  <p className="text-xs text-text-secondary">
                    Update reverse proxy CORS configuration to explicitly match verified domain headers, rejecting wildcard queries on authenticated routes.
                  </p>
                </div>

                <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02] space-y-2">
                  <div className="flex items-center gap-2 font-mono text-xs font-bold text-white">
                    <CheckCircle2 size={14} className="text-electric-blue" />
                    <span>SPRINT 1 HARDENING</span>
                  </div>
                  <p className="text-xs text-text-secondary">
                    Deprecate TLS 1.0 and 1.1 across all load-balancer listener definitions and deploy SRI validation hashes across CDNs.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Report Footer Bar */}
          <div className="pt-6 border-t border-white/10 flex flex-wrap items-center justify-between gap-4 text-xs font-mono text-text-muted">
            <div className="flex items-center gap-2">
              <FileCheck size={14} className="text-subtle-cyan" />
              <span>Report Engine: Mahoraga Synthesizer v1.0-alpha (Concept)</span>
            </div>
            <div className="text-white/70">
              Generated for: CipherFlux Labs Preview
            </div>
          </div>

        </div>

      </div>
    </section>
  );
};
