import { useState } from 'react';
import { 
  FileCheck, 
  Layers, 
  CheckCircle2, 
  ShieldAlert, 
  FileText, 
  Sparkles,
  Download,
  Loader2,
  Check
} from 'lucide-react';
import { MahoragaAPI } from '../services/api';

export const ReportPreview: React.FC = () => {
  const [selectedSection, setSelectedSection] = useState<'exec' | 'risk' | 'findings' | 'recommendations'>('exec');
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [exportSuccess, setExportSuccess] = useState<boolean>(false);

  const reportSections = [
    { id: 'exec', label: 'Executive Summary', icon: FileText },
    { id: 'risk', label: 'Risk Overview', icon: ShieldAlert },
    { id: 'findings', label: 'Findings Analysis', icon: Layers },
    { id: 'recommendations', label: 'Remediation Roadmap', icon: CheckCircle2 },
  ];

  const handleDownloadMarkdown = async () => {
    setIsExporting(true);
    try {
      const markdown = await MahoragaAPI.getMarkdownReport();
      if (markdown) {
        // Create download blob
        const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `mahoraga_security_audit_report_${new Date().toISOString().slice(0, 10)}.md`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        setExportSuccess(true);
        setTimeout(() => setExportSuccess(false), 3000);
      }
    } catch (err) {
      console.error('Failed to export markdown report', err);
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <section id="reports" className="py-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
      
      {/* Section Header */}
      <div className="text-center max-w-3xl mx-auto mb-14 space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-electric-blue/30 bg-electric-blue/5 text-subtle-cyan font-mono text-xs tracking-widest uppercase">
          <FileCheck size={12} />
          <span>STRUCTURED DELIVERABLES</span>
        </div>
        <h2 className="font-display font-extrabold tracking-wide text-3xl sm:text-4xl lg:text-5xl text-white">
          SECURITY AUDIT REPORT
        </h2>
        <p className="text-text-secondary text-sm sm:text-base leading-relaxed">
          Automated multi-tier security deliverables. Generates CISO executive summaries alongside 
          technical vulnerability dossiers and verified code-level remediation diffs.
        </p>
      </div>

      {/* Report Document Shell */}
      <div className="relative rounded-2xl border border-white/10 bg-[#07101A]/90 p-5 sm:p-8 backdrop-blur-2xl shadow-2xl">
        
        {/* Top Watermark / Status Bar & Export Action */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-6 border-b border-white/10">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-electric-blue/10 border border-electric-blue/20 text-subtle-cyan">
              <Sparkles size={18} />
            </div>
            <div>
              <div className="font-display font-bold text-sm sm:text-base text-white">
                ENTERPRISE AUDIT &amp; REMEDIATION REPORT
              </div>
              <div className="text-xs font-mono text-text-muted">
                FORMAT: OWASP TOP 10 • NIST SP 800-52r2 • CVSS v3.1
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={handleDownloadMarkdown}
              disabled={isExporting}
              className="font-mono text-xs font-semibold px-4 py-2 rounded-xl bg-electric-blue hover:bg-electric-blue/90 text-white shadow-glow-blue transition-all duration-200 flex items-center gap-2 disabled:opacity-50"
            >
              {isExporting ? (
                <>
                  <Loader2 size={14} className="animate-spin" />
                  <span>GENERATING MD...</span>
                </>
              ) : exportSuccess ? (
                <>
                  <Check size={14} className="text-emerald-300" />
                  <span>EXPORTED (.MD)</span>
                </>
              ) : (
                <>
                  <Download size={14} />
                  <span>EXPORT FULL REPORT (.MD)</span>
                </>
              )}
            </button>
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
                Mahoraga AI completed an automated architecture and vulnerability review across the target perimeter. 
                The assessment prioritizes actionable weaknesses that directly influence external reachability, sensitive data exposure, and transport layer security.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                <div className="p-4 rounded-lg bg-white/[0.02] border border-white/5">
                  <div className="text-xs font-mono text-text-muted">OVERALL POSTURE</div>
                  <div className="text-lg font-bold text-amber-400 mt-1">MODERATE EXPOSURE</div>
                  <div className="text-xs text-text-muted mt-1">CORS &amp; Header Regressions</div>
                </div>
                <div className="p-4 rounded-lg bg-white/[0.02] border border-white/5">
                  <div className="text-xs font-mono text-text-muted">REACHABILITY FACTOR</div>
                  <div className="text-lg font-bold text-emerald-400 mt-1">CONTAINED POSTURE</div>
                  <div className="text-xs text-text-muted mt-1">Zero Exploitable RCE Vectors</div>
                </div>
                <div className="p-4 rounded-lg bg-white/[0.02] border border-white/5">
                  <div className="text-xs font-mono text-text-muted">ESTIMATED REMEDIATION</div>
                  <div className="text-lg font-bold text-white mt-1">&lt; 1 DAY</div>
                  <div className="text-xs text-text-muted mt-1">Deterministic Code Diffs Ready</div>
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
                Instead of isolated CVSS metrics, risks are mapped to attack chains and business risk impact.
              </p>

              <div className="space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between p-3 rounded bg-white/[0.02] border border-white/5">
                  <span className="text-white font-semibold">Identity &amp; API Security Perimeter</span>
                  <span className="text-amber-400 font-bold">1 High Risk Vector (CORS)</span>
                </div>
                <div className="flex items-center justify-between p-3 rounded bg-white/[0.02] border border-white/5">
                  <span className="text-white font-semibold">Transport Layer &amp; Cryptographic Hygiene</span>
                  <span className="text-amber-300 font-bold">1 Medium Risk Vector (HSTS)</span>
                </div>
                <div className="flex items-center justify-between p-3 rounded bg-white/[0.02] border border-white/5">
                  <span className="text-white font-semibold">Browser Client Integrity &amp; Script Restrictions</span>
                  <span className="text-subtle-cyan font-bold">1 Medium Risk Vector (CSP)</span>
                </div>
              </div>
            </div>
          )}

          {/* Tab 3: Findings Analysis */}
          {selectedSection === 'findings' && (
            <div className="space-y-5 animate-fadeIn">
              <div className="border-b border-white/10 pb-4">
                <span className="font-mono text-xs text-electric-blue uppercase tracking-wider">
                  SECTION 3.0
                </span>
                <h3 className="text-xl sm:text-2xl font-display font-bold text-white mt-1">
                  Technical Finding Analysis
                </h3>
              </div>

              <div className="space-y-4 font-mono text-xs">
                <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-red-400 font-bold">HIGH SEVERITY • CVSS 7.4 • CWE-942</span>
                    <span className="text-text-muted">SCOPE: /v2/auth</span>
                  </div>
                  <div className="text-sm text-white font-semibold">
                    Permissive Cross-Origin Resource Sharing (CORS) Configuration
                  </div>
                  <p className="text-text-secondary leading-relaxed font-sans text-xs">
                    Access-Control-Allow-Origin header reflection permits unvalidated external web origins. 
                    If combined with session credentials, malicious websites could issue cross-origin requests to exfiltrate user data.
                  </p>
                </div>

                <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-amber-400 font-bold">MEDIUM SEVERITY • CVSS 5.3 • CWE-319</span>
                    <span className="text-text-muted">SCOPE: INGRESS EDGE</span>
                  </div>
                  <div className="text-sm text-white font-semibold">
                    Missing HTTP Strict Transport Security (HSTS)
                  </div>
                  <p className="text-text-secondary leading-relaxed font-sans text-xs">
                    Target does not enforce strict HTTPS via HSTS preload or subdomains, allowing downgrade attacks on unencrypted local networks.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Tab 4: Remediation Roadmap */}
          {selectedSection === 'recommendations' && (
            <div className="space-y-5 animate-fadeIn">
              <div className="border-b border-white/10 pb-4">
                <span className="font-mono text-xs text-electric-blue uppercase tracking-wider">
                  SECTION 4.0
                </span>
                <h3 className="text-xl sm:text-2xl font-display font-bold text-white mt-1">
                  Remediation Action Plan
                </h3>
              </div>

              <div className="space-y-4">
                <div className="p-4 rounded-xl border border-electric-blue/30 bg-electric-blue/5 space-y-2">
                  <div className="flex items-center gap-2 font-mono text-xs font-bold text-subtle-cyan">
                    <CheckCircle2 size={14} />
                    <span>PHASE 1: IMMEDIATE RESOLUTION (P0)</span>
                  </div>
                  <p className="text-xs text-text-secondary">
                    Update reverse proxy CORS configuration to match verified origin domain whitelists, refusing arbitrary reflection on authenticated routes.
                  </p>
                </div>

                <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02] space-y-2">
                  <div className="flex items-center gap-2 font-mono text-xs font-bold text-white">
                    <CheckCircle2 size={14} className="text-electric-blue" />
                    <span>PHASE 2: DEFENSIVE HARDENING (P1)</span>
                  </div>
                  <p className="text-xs text-text-secondary">
                    Enforce Strict-Transport-Security with max-age 31536000 and deploy Content-Security-Policy restricting script origins.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Report Footer Bar */}
          <div className="pt-6 border-t border-white/10 flex flex-wrap items-center justify-between gap-4 text-xs font-mono text-text-muted">
            <div className="flex items-center gap-2">
              <FileCheck size={14} className="text-emerald-400" />
              <span>Report Engine: Mahoraga Synthesizer v1.0 • Verified Output</span>
            </div>
            <div className="text-white/70">
              Format: GitHub-Flavored Markdown &amp; JSON Deliverable
            </div>
          </div>

        </div>

      </div>
    </section>
  );
};
