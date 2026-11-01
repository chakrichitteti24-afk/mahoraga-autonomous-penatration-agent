import React, { useState, useEffect } from 'react';
import { Radio, Server, CheckCircle2 } from 'lucide-react';
import { MahoragaAPI } from '../services/api';

export const StatusPanel: React.FC = () => {
  const [backendOnline, setBackendOnline] = useState(false);

  useEffect(() => {
    const check = async () => {
      const health = await MahoragaAPI.checkHealth();
      if (health && health.status === 'ONLINE') {
        setBackendOnline(true);
      }
    };
    check();
  }, []);

  const subsystems = [
    {
      name: 'SAST Source Code Scanner',
      spec: 'AST-based static analysis for SQL injection, command execution, and hardcoded keys',
      status: 'OPERATIONAL',
      statusColor: 'text-emerald-400',
      dotColor: 'bg-emerald-400',
      progress: 'AST & Pattern Engine Active',
    },
    {
      name: 'Web Application DAST Auditor',
      spec: 'Non-destructive live HTTP probe for HSTS, CSP, CORS reflections, and TLS handshakes',
      status: 'OPERATIONAL',
      statusColor: 'text-emerald-400',
      dotColor: 'bg-emerald-400',
      progress: 'Precision Socket & Header Probing',
    },
    {
      name: 'Software Supply Chain (SCA)',
      spec: 'Dependency analysis scanning package.json and requirements.txt against CVE advisories',
      status: 'OPERATIONAL',
      statusColor: 'text-subtle-cyan',
      dotColor: 'bg-subtle-cyan',
      progress: 'OSV & Local Advisory Catalog',
    },
    {
      name: 'Remediation Intelligence Agent',
      spec: 'Automated executive summary generation, CVSS triage, and code patch synthesis',
      status: 'OPERATIONAL',
      statusColor: 'text-electric-blue-light',
      dotColor: 'bg-electric-blue',
      progress: 'Active Reasoning & Diff Generator',
    },
  ];

  return (
    <section className="py-16 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
      <div className="relative rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.04] to-white/[0.01] p-6 sm:p-10 backdrop-blur-xl shadow-2xl overflow-hidden">
        
        {/* Subtle background glow */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-electric-blue/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />
        
        <div className="relative z-10 flex flex-col space-y-8">
          
          {/* Top Header Row */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-white/10">
            <div>
              <div className="flex items-center gap-2 font-mono text-xs text-text-muted tracking-widest uppercase">
                <Radio size={14} className="text-electric-blue" />
                <span>MAHORAGA AI // SYSTEM TELEMETRY</span>
              </div>
              <h3 className="font-display font-extrabold tracking-wider text-2xl sm:text-3xl text-white mt-1">
                SYSTEM STATUS: OPERATIONAL
              </h3>
            </div>

            {/* Live Operational Status Indicator */}
            <div className="flex items-center gap-3 px-4 py-2 rounded-xl bg-emerald-500/10 border border-emerald-500/30 self-start sm:self-center">
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-400"></span>
              </span>
              <div className="flex flex-col">
                <span className="font-mono text-xs font-bold tracking-wider text-white">
                  ALL ENGINES ACTIVE
                </span>
                <span className="font-mono text-[10px] text-emerald-400/90">
                  {backendOnline ? 'FASTAPI BACKEND CONNECTED' : 'LOCAL ENGINE READY'}
                </span>
              </div>
            </div>
          </div>

          {/* Central Message */}
          <div className="max-w-3xl">
            <p className="text-base sm:text-xl font-medium text-text-secondary leading-relaxed">
              &ldquo;Autonomous security intelligence deployed with verified deterministic precision.&rdquo;
            </p>
            <p className="text-xs sm:text-sm text-text-muted mt-2 font-mono">
              The Mahoraga AI platform provides continuous, non-destructive security assessment across your attack surface. 
              Live scanning daemons and static analysis engines execute in sandboxed environments with zero false-positive tolerance.
            </p>
          </div>

          {/* Subsystems Matrix */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            {subsystems.map((subsystem) => (
              <div 
                key={subsystem.name}
                className="p-4 rounded-xl border border-white/10 bg-white/[0.02] hover:bg-white/[0.04] transition-colors flex flex-col justify-between space-y-3"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Server size={14} className="text-electric-blue shrink-0" />
                    <span className="font-mono text-xs font-bold text-white tracking-wide">
                      {subsystem.name}
                    </span>
                  </div>
                  
                  {/* Subsystem Status Badge */}
                  <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-white/[0.03] border border-white/10 shrink-0">
                    <span className={`h-1.5 w-1.5 rounded-full ${subsystem.dotColor} animate-pulse`}></span>
                    <span className={`font-mono text-[10px] font-semibold tracking-wider ${subsystem.statusColor}`}>
                      {subsystem.status}
                    </span>
                  </div>
                </div>

                <p className="text-xs text-text-secondary font-mono leading-relaxed">
                  {subsystem.spec}
                </p>

                <div className="pt-2 border-t border-white/5 flex items-center justify-between text-[11px] font-mono text-text-muted">
                  <span className="flex items-center gap-1.5">
                    <CheckCircle2 size={12} className="text-emerald-400" />
                    <span className="text-text-secondary">{subsystem.progress}</span>
                  </span>
                  <span className="text-emerald-400/90 font-semibold">ONLINE</span>
                </div>
              </div>
            ))}
          </div>

        </div>
      </div>
    </section>
  );
};
