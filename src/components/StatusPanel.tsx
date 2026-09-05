import { GitCommit, Radio, Server } from 'lucide-react';

export const StatusPanel: React.FC = () => {
  const subsystems = [
    {
      name: 'Autonomous Agent Core',
      spec: 'Multi-step reasoning engine with bounded execution contexts',
      status: 'IN DEVELOPMENT',
      statusColor: 'text-subtle-cyan',
      dotColor: 'bg-subtle-cyan',
      progress: 'Architecture & Policy Design',
    },
    {
      name: 'Deterministic Policy Guardrails',
      spec: 'Strict containment layer preventing unauthorized operations',
      status: 'IN DEVELOPMENT',
      statusColor: 'text-electric-blue-light',
      dotColor: 'bg-electric-blue',
      progress: 'Formal Verification Framework',
    },
    {
      name: 'Security Assessment Engine',
      spec: 'Target topology analysis & workflow orchestration engine',
      status: 'IN DEVELOPMENT',
      statusColor: 'text-white/80',
      dotColor: 'bg-white/60',
      progress: 'Simulation Pipeline Engineering',
    },
    {
      name: 'Intelligent Report Synthesizer',
      spec: 'Executive summary & remediation path automated generator',
      status: 'IN DEVELOPMENT',
      statusColor: 'text-subtle-cyan',
      dotColor: 'bg-subtle-cyan',
      progress: 'Structured Schema Definition',
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
                <span>MAHORAGA AI // SYSTEM STATUS</span>
              </div>
              <h3 className="font-display font-extrabold tracking-wider text-2xl sm:text-3xl text-white mt-1">
                UNDER CONSTRUCTION
              </h3>
            </div>

            {/* Slow Pulsing Status Indicator (NO spinning wheel) */}
            <div className="flex items-center gap-3 px-4 py-2 rounded-xl bg-electric-blue/10 border border-electric-blue/30 self-start sm:self-center">
              <span className="relative flex h-3 w-3">
                <span className="animate-pulse-slow absolute inline-flex h-full w-full rounded-full bg-electric-blue opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-electric-blue"></span>
              </span>
              <div className="flex flex-col">
                <span className="font-mono text-xs font-bold tracking-wider text-white">
                  ENGINEERING IN PROGRESS
                </span>
                <span className="font-mono text-[10px] text-text-muted">
                  BACKEND NOT YET DEPLOYED
                </span>
              </div>
            </div>
          </div>

          {/* Central Message */}
          <div className="max-w-3xl">
            <p className="text-base sm:text-xl font-medium text-text-secondary leading-relaxed">
              &ldquo;Autonomous security intelligence is being engineered.&rdquo;
            </p>
            <p className="text-xs sm:text-sm text-text-muted mt-2 font-mono">
              The Mahoraga AI platform is currently undergoing foundational core architecture development. 
              Live security engines, automated testing tools, and scanning daemons are intentionally disabled in this preview environment.
            </p>
          </div>

          {/* Subsystems Matrix */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            {subsystems.map((subsystem) => (
              <div
                key={subsystem.name}
                className="p-4 rounded-xl border border-white/5 bg-white/[0.02] hover:bg-white/[0.04] transition-colors flex flex-col justify-between space-y-3"
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h4 className="font-mono text-sm font-semibold text-white">
                      {subsystem.name}
                    </h4>
                    <p className="text-xs text-text-muted mt-0.5">
                      {subsystem.spec}
                    </p>
                  </div>
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-white/[0.05] border border-white/10 text-white/90 whitespace-nowrap">
                    {subsystem.status}
                  </span>
                </div>

                <div className="flex items-center justify-between text-[11px] font-mono text-text-muted pt-2 border-t border-white/5">
                  <div className="flex items-center gap-1.5">
                    <span className={`h-1.5 w-1.5 rounded-full ${subsystem.dotColor} animate-pulse-slow`}></span>
                    <span>Current Focus:</span>
                  </div>
                  <span className="text-white/80">{subsystem.progress}</span>
                </div>
              </div>
            ))}
          </div>

          {/* Status Verification Footer */}
          <div className="flex flex-wrap items-center justify-between gap-4 pt-4 border-t border-white/10 text-xs font-mono text-text-muted">
            <div className="flex items-center gap-2">
              <GitCommit size={14} className="text-electric-blue" />
              <span>Target Milestone: Autonomous v1 Private Preview</span>
            </div>
            <div className="flex items-center gap-2">
              <Server size={14} className="text-subtle-cyan" />
              <span>Host Environment: Safe Frontend Sandbox</span>
            </div>
          </div>

        </div>
      </div>
    </section>
  );
};
