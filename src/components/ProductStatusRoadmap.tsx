import { Layers, Cpu, Shield, FileText, Clock } from 'lucide-react';

export const ProductStatusRoadmap: React.FC = () => {
  const tracks = [
    {
      title: 'Frontend Interface',
      status: 'IN DEVELOPMENT',
      badge: 'ACTIVE DEVELOPMENT',
      description: 'Designing the mission-control operator console, responsive design systems, and real-time supervisory telemetry views.',
      icon: Layers,
      items: [
        'Component Design System (Vite + React)',
        'Dark Mission-Control Architecture',
        'Responsive Operator Dashboard Panels',
      ],
    },
    {
      title: 'AI Agent',
      status: 'IN DEVELOPMENT',
      badge: 'ARCHITECTURE PHASE',
      description: 'Engineering the autonomous multi-agent reasoning kernel, bounded goal planners, and context-preserving short/long-term memory models.',
      icon: Cpu,
      items: [
        'Multi-Step Reasoning Kernel',
        'Deterministic Boundary Guardrails',
        'Natural Language Command Dispatcher',
      ],
    },
    {
      title: 'Security Engine',
      status: 'IN DEVELOPMENT',
      badge: 'FOUNDATION PHASE',
      description: 'Building the core security assessment pipelines, non-disruptive surface analyzers, and strict policy enforcement sandboxes.',
      icon: Shield,
      items: [
        'Passive Topology Discovery Module',
        'Strict Authorization Enforcement Gate',
        'Isolated Testing Sandboxes',
      ],
    },
    {
      title: 'Reporting',
      status: 'IN DEVELOPMENT',
      badge: 'SPECIFICATION PHASE',
      description: 'Crafting automated deliverable engines that synthesize findings into actionable executive summaries, verified proof diffs, and remediation steps.',
      icon: FileText,
      items: [
        'Neural Report Synthesizer',
        'Code-Level Remediation Generator',
        'Enterprise Compliance Schemas',
      ],
    },
  ];

  return (
    <section id="about" className="py-24 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
      
      {/* Big Feature Banner */}
      <div className="relative rounded-3xl border border-white/15 bg-gradient-to-b from-white/[0.05] via-[#07101A] to-[#02050A] p-8 sm:p-14 backdrop-blur-2xl overflow-hidden shadow-2xl">
        
        {/* Background Ambient Glow */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-3xl h-64 bg-electric-blue/10 blur-[120px] pointer-events-none" />

        <div className="relative z-10 flex flex-col items-center text-center space-y-6 max-w-4xl mx-auto">
          
          {/* Status Label */}
          <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full border border-electric-blue/40 bg-electric-blue/10 text-subtle-cyan font-mono text-xs font-semibold tracking-widest uppercase">
            <span className="h-2 w-2 rounded-full bg-electric-blue animate-pulse"></span>
            <span>SYSTEM DEVELOPMENT STATUS</span>
          </div>

          {/* Large Heading */}
          <div className="space-y-2">
            <h2 className="font-display font-black tracking-[0.18em] sm:tracking-[0.22em] text-3xl sm:text-5xl md:text-6xl text-white drop-shadow-[0_0_30px_rgba(0,102,255,0.3)]">
              MAHORAGA AI
            </h2>
            <div className="font-display font-extrabold tracking-wider text-xl sm:text-3xl text-electric-blue-light uppercase">
              UNDER CONSTRUCTION
            </div>
          </div>

          {/* Core Statement */}
          <p className="text-xl sm:text-2xl font-medium text-text-primary max-w-2xl leading-relaxed">
            &ldquo;Something powerful is being engineered.&rdquo;
          </p>

          <p className="text-sm sm:text-base text-text-secondary max-w-2xl leading-relaxed">
            CipherFlux Labs is actively developing the next evolution in autonomous cybersecurity intelligence. 
            All core subsystems are being engineered with uncompromising safety, reliability, and precision.
          </p>

        </div>

        {/* 4 Status Cards Grid */}
        <div className="relative z-10 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mt-16">
          {tracks.map((track) => {
            const Icon = track.icon;
            return (
              <div
                key={track.title}
                className="rounded-2xl border border-white/10 bg-white/[0.02] p-6 backdrop-blur-xl flex flex-col justify-between hover:border-white/20 transition-colors"
              >
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="p-2.5 rounded-xl bg-white/5 text-subtle-cyan border border-white/10">
                      <Icon size={20} />
                    </div>
                    <span className="font-mono text-[10px] tracking-wider px-2 py-0.5 rounded bg-electric-blue/15 text-subtle-cyan border border-electric-blue/30 font-semibold">
                      {track.status}
                    </span>
                  </div>

                  <div>
                    <h3 className="font-display font-bold text-lg text-white">
                      {track.title}
                    </h3>
                    <div className="text-[10px] font-mono text-electric-blue-light uppercase mt-0.5">
                      {track.badge}
                    </div>
                  </div>

                  <p className="text-xs text-text-secondary leading-relaxed">
                    {track.description}
                  </p>
                </div>

                <div className="pt-4 mt-6 border-t border-white/5 space-y-2 font-mono text-[11px] text-text-muted">
                  {track.items.map((item, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <Clock size={12} className="text-subtle-cyan/60 shrink-0" />
                      <span className="truncate">{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

      </div>

    </section>
  );
};
