import React from 'react';
import { 
  ShieldCheck, 
  Workflow, 
  Binary, 
  AlertTriangle, 
  FileSpreadsheet, 
  Radar,
  Lock,
  ArrowUpRight
} from 'lucide-react';
import type { Capability } from '../types';

export const CapabilitiesSection: React.FC = () => {
  const capabilities: Capability[] = [
    {
      id: 'assessment',
      title: 'AI-Driven Security Assessment',
      badge: 'CORE AGENT',
      description: 'Autonomous surface mapping and context-aware inspection that dynamically adapts to target architecture without manual scripting.',
      iconName: 'ShieldCheck',
      metrics: 'Dynamic Context Discovery',
      status: 'IN ENGINEERING',
    },
    {
      id: 'orchestration',
      title: 'Autonomous Workflow Orchestration',
      badge: 'ORCHESTRATION',
      description: 'Multi-step autonomous execution loop bounded by deterministic safety guardrails, state verification, and safe rollback policies.',
      iconName: 'Workflow',
      metrics: 'Bounded Multi-Agent Loops',
      status: 'IN ENGINEERING',
    },
    {
      id: 'finding-analysis',
      title: 'Intelligent Finding Analysis',
      badge: 'CORRELATION',
      description: 'Deep neural correlation that links subtle configuration weaknesses across disparate services to identify chained attack paths.',
      iconName: 'Binary',
      metrics: 'Multi-Vector Chain Modeling',
      status: 'PROTOTYPING',
    },
    {
      id: 'risk-prioritization',
      title: 'Security Risk Prioritization',
      badge: 'TRIAGE',
      description: 'Business-criticality scoring that replaces generic CVSS scores with true exploit reachability and environmental impact modeling.',
      iconName: 'AlertTriangle',
      metrics: 'Zero-Noise Reachability Triage',
      status: 'SPECIFICATION',
    },
    {
      id: 'automated-reporting',
      title: 'Automated Report Generation',
      badge: 'SYNTHESIS',
      description: 'Generates board-ready executive summaries alongside verified proof-of-concepts, compliance matrices, and code-level remediation patches.',
      iconName: 'FileSpreadsheet',
      metrics: 'Structured Deliverable Engine',
      status: 'PROTOTYPING',
    },
    {
      id: 'continuous-intelligence',
      title: 'Continuous Security Intelligence',
      badge: 'PERSISTENCE',
      description: 'Maintains an active mental model of your evolving attack surface, flagging posture drift and new exposure vectors proactively.',
      iconName: 'Radar',
      metrics: 'Autonomous Surface Drift Tracking',
      status: 'SPECIFICATION',
    },
  ];

  const getIcon = (name: string) => {
    switch (name) {
      case 'ShieldCheck': return ShieldCheck;
      case 'Workflow': return Workflow;
      case 'Binary': return Binary;
      case 'AlertTriangle': return AlertTriangle;
      case 'FileSpreadsheet': return FileSpreadsheet;
      case 'Radar': return Radar;
      default: return ShieldCheck;
    }
  };

  return (
    <section id="capabilities" className="py-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
      
      {/* Section Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between mb-16 gap-6">
        <div className="space-y-3 max-w-2xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-electric-blue/30 bg-electric-blue/5 text-subtle-cyan font-mono text-xs tracking-widest uppercase">
            <span>CORE ARCHITECTURE</span>
          </div>
          <h2 className="font-display font-extrabold tracking-wide text-3xl sm:text-4xl lg:text-5xl text-white">
            BUILT FOR AUTONOMOUS SECURITY
          </h2>
          <p className="text-text-secondary text-sm sm:text-base leading-relaxed">
            Engineered from the ground up as an intelligent companion for modern security teams, 
            blending advanced language reasoning with deterministic execution policies.
          </p>
        </div>

        <div className="shrink-0">
          <div className="inline-flex items-center gap-2 text-xs font-mono text-text-muted bg-white/[0.03] border border-white/10 px-4 py-2 rounded-xl">
            <Lock size={14} className="text-electric-blue" />
            <span>PRODUCT CAPABILITIES IN ACTIVE R&amp;D</span>
          </div>
        </div>
      </div>

      {/* Grid of 6 Capabilities */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {capabilities.map((item) => {
          const Icon = getIcon(item.iconName);
          return (
            <div
              key={item.id}
              className="group relative rounded-2xl border border-white/10 bg-white/[0.02] p-6 sm:p-7 backdrop-blur-xl transition-all duration-300 hover:border-electric-blue/40 hover:bg-white/[0.04] hover:shadow-glow-blue flex flex-col justify-between"
            >
              <div className="space-y-4">
                
                {/* Top Badge & Status */}
                <div className="flex items-center justify-between">
                  <div className="p-2.5 rounded-xl bg-electric-blue/10 border border-electric-blue/20 text-subtle-cyan group-hover:bg-electric-blue group-hover:text-white transition-colors duration-300">
                    <Icon size={22} />
                  </div>
                  <span className="font-mono text-[10px] tracking-wider px-2 py-0.5 rounded bg-white/[0.04] border border-white/10 text-text-secondary">
                    {item.status}
                  </span>
                </div>

                {/* Title */}
                <div>
                  <div className="text-[10px] font-mono tracking-widest text-electric-blue uppercase mb-1">
                    {item.badge}
                  </div>
                  <h3 className="font-display font-bold text-lg text-white group-hover:text-subtle-cyan transition-colors">
                    {item.title}
                  </h3>
                </div>

                {/* Description */}
                <p className="text-xs sm:text-sm text-text-secondary leading-relaxed">
                  {item.description}
                </p>
              </div>

              {/* Card Footer Metric */}
              <div className="pt-5 mt-6 border-t border-white/5 flex items-center justify-between text-xs font-mono text-text-muted">
                <span className="text-white/70">{item.metrics}</span>
                <span className="text-electric-blue group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform">
                  <ArrowUpRight size={16} />
                </span>
              </div>

            </div>
          );
        })}
      </div>

    </section>
  );
};
