import React, { useState } from 'react';
import { 
  User, 
  BrainCircuit, 
  Search, 
  Network, 
  AlertOctagon, 
  FileCheck2, 
  ArrowRight, 
  Info,
  Shield
} from 'lucide-react';

interface StepDetail {
  id: string;
  name: string;
  category: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  description: string;
  details: string;
  conceptualStatus: string;
}

export const AgentWorkflow: React.FC = () => {
  const [activeStep, setActiveStep] = useState<number>(1);

  const steps: StepDetail[] = [
    {
      id: 'user',
      name: 'USER',
      category: 'Input Directive',
      icon: User,
      description: 'Operator defines target assessment scope & authorized boundaries.',
      details: 'Strict authorization rules and explicit scope constraints are verified prior to any agent activity.',
      conceptualStatus: 'INPUT_READY',
    },
    {
      id: 'mahoraga',
      name: 'MAHORAGA AI',
      category: 'Autonomous Agent',
      icon: BrainCircuit,
      description: 'Core agent orchestrates reasoning loop under deterministic guardrails.',
      details: 'Agent plans multi-step assessment workflows while enforcing strict sandbox containment.',
      conceptualStatus: 'REASONING_CORE',
    },
    {
      id: 'assess',
      name: 'ASSESS',
      category: 'Workflow Stage 1',
      icon: Search,
      description: 'Autonomous discovery of architectural attack surface & configurations.',
      details: 'Maps services, API endpoints, exposed protocols, and structural posture without aggressive disruption.',
      conceptualStatus: 'CONCEPTUAL_PIPELINE',
    },
    {
      id: 'analyze',
      name: 'ANALYZE',
      category: 'Workflow Stage 2',
      icon: Network,
      description: 'Contextual analysis of security risks & chained vulnerabilities.',
      details: 'Correlates multi-vector findings into cohesive exploit path models to verify real exploitability.',
      conceptualStatus: 'CONCEPTUAL_PIPELINE',
    },
    {
      id: 'prioritize',
      name: 'PRIORITIZE',
      category: 'Workflow Stage 3',
      icon: AlertOctagon,
      description: 'Risk triage based on business impact and attack surface exposure.',
      details: 'Filters noise, eliminates false positives, and calculates realistic contextual threat rankings.',
      conceptualStatus: 'CONCEPTUAL_PIPELINE',
    },
    {
      id: 'report',
      name: 'REPORT',
      category: 'Deliverable Stage',
      icon: FileCheck2,
      description: 'Generates structured executive summaries & technical remediation guides.',
      details: 'Delivers actionable code-level fixes, verified proof-of-concepts, and management dashboards.',
      conceptualStatus: 'SYNTHESIZER_OUT',
    },
  ];

  return (
    <section id="security" className="py-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
      
      {/* Section Header */}
      <div className="text-center max-w-3xl mx-auto mb-14 space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-electric-blue/30 bg-electric-blue/5 text-subtle-cyan font-mono text-xs tracking-widest uppercase">
          <Shield size={12} />
          <span>AUTONOMOUS AGENT PIPELINE</span>
        </div>
        <h2 className="font-display font-extrabold tracking-wide text-3xl sm:text-4xl lg:text-5xl text-white">
          THE AGENT REASONING CYCLE
        </h2>
        <p className="text-text-secondary text-sm sm:text-base">
          A structured conceptual view of how Mahoraga AI is designed to autonomously coordinate 
          security assessments from user initiation to verified reporting.
        </p>
      </div>

      {/* Pipeline Container */}
      <div className="relative rounded-2xl border border-white/10 bg-white/[0.02] p-6 sm:p-8 backdrop-blur-xl">
        
        {/* Conceptual Notice Watermark */}
        <div className="flex items-center justify-between gap-4 pb-6 mb-8 border-b border-white/10 flex-wrap">
          <div className="flex items-center gap-2 text-xs font-mono text-text-muted">
            <Info size={14} className="text-electric-blue" />
            <span>CONCEPTUAL VISUALIZATION — NO REAL ATTACKS OR SCANS EXECUTED</span>
          </div>
          <div className="text-[11px] font-mono px-2.5 py-1 rounded bg-white/[0.04] border border-white/10 text-subtle-cyan">
            SPECIFICATION STAGE
          </div>
        </div>

        {/* Steps Flow (Responsive: Horizontal on large screens, stacked on mobile) */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3 sm:gap-4 relative">
          {steps.map((item, index) => {
            const Icon = item.icon;
            const isSelected = activeStep === index;
            const isMahoraga = item.id === 'mahoraga';

            return (
              <div key={item.id} className="relative flex flex-col">
                <button
                  type="button"
                  onClick={() => setActiveStep(index)}
                  className={`w-full text-left p-4 rounded-xl border transition-all duration-300 flex flex-col justify-between h-full group ${
                    isSelected
                      ? 'border-electric-blue bg-electric-blue/10 shadow-glow-blue'
                      : 'border-white/10 bg-white/[0.02] hover:bg-white/[0.05] hover:border-white/20'
                  }`}
                  aria-selected={isSelected}
                  role="tab"
                >
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[10px] text-text-muted tracking-widest">
                        0{index + 1}
                      </span>
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        isMahoraga ? 'bg-electric-blue/20 text-subtle-cyan font-bold' : 'bg-white/5 text-text-muted'
                      }`}>
                        {item.category}
                      </span>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg ${
                        isSelected 
                          ? 'bg-electric-blue text-white shadow-glow-blue' 
                          : 'bg-white/5 text-text-secondary group-hover:text-white'
                      } transition-colors`}>
                        <Icon size={18} />
                      </div>
                      <div className="font-display font-bold text-sm tracking-wider text-white">
                        {item.name}
                      </div>
                    </div>

                    <p className="text-xs text-text-muted line-clamp-2 leading-relaxed">
                      {item.description}
                    </p>
                  </div>

                  <div className="pt-3 mt-3 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-text-muted">
                    <span className="text-white/60">Stage:</span>
                    <span className="text-subtle-cyan/80">{item.conceptualStatus}</span>
                  </div>
                </button>

                {/* Connector Arrow (Desktop only, except last) */}
                {index < steps.length - 1 && (
                  <div className="hidden lg:flex absolute -right-2.5 top-1/2 -translate-y-1/2 z-20 text-white/30 pointer-events-none">
                    <ArrowRight size={14} className="text-electric-blue" />
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Selected Step Expanded Inspector */}
        <div className="mt-8 p-5 sm:p-6 rounded-xl border border-electric-blue/30 bg-gradient-to-r from-electric-blue/[0.07] to-transparent">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="font-mono text-xs text-subtle-cyan tracking-wider uppercase">
                PHASE 0{activeStep + 1} // ARCHITECTURAL SPECIFICATION
              </div>
              <h4 className="font-display font-bold text-lg text-white flex items-center gap-2">
                <span>{steps[activeStep].name}</span>
                <span className="text-sm font-normal text-text-secondary">— {steps[activeStep].category}</span>
              </h4>
              <p className="text-sm text-text-secondary max-w-3xl leading-relaxed pt-1">
                {steps[activeStep].details}
              </p>
            </div>

            <div className="font-mono text-xs text-right shrink-0">
              <div className="text-text-muted">EXECUTION STATUS</div>
              <div className="text-white font-semibold flex items-center gap-1.5 justify-end mt-0.5">
                <span className="w-2 h-2 rounded-full bg-electric-blue animate-pulse"></span>
                <span>ENGINEERING IN PROGRESS</span>
              </div>
            </div>
          </div>
        </div>

      </div>
    </section>
  );
};
