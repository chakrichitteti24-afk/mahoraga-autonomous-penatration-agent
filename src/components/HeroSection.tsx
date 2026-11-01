import { Lock, Play, FileText, Bot } from 'lucide-react';
import { AICoreVisual } from './AICoreVisual';

interface HeroSectionProps {
  onOpenWaitlist?: () => void;
}

export const HeroSection: React.FC<HeroSectionProps> = () => {
  const scrollTo = (id: string) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <section 
      id="overview" 
      className="relative min-h-[92vh] flex items-center justify-center pt-28 pb-16 px-4 sm:px-6 lg:px-8 overflow-hidden"
    >
      {/* Background Cyber Ambient Lights */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-7xl h-[550px] bg-radial-top pointer-events-none opacity-70" />
      <div className="absolute inset-0 bg-grid-cyber opacity-40 pointer-events-none" />

      <div className="relative z-10 max-w-7xl mx-auto w-full">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-8 items-center">
          
          {/* Left Column: Brand & Messaging */}
          <div className="lg:col-span-7 flex flex-col items-center lg:items-start text-center lg:text-left space-y-6 sm:space-y-8">
            
            {/* Live Status Badge */}
            <div className="inline-flex items-center gap-2.5 px-3.5 py-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 backdrop-blur-md shadow-inner-glow transition-all duration-300">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400"></span>
              </span>
              <span className="font-mono text-xs font-semibold tracking-[0.2em] text-emerald-300 uppercase">
                SECURITY SCANNER ACTIVE
              </span>
              <span className="text-white/20">|</span>
              <span className="font-mono text-[11px] font-medium tracking-wider text-subtle-cyan">
                PRECISION AUDIT ENGINE
              </span>
            </div>

            {/* Main Wordmark: MAHORAGA AI */}
            <div className="space-y-3 w-full">
              <div className="flex flex-wrap items-baseline justify-center lg:justify-start gap-x-4 sm:gap-x-5 gap-y-1">
                <h1 className="font-display font-black tracking-[0.16em] sm:tracking-[0.22em] text-4xl sm:text-6xl md:text-7xl lg:text-7xl xl:text-8xl text-white leading-none drop-shadow-[0_0_35px_rgba(0,102,255,0.35)]">
                  MAHORAGA
                </h1>
                <span className="font-display font-bold text-lg sm:text-2xl md:text-3xl tracking-[0.25em] text-subtle-cyan px-2.5 py-0.5 rounded-md bg-electric-blue/15 border border-electric-blue/35">
                  AI
                </span>
              </div>

              {/* Secondary Heading */}
              <h2 className="font-mono font-semibold tracking-[0.18em] sm:tracking-[0.25em] text-xs sm:text-sm md:text-base text-electric-blue-light uppercase">
                AUTONOMOUS VULNERABILITY AUDITOR &amp; DEFENSE AGENT
              </h2>
            </div>

            {/* Main Description */}
            <p className="max-w-2xl text-base sm:text-lg text-text-secondary font-normal leading-relaxed">
              Precision automated security assessment for live web applications, source code, and dependencies. 
              Eliminates false positives with verified proofs, OWASP Top 10 mappings, and code-level remediation diffs.
            </p>

            {/* Credibility Note */}
            <div className="inline-flex items-center gap-2 text-xs font-mono text-text-muted bg-white/[0.02] border border-white/5 px-3 py-1.5 rounded-lg">
              <Lock size={13} className="text-emerald-400" />
              <span>Non-destructive precision audits • NIST SP 800-52r2 • CVSS v3.1 Compliant</span>
            </div>

            {/* Interactive Call to Actions */}
            <div className="flex flex-col sm:flex-row items-center gap-4 w-full sm:w-auto pt-2">
              
              {/* Primary Action: START LIVE SCAN */}
              <button
                type="button"
                onClick={() => scrollTo('scanner')}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2.5 px-8 py-3.5 rounded-xl bg-electric-blue hover:bg-electric-blue/90 text-white font-mono text-xs sm:text-sm font-semibold tracking-wider shadow-glow-blue transition-all duration-200 group focus:outline-none focus-visible:ring-2 focus-visible:ring-electric-blue"
              >
                <Play size={16} fill="currentColor" className="group-hover:scale-110 transition-transform" />
                <span>START LIVE SCAN</span>
              </button>

              {/* Secondary Action: VIEW REPORTS */}
              <button
                type="button"
                onClick={() => scrollTo('reports')}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-white font-mono text-xs sm:text-sm font-medium tracking-wide transition-all duration-200"
              >
                <FileText size={15} className="text-subtle-cyan" />
                <span>AUDIT REPORTS</span>
              </button>

              {/* Tertiary Action: ASK AGENT */}
              <button
                type="button"
                onClick={() => scrollTo('agent-chat')}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-white font-mono text-xs sm:text-sm font-medium tracking-wide transition-all duration-200"
              >
                <Bot size={15} className="text-electric-blue" />
                <span>ASK MAHORAGA</span>
              </button>

            </div>

          </div>

          {/* Right Column: AI Core Interactive Visual */}
          <div className="lg:col-span-5 flex justify-center items-center relative">
            <AICoreVisual />
          </div>

        </div>
      </div>
    </section>
  );
};
