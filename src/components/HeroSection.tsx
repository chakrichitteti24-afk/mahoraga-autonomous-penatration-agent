import { ArrowRight, Lock, Bell } from 'lucide-react';
import { AICoreVisual } from './AICoreVisual';

interface HeroSectionProps {
  onOpenWaitlist: () => void;
}

export const HeroSection: React.FC<HeroSectionProps> = ({ onOpenWaitlist }) => {
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
            
            {/* Small Status Badge: ● UNDER CONSTRUCTION */}
            <div className="inline-flex items-center gap-2.5 px-3.5 py-1.5 rounded-full border border-white/10 bg-white/[0.04] backdrop-blur-md shadow-inner-glow transition-all duration-300 hover:border-electric-blue/40">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-electric-blue opacity-60"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-electric-blue"></span>
              </span>
              <span className="font-mono text-xs font-semibold tracking-[0.2em] text-white/90 uppercase">
                UNDER CONSTRUCTION
              </span>
              <span className="text-white/20">|</span>
              <span className="font-mono text-[11px] font-medium tracking-wider text-subtle-cyan">
                COMING SOON
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
                AUTONOMOUS CYBERSECURITY INTELLIGENCE
              </h2>
            </div>

            {/* Main Description */}
            <p className="max-w-2xl text-base sm:text-lg text-text-secondary font-normal leading-relaxed">
              An AI-powered security agent designed to automate security assessment workflows, 
              analyze findings, and generate actionable security reports.
            </p>

            {/* Credibility Note */}
            <div className="inline-flex items-center gap-2 text-xs font-mono text-text-muted bg-white/[0.02] border border-white/5 px-3 py-1.5 rounded-lg">
              <Lock size={13} className="text-electric-blue" />
              <span>Engineered with deterministic policy guardrails by CipherFlux Labs</span>
            </div>

            {/* Call to Actions */}
            <div className="flex flex-col sm:flex-row items-center gap-4 w-full sm:w-auto pt-2">
              
              {/* Primary CTA: COMING SOON (Stylized as upcoming/disabled state) */}
              <button
                type="button"
                onClick={onOpenWaitlist}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2.5 px-7 py-3.5 rounded-xl bg-white/[0.06] hover:bg-white/[0.1] border border-white/15 text-white/90 font-mono text-xs sm:text-sm font-semibold tracking-wider transition-all duration-200 group focus:outline-none focus-visible:ring-2 focus-visible:ring-electric-blue"
                aria-label="Notify me when Mahoraga AI is ready"
              >
                <Bell size={15} className="text-subtle-cyan group-hover:scale-110 transition-transform" />
                <span>COMING SOON — GET UPDATES</span>
              </button>

              {/* Secondary CTA: EXPLORE PLATFORM */}
              <a
                href="#capabilities"
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-7 py-3.5 rounded-xl border border-white/10 hover:border-electric-blue/40 bg-transparent hover:bg-electric-blue/5 text-text-secondary hover:text-white font-mono text-xs sm:text-sm font-medium tracking-wider transition-all duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-electric-blue"
              >
                <span>EXPLORE PLATFORM</span>
                <ArrowRight size={15} className="text-electric-blue" />
              </a>
            </div>

            {/* Live Engineering Status Micro-Ticker */}
            <div className="pt-4 border-t border-white/5 w-full flex flex-wrap items-center justify-center lg:justify-start gap-4 sm:gap-6 text-xs font-mono text-text-muted">
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-electric-blue"></span>
                <span>STATUS: ARCHITECTURE PHASE</span>
              </div>
              <span className="text-white/10 hidden sm:inline">•</span>
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-subtle-cyan"></span>
                <span>TARGET ENGINE: AUTONOMOUS v1</span>
              </div>
              <span className="text-white/10 hidden sm:inline">•</span>
              <div className="text-text-muted">
                DEMO PREVIEW ONLY
              </div>
            </div>

          </div>

          {/* Right Column: Abstract AI Core Visual */}
          <div className="lg:col-span-5 flex justify-center items-center">
            <AICoreVisual />
          </div>

        </div>
      </div>
    </section>
  );
};
