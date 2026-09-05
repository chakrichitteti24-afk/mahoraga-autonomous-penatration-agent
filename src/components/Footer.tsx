import React from 'react';
import { CipherFluxLogo } from './CipherFluxLogo';
import { Lock } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-white/10 bg-[#02050A] pt-16 pb-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto flex flex-col space-y-10">
        
        {/* Main Footer Row */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-8">
          
          {/* Brand Info */}
          <div className="space-y-2">
            <div className="flex items-baseline gap-2">
              <span className="font-display font-extrabold tracking-[0.2em] text-xl text-white">
                MAHORAGA
              </span>
              <span className="font-display font-bold text-xs tracking-[0.25em] text-subtle-cyan px-2 py-0.5 rounded bg-electric-blue/15 border border-electric-blue/30">
                AI
              </span>
            </div>
            <p className="font-mono text-xs tracking-wider text-text-secondary">
              Autonomous Cybersecurity Intelligence
            </p>
          </div>

          {/* Under Construction Notice Badge */}
          <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full border border-white/10 bg-white/[0.02] self-start md:self-center">
            <span className="h-2 w-2 rounded-full bg-electric-blue animate-pulse-slow"></span>
            <span className="font-mono text-xs font-semibold tracking-[0.2em] text-white/90 uppercase">
              UNDER CONSTRUCTION
            </span>
          </div>

          {/* CipherFlux Labs Parent Attribution */}
          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="text-[10px] font-mono text-text-muted tracking-widest uppercase">
                ENGINEERED BY
              </div>
              <div className="font-mono text-xs font-semibold text-white tracking-wider">
                CipherFlux Labs
              </div>
            </div>
            <CipherFluxLogo size={32} showText={false} />
          </div>

        </div>

        {/* Safety & Legal Transparency Disclaimer */}
        <div className="pt-8 border-t border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs font-mono text-text-muted">
          <div className="flex items-center gap-2">
            <Lock size={12} className="text-electric-blue" />
            <span>
              Mahoraga AI is an upcoming research &amp; engineering initiative. Backend engine not yet operational.
            </span>
          </div>
          <div>
            &copy; {new Date().getFullYear()} CipherFlux Labs. All rights reserved.
          </div>
        </div>

      </div>
    </footer>
  );
};
