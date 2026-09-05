import React, { useEffect, useState } from 'react';

interface InitializationScreenProps {
  onComplete: () => void;
}

export const InitializationScreen: React.FC<InitializationScreenProps> = ({ onComplete }) => {
  const [stage, setStage] = useState<'dark' | 'wordmark' | 'status' | 'fadeout' | 'done'>('dark');

  useEffect(() => {
    // Check for prefers-reduced-motion
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion) {
      setStage('done');
      onComplete();
      return;
    }

    // Sequence timeline:
    // 0 - 300ms: Dark screen
    // 300ms: MAHORAGA AI wordmark smoothly appears
    // 950ms: UNDER CONSTRUCTION status fades in
    // 1650ms: Fadeout begins
    // 2000ms: Complete and unmount

    const t1 = setTimeout(() => setStage('wordmark'), 250);
    const t2 = setTimeout(() => setStage('status'), 850);
    const t3 = setTimeout(() => setStage('fadeout'), 1600);
    const t4 = setTimeout(() => {
      setStage('done');
      onComplete();
    }, 1950);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
    };
  }, [onComplete]);

  if (stage === 'done') return null;

  return (
    <div
      className={`fixed inset-0 z-50 flex flex-col items-center justify-center bg-[#02050A] select-none transition-opacity duration-500 ease-out ${
        stage === 'fadeout' ? 'opacity-0 pointer-events-none' : 'opacity-100'
      }`}
      aria-hidden="true"
    >
      <div className="flex flex-col items-center justify-center px-6 text-center">
        {/* MAHORAGA AI Wordmark */}
        <div
          className={`transition-all duration-700 ease-out transform ${
            stage === 'dark'
              ? 'opacity-0 translate-y-3 scale-95'
              : 'opacity-100 translate-y-0 scale-100'
          }`}
        >
          <div className="flex items-baseline justify-center gap-3 sm:gap-4 flex-wrap">
            <h1 className="font-display font-extrabold tracking-[0.22em] text-3xl sm:text-5xl md:text-6xl text-white drop-shadow-[0_0_25px_rgba(0,102,255,0.4)]">
              MAHORAGA
            </h1>
            <span className="font-display font-bold text-xs sm:text-sm tracking-[0.3em] px-2.5 py-1 rounded bg-electric-blue/20 border border-electric-blue/40 text-subtle-cyan">
              AI
            </span>
          </div>
        </div>

        {/* Subtle Status: UNDER CONSTRUCTION */}
        <div
          className={`mt-6 sm:mt-8 transition-all duration-500 ease-out transform ${
            stage === 'status' || stage === 'fadeout'
              ? 'opacity-100 translate-y-0'
              : 'opacity-0 translate-y-2'
          }`}
        >
          <div className="inline-flex items-center gap-2.5 px-3 py-1 rounded-full border border-white/10 bg-white/[0.03]">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-subtle-cyan opacity-40"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-subtle-cyan"></span>
            </span>
            <span className="font-mono text-[10px] sm:text-xs font-semibold tracking-[0.25em] text-text-secondary uppercase">
              UNDER CONSTRUCTION
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
