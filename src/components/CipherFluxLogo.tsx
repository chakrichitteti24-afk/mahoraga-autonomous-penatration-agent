import React from 'react';

interface LogoProps {
  className?: string;
  size?: number;
  showText?: boolean;
}

export const CipherFluxLogo: React.FC<LogoProps> = ({
  className = '',
  size = 28,
  showText = true,
}) => {
  return (
    <div className={`inline-flex items-center gap-2.5 ${className}`}>
      <div 
        className="relative flex items-center justify-center shrink-0" 
        style={{ width: size, height: size }}
        aria-hidden="true"
      >
        <svg 
          viewBox="0 0 32 32" 
          width={size} 
          height={size} 
          fill="none" 
          xmlns="http://www.w3.org/2000/svg"
          className="transition-transform duration-500 hover:scale-105"
        >
          {/* Subtle Outer Hex Shield */}
          <polygon
            points="16,2 29,9.5 29,22.5 16,30 3,22.5 3,9.5"
            stroke="rgba(0, 240, 255, 0.4)"
            strokeWidth="1.2"
            fill="rgba(0, 102, 255, 0.08)"
          />
          {/* Inner Intersecting Flux Lines */}
          <path
            d="M8 12L24 20M24 12L8 20M16 5V27"
            stroke="#0066FF"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          {/* Core Nexus Center */}
          <circle cx="16" cy="16" r="3" fill="#00F0FF" />
          <circle cx="16" cy="16" r="1.5" fill="#FFFFFF" />
        </svg>
      </div>

      {showText && (
        <div className="flex flex-col leading-none">
          <span className="font-mono text-[11px] font-semibold tracking-[0.2em] text-white uppercase">
            CipherFlux
          </span>
          <span className="font-mono text-[8px] font-medium tracking-[0.25em] text-text-secondary uppercase">
            Labs
          </span>
        </div>
      )}
    </div>
  );
};
