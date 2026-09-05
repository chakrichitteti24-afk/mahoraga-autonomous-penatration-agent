import { useState, useEffect } from 'react';
import { Menu, X } from 'lucide-react';
import { CipherFluxLogo } from './CipherFluxLogo';

interface NavbarProps {
  onOpenWaitlist?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onOpenWaitlist }) => {
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const navLinks = [
    { label: 'Overview', href: '#overview' },
    { label: 'Capabilities', href: '#capabilities' },
    { label: 'Security', href: '#security' },
    { label: 'Reports', href: '#reports' },
    { label: 'About', href: '#about' },
  ];

  return (
    <header className="fixed top-0 left-0 right-0 z-40 px-3 sm:px-6 lg:px-8 pt-3 sm:pt-4 transition-all duration-300">
      <nav
        aria-label="Main Navigation"
        className={`mx-auto max-w-7xl rounded-2xl border transition-all duration-300 ${
          scrolled
            ? 'bg-[#02050A]/85 border-white/10 shadow-2xl backdrop-blur-xl'
            : 'bg-[#02050A]/60 border-white/10 shadow-lg backdrop-blur-lg'
        } px-4 sm:px-6 py-2.5 sm:py-3`}
      >
        <div className="flex items-center justify-between gap-4">
          {/* Brand Logo & Wordmark */}
          <a
            href="#overview"
            className="flex items-center gap-3 group focus:outline-none focus-visible:ring-2 focus-visible:ring-electric-blue rounded-lg py-1"
          >
            <CipherFluxLogo size={26} showText={false} />
            <div className="flex items-baseline gap-1.5">
              <span className="font-display font-extrabold tracking-[0.2em] text-base sm:text-lg text-white group-hover:text-subtle-cyan transition-colors">
                MAHORAGA
              </span>
              <span className="font-display font-bold text-[10px] tracking-[0.25em] text-subtle-cyan px-1.5 py-0.5 rounded bg-electric-blue/15 border border-electric-blue/30">
                AI
              </span>
            </div>
          </a>

          {/* Desktop Navigation Links */}
          <div className="hidden md:flex items-center gap-6 lg:gap-8">
            {navLinks.map((link) => (
              <a
                key={link.label}
                href={link.href}
                className="font-mono text-xs tracking-wider text-text-secondary hover:text-white transition-colors duration-200 py-1 relative group focus:outline-none focus-visible:ring-1 focus-visible:ring-electric-blue rounded"
              >
                {link.label}
                <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-electric-blue transition-all duration-300 group-hover:w-full" />
              </a>
            ))}
          </div>

          {/* Right Status Pill & CTA */}
          <div className="hidden sm:flex items-center gap-3">
            <div
              className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-text-secondary"
              title="Autonomous Penetration Testing Engine is currently in engineering phase"
            >
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-electric-blue opacity-50"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-electric-blue"></span>
              </span>
              <span className="font-mono text-[10px] font-semibold tracking-[0.18em] uppercase text-white/90">
                UNDER CONSTRUCTION
              </span>
            </div>

            {onOpenWaitlist && (
              <button
                type="button"
                onClick={onOpenWaitlist}
                className="font-mono text-xs font-medium px-3.5 py-1.5 rounded-lg border border-electric-blue/40 bg-electric-blue/10 hover:bg-electric-blue/20 text-subtle-cyan transition-all duration-200 hover:shadow-glow-blue focus:outline-none focus-visible:ring-2 focus-visible:ring-electric-blue"
              >
                Get Updates
              </button>
            )}
          </div>

          {/* Mobile Menu Button */}
          <div className="flex sm:hidden items-center gap-2">
            <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-white/[0.04] border border-white/10 text-[9px] font-mono tracking-wider text-text-secondary">
              <span className="h-1.5 w-1.5 rounded-full bg-electric-blue animate-pulse"></span>
              <span>DEV</span>
            </div>
            <button
              type="button"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-1.5 rounded-lg border border-white/10 bg-white/[0.04] text-text-secondary hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-electric-blue"
              aria-label={mobileMenuOpen ? 'Close Menu' : 'Open Menu'}
            >
              {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
          </div>
        </div>

        {/* Mobile Dropdown Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden pt-4 pb-3 border-t border-white/10 mt-3 flex flex-col gap-3 animate-fadeIn">
            {navLinks.map((link) => (
              <a
                key={link.label}
                href={link.href}
                onClick={() => setMobileMenuOpen(false)}
                className="font-mono text-sm tracking-wider text-text-secondary hover:text-white px-2 py-1.5 rounded hover:bg-white/[0.05] transition-colors"
              >
                {link.label}
              </a>
            ))}
            <div className="pt-2 border-t border-white/5 flex flex-col gap-2">
              <div className="flex items-center gap-2 px-2 py-1 text-xs font-mono text-text-secondary">
                <span className="h-2 w-2 rounded-full bg-electric-blue animate-pulse"></span>
                <span>STATUS: UNDER CONSTRUCTION</span>
              </div>
              {onOpenWaitlist && (
                <button
                  type="button"
                  onClick={() => {
                    setMobileMenuOpen(false);
                    onOpenWaitlist();
                  }}
                  className="w-full text-center font-mono text-xs font-semibold py-2 px-4 rounded-lg bg-electric-blue/15 border border-electric-blue/40 text-subtle-cyan hover:bg-electric-blue/25"
                >
                  REQUEST ACCESS NOTIFICATION
                </button>
              )}
            </div>
          </div>
        )}
      </nav>
    </header>
  );
};
