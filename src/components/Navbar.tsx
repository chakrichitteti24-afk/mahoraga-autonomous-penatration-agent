import { useState, useEffect } from 'react';
import { Menu, X, Play } from 'lucide-react';
import { CipherFluxLogo } from './CipherFluxLogo';

interface NavbarProps {
  onOpenWaitlist?: () => void;
}

export const Navbar: React.FC<NavbarProps> = () => {
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
    { label: 'Scanner Console', href: '#scanner' },
    { label: 'Reports', href: '#reports' },
    { label: 'AI Agent', href: '#agent-chat' },
  ];

  const scrollToScanner = () => {
    const el = document.getElementById('scanner');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <header className="fixed top-0 left-0 right-0 z-40 px-3 sm:px-6 lg:px-8 pt-3 sm:pt-4 transition-all duration-300">
      <nav
        aria-label="Main Navigation"
        className={`mx-auto max-w-7xl rounded-2xl border transition-all duration-300 ${
          scrolled
            ? 'bg-[#02050A]/90 border-white/10 shadow-2xl backdrop-blur-xl'
            : 'bg-[#02050A]/70 border-white/10 shadow-lg backdrop-blur-lg'
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
              className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400"
              title="Mahoraga Security Engine is operational"
            >
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400"></span>
              </span>
              <span className="font-mono text-[10px] font-semibold tracking-[0.18em] uppercase text-emerald-300">
                SYSTEM OPERATIONAL
              </span>
            </div>

            <button
              type="button"
              onClick={scrollToScanner}
              className="font-mono text-xs font-semibold px-4 py-1.5 rounded-lg bg-electric-blue hover:bg-electric-blue/90 text-white shadow-glow-blue transition-all duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-electric-blue flex items-center gap-1.5"
            >
              <Play size={12} fill="currentColor" />
              <span>Launch Scanner</span>
            </button>
          </div>

          {/* Mobile Menu Button */}
          <div className="flex sm:hidden items-center gap-2">
            <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-[9px] font-mono tracking-wider text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>LIVE</span>
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
              <button
                type="button"
                onClick={() => {
                  setMobileMenuOpen(false);
                  scrollToScanner();
                }}
                className="w-full text-center font-mono text-xs font-semibold py-2.5 px-4 rounded-lg bg-electric-blue text-white shadow-glow-blue flex items-center justify-center gap-2"
              >
                <Play size={13} fill="currentColor" />
                <span>LAUNCH SCANNER</span>
              </button>
            </div>
          </div>
        )}
      </nav>
    </header>
  );
};
