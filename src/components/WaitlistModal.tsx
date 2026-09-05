import React, { useState, useEffect } from 'react';
import { X, Bell, CheckCircle2, Shield, ArrowRight } from 'lucide-react';

interface WaitlistModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const WaitlistModal: React.FC<WaitlistModalProps> = ({ isOpen, onClose }) => {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('Security Engineer');
  const [submitted, setSubmitted] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'unset';
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;
    setSubmitted(true);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn"
      role="dialog"
      aria-modal="true"
      aria-labelledby="waitlist-title"
    >
      <div className="relative w-full max-w-lg rounded-2xl border border-white/15 bg-[#07101A] p-6 sm:p-8 shadow-2xl backdrop-blur-2xl">
        
        {/* Close Button */}
        <button
          type="button"
          onClick={onClose}
          className="absolute top-4 right-4 p-2 rounded-lg border border-white/10 bg-white/5 text-text-secondary hover:text-white hover:bg-white/10 focus:outline-none focus-visible:ring-2 focus-visible:ring-electric-blue"
          aria-label="Close dialog"
        >
          <X size={18} />
        </button>

        {!submitted ? (
          <div className="space-y-6">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-electric-blue/15 border border-electric-blue/30 text-subtle-cyan">
                <Bell size={20} />
              </div>
              <div>
                <span className="text-[10px] font-mono text-electric-blue uppercase tracking-widest">
                  ENGINEERING NOTIFICATIONS
                </span>
                <h3 id="waitlist-title" className="font-display font-bold text-xl text-white">
                  Request Alpha Access Updates
                </h3>
              </div>
            </div>

            <p className="text-xs sm:text-sm text-text-secondary leading-relaxed">
              Mahoraga AI is currently under active construction by CipherFlux Labs. Enter your corporate email to receive verified engineering milestones and early alpha invitations.
            </p>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <label htmlFor="user-email" className="block text-xs font-mono text-text-muted">
                  CORPORATE EMAIL
                </label>
                <input
                  id="user-email"
                  type="email"
                  required
                  placeholder="security@enterprise.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full px-4 py-3 rounded-xl bg-black/50 border border-white/10 text-white placeholder-white/20 text-xs sm:text-sm font-mono focus:border-electric-blue focus:outline-none focus:ring-1 focus:ring-electric-blue"
                />
              </div>

              <div className="space-y-1.5">
                <label htmlFor="user-role" className="block text-xs font-mono text-text-muted">
                  SECURITY ROLE / FOCUS
                </label>
                <select
                  id="user-role"
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="w-full px-4 py-3 rounded-xl bg-black/50 border border-white/10 text-white text-xs sm:text-sm font-mono focus:border-electric-blue focus:outline-none focus:ring-1 focus:ring-electric-blue"
                >
                  <option value="Security Engineer" className="bg-[#07101A]">Security Engineer / AppSec</option>
                  <option value="Penetration Tester" className="bg-[#07101A]">Penetration Tester / Red Team</option>
                  <option value="SecOps / SOC Lead" className="bg-[#07101A]">SecOps / SOC Analyst</option>
                  <option value="CISO / Security Director" className="bg-[#07101A]">CISO / Security Leadership</option>
                  <option value="Security Researcher" className="bg-[#07101A]">Academic / Independent Researcher</option>
                </select>
              </div>

              <button
                type="submit"
                className="w-full flex items-center justify-center gap-2 py-3 px-6 rounded-xl bg-electric-blue hover:bg-electric-blue-dark text-white font-mono text-xs sm:text-sm font-semibold tracking-wider transition-colors shadow-glow-blue focus:outline-none focus-visible:ring-2 focus-visible:ring-subtle-cyan"
              >
                <span>REGISTER FOR ALPHA UPDATES</span>
                <ArrowRight size={16} />
              </button>
            </form>

            <div className="flex items-center gap-2 text-[11px] font-mono text-text-muted pt-2 border-t border-white/5">
              <Shield size={13} className="text-electric-blue shrink-0" />
              <span>Zero spam guarantee. Communications restricted strictly to verified technical releases.</span>
            </div>
          </div>
        ) : (
          <div className="py-8 text-center space-y-4 animate-fadeIn">
            <div className="w-12 h-12 rounded-full bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 mx-auto flex items-center justify-center">
              <CheckCircle2 size={24} />
            </div>
            <h3 className="font-display font-bold text-xl text-white">
              Notification Registered
            </h3>
            <p className="text-xs sm:text-sm text-text-secondary max-w-sm mx-auto leading-relaxed">
              Thank you. Your email <span className="text-white font-mono">{email}</span> has been queued for private preview briefings as CipherFlux Labs advances the Mahoraga AI engine.
            </p>
            <button
              type="button"
              onClick={onClose}
              className="mt-4 px-6 py-2 rounded-xl bg-white/10 hover:bg-white/15 text-white font-mono text-xs tracking-wider"
            >
              CLOSE
            </button>
          </div>
        )}

      </div>
    </div>
  );
};
