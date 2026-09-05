import { useState } from 'react';
import { Mic, Sparkles, Bot } from 'lucide-react';
import type { VoicePromptDemo } from '../types';

export const VoiceConcept: React.FC = () => {
  const [selectedPromptIndex, setSelectedPromptIndex] = useState<number>(0);
  const [isListening, setIsListening] = useState<boolean>(false);

  const promptDemos: VoicePromptDemo[] = [
    {
      id: 'p-1',
      query: 'Analyze the security assessment.',
      simulatedAgentResponse: 'Analysis complete: 3 simulated findings evaluated. The highest priority vector is a permissive CORS configuration on /api/v2/auth/session. Recommended mitigation diff generated in Section 4.0.',
      reasoningVector: 'Scope Context: 1 High, 1 Med, 1 Low • Confidence: 99.4%',
    },
    {
      id: 'p-2',
      query: 'Summarize high-risk attack vectors for leadership.',
      simulatedAgentResponse: 'Executive Summary: Zero external RCE vulnerabilities detected. One configuration anomaly allows potential ambient credential exposure in browser context. Risk level is contained and remediable within one development sprint.',
      reasoningVector: 'Audience: CISO / Executive • Tone: Strategic Impact',
    },
    {
      id: 'p-3',
      query: 'Verify TLS certificate and cipher suite compliance.',
      simulatedAgentResponse: 'Cryptographic posture evaluated: Ingress gateway supports legacy TLS 1.0 and 1.1 with CBC ciphers. Recommending immediate update to TLS 1.2+ with forward-secret ECDHE cipher suites.',
      reasoningVector: 'Standard: NIST SP 800-52r2 • Remediation Diff Ready',
    },
  ];

  const currentDemo = promptDemos[selectedPromptIndex];

  const toggleMic = () => {
    setIsListening(true);
    setTimeout(() => {
      setIsListening(false);
    }, 1800);
  };

  return (
    <section className="py-20 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto w-full">
      
      {/* Section Header */}
      <div className="text-center max-w-2xl mx-auto mb-12 space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-electric-blue/30 bg-electric-blue/5 text-subtle-cyan font-mono text-xs tracking-widest uppercase">
          <Bot size={13} />
          <span>AUTONOMOUS AGENT INTERACTION</span>
        </div>
        <h2 className="font-display font-extrabold tracking-wide text-3xl sm:text-4xl text-white">
          &ldquo;Ask Mahoraga&rdquo;
        </h2>
        <p className="text-text-secondary text-sm sm:text-base leading-relaxed">
          Conceptual voice and natural language command interface for autonomous security operations.
        </p>
      </div>

      {/* Voice Console Shell */}
      <div className="relative rounded-2xl border border-white/10 bg-[#07101A]/80 p-6 sm:p-8 backdrop-blur-2xl shadow-2xl">
        
        {/* Top Watermark */}
        <div className="flex items-center justify-between pb-4 mb-6 border-b border-white/10 text-xs font-mono text-text-muted">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-electric-blue animate-pulse-slow"></span>
            <span>VOICE &amp; NLP AGENT INTERFACE (CONCEPTUAL PREVIEW)</span>
          </div>
          <div className="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-white/80 text-[10px]">
            DEMO ONLY
          </div>
        </div>

        {/* Conceptual Input Field & Mic Button */}
        <div className="relative flex items-center bg-black/50 border border-white/10 rounded-2xl p-2 sm:p-3 transition-all focus-within:border-electric-blue shadow-inner">
          
          {/* Animated Microphone Button */}
          <button
            type="button"
            onClick={toggleMic}
            className={`relative p-3.5 sm:p-4 rounded-xl transition-all duration-300 flex items-center justify-center shrink-0 ${
              isListening
                ? 'bg-electric-blue text-white shadow-glow-blue-lg scale-105'
                : 'bg-white/5 hover:bg-white/10 text-subtle-cyan border border-white/10'
            }`}
            aria-label="Click to simulate voice input"
            title="Click to simulate voice command"
          >
            {isListening && (
              <span className="absolute inset-0 rounded-xl bg-subtle-cyan animate-ping opacity-30"></span>
            )}
            <Mic size={20} className={isListening ? 'animate-bounce' : ''} />
          </button>

          {/* Prompt Display */}
          <div className="flex-1 px-4 text-left">
            <div className="text-[10px] font-mono text-text-muted uppercase">
              {isListening ? 'LISTENING (DEMO SIMULATION)...' : 'PROMPT DIRECTIVE'}
            </div>
            <div className="font-mono text-sm sm:text-base text-white font-medium mt-0.5">
              &ldquo;{currentDemo.query}&rdquo;
            </div>
          </div>

          {/* Soundwave Simulation Indicator */}
          <div className="hidden sm:flex items-center gap-1 px-3">
            {[4, 12, 8, 16, 6, 14, 10, 5].map((height, i) => (
              <span
                key={i}
                className="w-1 bg-electric-blue/70 rounded-full transition-all duration-300"
                style={{
                  height: isListening ? `${height * 1.8}px` : `${height}px`,
                  opacity: isListening ? 1 : 0.4,
                }}
              />
            ))}
          </div>
        </div>

        {/* Clickable Sample Directives */}
        <div className="mt-5 flex flex-wrap items-center gap-2">
          <span className="text-xs font-mono text-text-muted mr-1">TRY PROMPTS:</span>
          {promptDemos.map((demo, idx) => (
            <button
              key={demo.id}
              type="button"
              onClick={() => setSelectedPromptIndex(idx)}
              className={`font-mono text-xs px-3 py-1.5 rounded-lg border transition-all ${
                selectedPromptIndex === idx
                  ? 'border-electric-blue bg-electric-blue/15 text-subtle-cyan shadow-glow-blue'
                  : 'border-white/5 bg-white/[0.02] text-text-secondary hover:text-white hover:bg-white/5'
              }`}
            >
              {demo.query}
            </button>
          ))}
        </div>

        {/* Conceptual Agent Response Box */}
        <div className="mt-6 p-5 rounded-xl border border-electric-blue/20 bg-gradient-to-r from-electric-blue/[0.06] to-transparent space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-mono text-xs text-subtle-cyan">
              <Sparkles size={14} />
              <span className="font-semibold">MAHORAGA AI RESPONSE (CONCEPTUAL PREVIEW)</span>
            </div>
            <span className="text-[10px] font-mono text-text-muted">
              {currentDemo.reasoningVector}
            </span>
          </div>

          <p className="text-sm text-white/90 leading-relaxed font-sans">
            {currentDemo.simulatedAgentResponse}
          </p>

          <div className="pt-2 flex items-center justify-between text-[11px] font-mono text-text-muted border-t border-white/5">
            <span>Safety Rule: Real security commands not executed in preview environment</span>
            <span className="text-electric-blue">Engine v1 In Development</span>
          </div>
        </div>

      </div>
    </section>
  );
};
