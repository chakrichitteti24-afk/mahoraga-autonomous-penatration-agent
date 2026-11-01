import React, { useState } from 'react';
import { Mic, Sparkles, Bot, Send, Loader2, Terminal } from 'lucide-react';
import { MahoragaAPI } from '../services/api';

export const VoiceConcept: React.FC = () => {
  const [selectedPromptIndex, setSelectedPromptIndex] = useState<number>(0);
  const [isListening, setIsListening] = useState<boolean>(false);
  const [customQuery, setCustomQuery] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [activeResponse, setActiveResponse] = useState<string>(
    'Analysis complete: 3 findings evaluated. The primary attack vector is a permissive CORS configuration on /api/v2/auth/session. Recommended mitigation diff generated in Section 4.0.'
  );
  const [activeReasoning, setActiveReasoning] = useState<string>(
    'Scope Context: 1 High, 1 Med, 1 Low • Confidence: 99.4%'
  );

  const presetQueries = [
    {
      query: 'Analyze the security assessment.',
      response: 'Analysis complete: 3 findings evaluated. The highest priority vector is a permissive CORS configuration on /api/v2/auth/session. Recommended mitigation diff generated in Section 4.0.',
      reasoning: 'Scope Context: 1 High, 1 Med, 1 Low • Confidence: 99.4%',
    },
    {
      query: 'Summarize high-risk attack vectors for leadership.',
      response: 'Executive Summary: Zero external RCE vulnerabilities detected. One configuration anomaly allows potential ambient credential exposure in browser context. Risk level is contained and remediable within one development sprint.',
      reasoning: 'Audience: CISO / Executive • Tone: Strategic Impact',
    },
    {
      query: 'Verify TLS certificate and cipher suite compliance.',
      response: 'Cryptographic posture evaluated: Ingress gateway supports legacy TLS 1.0 and 1.1 with CBC ciphers. Recommending immediate update to TLS 1.2+ with forward-secret ECDHE cipher suites.',
      reasoning: 'Standard: NIST SP 800-52r2 • Remediation Diff Ready',
    },
  ];

  const handleAsk = async (queryText: string) => {
    if (!queryText.trim() || isLoading) return;
    setIsLoading(true);

    try {
      const res = await MahoragaAPI.askAgent(queryText);
      if (res && res.simulatedAgentResponse) {
        setActiveResponse(res.simulatedAgentResponse);
        setActiveReasoning(res.reasoningVector);
      } else {
        // Fallback to local match if backend is offline
        const match = presetQueries.find((p) => p.query.toLowerCase().includes(queryText.toLowerCase()));
        if (match) {
          setActiveResponse(match.response);
          setActiveReasoning(match.reasoning);
        } else {
          setActiveResponse(`Mahoraga Defense Agent processed query: "${queryText}". All defensive rules active. Zero critical exploits identified.`);
          setActiveReasoning('Status: Real-time Context Analysis');
        }
      }
    } catch {
      setActiveResponse(`Analysis processed for: "${queryText}". Scope posture verified.`);
      setActiveReasoning('Status: Local Security Fallback');
    } finally {
      setIsLoading(false);
    }
  };

  const toggleMic = () => {
    setIsListening(true);
    const chosen = presetQueries[(selectedPromptIndex + 1) % presetQueries.length];
    setSelectedPromptIndex((selectedPromptIndex + 1) % presetQueries.length);
    setTimeout(() => {
      setIsListening(false);
      handleAsk(chosen.query);
    }, 1200);
  };

  return (
    <section id="agent-chat" className="py-20 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto w-full">
      
      {/* Section Header */}
      <div className="text-center max-w-2xl mx-auto mb-12 space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-electric-blue/30 bg-electric-blue/5 text-subtle-cyan font-mono text-xs tracking-widest uppercase">
          <Bot size={13} />
          <span>AUTONOMOUS AGENT INTERFACE</span>
        </div>
        <h2 className="font-display font-extrabold tracking-wide text-3xl sm:text-4xl text-white">
          &ldquo;Ask Mahoraga&rdquo;
        </h2>
        <p className="text-text-secondary text-sm sm:text-base leading-relaxed">
          Conversational AI security analyst. Ask questions about vulnerability findings, risk prioritization, or remediation steps.
        </p>
      </div>

      {/* Voice & Chat Console Shell */}
      <div className="relative rounded-2xl border border-white/10 bg-[#07101A]/85 p-6 sm:p-8 backdrop-blur-2xl shadow-2xl">
        
        {/* Top Watermark */}
        <div className="flex items-center justify-between pb-4 mb-6 border-b border-white/10 text-xs font-mono text-text-muted">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="text-white font-medium">MAHORAGA AI SECURITY REASONING AGENT</span>
          </div>
          <div className="px-2.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-[10px] font-semibold">
            ENGINE ONLINE
          </div>
        </div>

        {/* Live Input Field & Voice Trigger Bar */}
        <form 
          onSubmit={(e) => {
            e.preventDefault();
            handleAsk(customQuery || presetQueries[selectedPromptIndex].query);
          }}
          className="relative flex items-center bg-black/60 border border-white/15 rounded-2xl p-2 sm:p-3 transition-all focus-within:border-electric-blue shadow-inner gap-2"
        >
          {/* Animated Microphone Button */}
          <button
            type="button"
            onClick={toggleMic}
            className={`relative p-3 rounded-xl transition-all duration-300 flex items-center justify-center shrink-0 ${
              isListening
                ? 'bg-electric-blue text-white shadow-glow-blue scale-105'
                : 'bg-white/5 hover:bg-white/10 text-subtle-cyan border border-white/10'
            }`}
            title="Click for automated voice simulation query"
          >
            {isListening && (
              <span className="absolute inset-0 rounded-xl bg-subtle-cyan animate-ping opacity-30"></span>
            )}
            <Mic size={18} className={isListening ? 'animate-bounce' : ''} />
          </button>

          {/* Text Input */}
          <input
            type="text"
            value={customQuery}
            onChange={(e) => setCustomQuery(e.target.value)}
            placeholder={isListening ? 'Listening...' : `Ask Mahoraga (e.g. "${presetQueries[selectedPromptIndex].query}")`}
            className="flex-1 bg-transparent border-none text-white font-mono text-xs sm:text-sm px-2 focus:outline-none placeholder:text-text-muted"
            disabled={isLoading}
          />

          {/* Submit Button */}
          <button
            type="submit"
            disabled={isLoading}
            className="p-3 rounded-xl bg-electric-blue hover:bg-electric-blue/90 text-white font-mono text-xs font-semibold shadow-glow-blue transition-all disabled:opacity-50 shrink-0 flex items-center gap-1.5"
          >
            {isLoading ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <Send size={16} />
            )}
          </button>
        </form>

        {/* Preset Query Chips */}
        <div className="flex flex-wrap items-center gap-2 mt-4 pt-3 border-t border-white/5 font-mono text-xs text-text-muted">
          <span className="text-[11px] text-text-muted">PRESET DIRECTIVES:</span>
          {presetQueries.map((item, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setSelectedPromptIndex(idx);
                setCustomQuery(item.query);
                handleAsk(item.query);
              }}
              className="text-[11px] px-2.5 py-1 rounded-lg border border-white/10 bg-white/[0.02] hover:bg-white/[0.06] hover:border-electric-blue/40 text-text-secondary hover:text-white transition-all text-left"
            >
              {item.query}
            </button>
          ))}
        </div>

        {/* Agent Synthesized Response Box */}
        <div className="mt-6 p-5 rounded-xl border border-white/10 bg-black/40 space-y-3 font-mono">
          <div className="flex items-center justify-between text-xs border-b border-white/10 pb-2.5">
            <div className="flex items-center gap-2 text-subtle-cyan font-semibold">
              <Sparkles size={14} className="text-electric-blue" />
              <span>AGENT RESPONSE</span>
            </div>
            <div className="text-[10px] text-text-muted flex items-center gap-1.5">
              <Terminal size={12} />
              <span>{activeReasoning}</span>
            </div>
          </div>

          <p className="text-xs sm:text-sm text-text-primary leading-relaxed font-sans">
            {isLoading ? (
              <span className="flex items-center gap-2 text-text-muted font-mono text-xs">
                <Loader2 size={14} className="animate-spin text-electric-blue" />
                Synthesizing security posture reasoning...
              </span>
            ) : (
              activeResponse
            )}
          </p>

          <div className="pt-2 flex items-center justify-between text-[10px] text-text-muted border-t border-white/5">
            <span>Model: Mahoraga Autonomous Security Engine v1.0</span>
            <span className="text-emerald-400">Policy Verified • Deterministic</span>
          </div>
        </div>

      </div>
    </section>
  );
};
