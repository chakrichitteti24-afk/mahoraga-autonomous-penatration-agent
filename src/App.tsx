import React, { useState } from 'react';
import { InitializationScreen } from './components/InitializationScreen';
import { Navbar } from './components/Navbar';
import { HeroSection } from './components/HeroSection';
import { StatusPanel } from './components/StatusPanel';
import { CapabilitiesSection } from './components/CapabilitiesSection';
import { AgentWorkflow } from './components/AgentWorkflow';
import { DashboardPreview } from './components/DashboardPreview';
import { ReportPreview } from './components/ReportPreview';
import { VoiceConcept } from './components/VoiceConcept';
import { ProductStatusRoadmap } from './components/ProductStatusRoadmap';
import { Footer } from './components/Footer';
import { WaitlistModal } from './components/WaitlistModal';

export const App: React.FC = () => {
  const [initFinished, setInitFinished] = useState(false);
  const [isWaitlistOpen, setIsWaitlistOpen] = useState(false);

  return (
    <div className="min-h-screen bg-background text-text-primary selection:bg-electric-blue/30 selection:text-subtle-cyan relative overflow-x-hidden">
      
      {/* Initialization Screen (Runs ~1.8s then smoothly fades away without blocking) */}
      {!initFinished && (
        <InitializationScreen onComplete={() => setInitFinished(true)} />
      )}

      {/* Floating Glass Navbar */}
      <Navbar onOpenWaitlist={() => setIsWaitlistOpen(true)} />

      {/* Main Content Sections */}
      <main>
        {/* Hero Section with MAHORAGA AI wordmark & AI Core Visualization */}
        <HeroSection onOpenWaitlist={() => setIsWaitlistOpen(true)} />

        {/* Dedicated UNDER CONSTRUCTION System Status Panel */}
        <StatusPanel />

        {/* Capabilities Section: BUILT FOR AUTONOMOUS SECURITY */}
        <CapabilitiesSection />

        {/* Conceptual Agent Workflow Pipeline: USER -> MAHORAGA AI -> ASSESS -> ANALYZE -> PRIORITIZE -> REPORT */}
        <AgentWorkflow />

        {/* Security Assessment UI Preview (Operator Console Mockup) */}
        <DashboardPreview />

        {/* Automated Security Reports Section */}
        <ReportPreview />

        {/* Voice & NLP Agent Conceptual Interface ("Ask Mahoraga") */}
        <VoiceConcept />

        {/* Product Status & Engineering Roadmap Matrix */}
        <ProductStatusRoadmap />
      </main>

      {/* Minimal Footer */}
      <Footer />

      {/* Early Access / Update Notification Modal */}
      <WaitlistModal
        isOpen={isWaitlistOpen}
        onClose={() => setIsWaitlistOpen(false)}
      />

    </div>
  );
};

export default App;
