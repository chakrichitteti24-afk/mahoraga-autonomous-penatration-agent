export interface Capability {
  id: string;
  title: string;
  badge: string;
  description: string;
  iconName: string;
  metrics: string;
  status: 'IN ENGINEERING' | 'SPECIFICATION' | 'PROTOTYPING';
}

export interface WorkflowStep {
  step: string;
  title: string;
  description: string;
  status: string;
  tag: string;
}

export interface SecurityFindingPreview {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  category: string;
  targetScope: string;
  cvss: string;
  remediationSummary: string;
  statusBadge: string;
}

export interface ReportSection {
  id: string;
  title: string;
  icon: string;
  previewSummary: string;
  details: string[];
}

export interface VoicePromptDemo {
  id: string;
  query: string;
  simulatedAgentResponse: string;
  reasoningVector: string;
}

export interface SubsystemStatus {
  name: string;
  designation: string;
  status: 'IN DEVELOPMENT' | 'SPECIFICATION' | 'RESEARCH PHASE';
  phase: string;
  progressPercent: number;
  note: string;
}
