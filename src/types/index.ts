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
  affectedUrl?: string;
  httpMethod?: string;
  affectedParameter?: string;
  cvss: string;
  cvssVersion?: string;
  cweId?: string;
  cveId?: string;
  owaspCategory?: string;
  lineNumber?: number;
  remediationSummary: string;
  remediationCode?: string;
  codeSnippet?: string;
  statusBadge: string;
  verificationStatus?: 'CONFIRMED' | 'POTENTIAL' | 'INCONCLUSIVE' | 'NOT_VULNERABLE' | 'NOT_TESTED';
  confidence?: number;
  impact?: string;
  timestamp?: string;
  suppressed?: boolean;
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
  status: 'OPERATIONAL' | 'IN DEVELOPMENT' | 'SPECIFICATION' | 'RESEARCH PHASE';
  phase: string;
  progressPercent: number;
  note: string;
}

export interface RuleDefinition {
  ruleId: string;
  ruleName: string;
  category: string;
  cweId?: string;
  defaultSeverity: string;
  cvssBase: string;
  description: string;
  detectionLogic: string;
  requiredEvidence: string;
  verificationLogic: string;
  falsePositiveConditions: string;
  remediationGuidance: string;
  references: string[];
}

export interface CoverageItem {
  category: string;
  engine: string;
  status: string;
  checksCount: number;
  notes: string;
}
