import type { SecurityFindingPreview, RuleDefinition, CoverageItem } from '../types';

const API_BASE = 'http://127.0.0.1:8000/api';

export interface HealthStatus {
  status: string;
  service: string;
  version: string;
  activeEngines: string[];
}

export interface ScanResultResponse {
  scanId: string;
  target: string;
  scanType: string;
  status: string;
  summary: {
    totalFindings: number;
    confirmedCount: number;
    potentialCount: number;
    inconclusiveCount: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    riskScore: number;
    durationSeconds: number;
  };
  findings: SecurityFindingPreview[];
  executiveSummary: string;
}

export interface AgentAskResponse {
  id: string;
  query: string;
  simulatedAgentResponse: string;
  reasoningVector: string;
  suggestedActions: string[];
  relevantFindings: SecurityFindingPreview[];
}

export const MahoragaAPI = {
  /**
   * Check if CipherFlux Labs backend server is active.
   */
  async checkHealth(): Promise<HealthStatus | null> {
    try {
      const res = await fetch(`${API_BASE}/health`, {
        signal: AbortSignal.timeout(2000),
      });
      if (res.ok) {
        return await res.json();
      }
      return null;
    } catch {
      return null;
    }
  },

  /**
   * Fetch latest findings from the backend store.
   */
  async getLatestFindings(): Promise<SecurityFindingPreview[] | null> {
    try {
      const res = await fetch(`${API_BASE}/findings/latest`, {
        signal: AbortSignal.timeout(3000),
      });
      if (res.ok) {
        return await res.json();
      }
      return null;
    } catch {
      return null;
    }
  },

  /**
   * Run a live SAST code vulnerability scan.
   */
  async scanCodeSnippet(code: string, language: string = 'auto'): Promise<ScanResultResponse | null> {
    try {
      const res = await fetch(`${API_BASE}/scan/code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawCode: code, language, authorizedBy: 'ui_operator' }),
      });
      if (res.ok) {
        return await res.json();
      }
      return null;
    } catch {
      return null;
    }
  },

  /**
   * Run a live Web Application vulnerability & posture scan against a real URL.
   */
  async scanEndpoint(targetUrl: string, options: { checkCors?: boolean; checkHeaders?: boolean; checkSsl?: boolean; checkInjection?: boolean } = {}): Promise<ScanResultResponse | null> {
    try {
      const res = await fetch(`${API_BASE}/scan/endpoint`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetUrl,
          checkCors: options.checkCors ?? true,
          checkHeaders: options.checkHeaders ?? true,
          checkSsl: options.checkSsl ?? true,
          checkInjection: options.checkInjection ?? true,
          authorizedBy: 'ui_operator',
        }),
      });
      if (res.ok) {
        return await res.json();
      }
      return null;
    } catch {
      return null;
    }
  },

  /**
   * Run a network port and service assessment on an authorized host.
   */
  async scanNetwork(targetHost: string, ports?: number[]): Promise<ScanResultResponse | null> {
    try {
      const res = await fetch(`${API_BASE}/scan/network`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetHost, ports, authorizedBy: 'ui_operator' }),
      });
      if (res.ok) {
        return await res.json();
      }
      return null;
    } catch {
      return null;
    }
  },

  /**
   * Run DNS, SPF, DMARC, and zone transfer assessment.
   */
  async scanDns(domain: string): Promise<ScanResultResponse | null> {
    try {
      const res = await fetch(`${API_BASE}/scan/dns`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, authorizedBy: 'ui_operator' }),
      });
      if (res.ok) {
        return await res.json();
      }
      return null;
    } catch {
      return null;
    }
  },

  /**
   * Run Infrastructure as Code (Dockerfile, K8s, Terraform) scan.
   */
  async scanIaC(fileType: string, rawContent: string): Promise<ScanResultResponse | null> {
    try {
      const res = await fetch(`${API_BASE}/scan/iac`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fileType, rawContent, authorizedBy: 'ui_operator' }),
      });
      if (res.ok) {
        return await res.json();
      }
      return null;
    } catch {
      return null;
    }
  },

  /**
   * Ask the autonomous agent a security question ("Ask CipherFlux").
   */
  async askAgent(query: string): Promise<AgentAskResponse | null> {
    try {
      const res = await fetch(`${API_BASE}/agent/ask`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
      });
      if (res.ok) {
        return await res.json();
      }
      return null;
    } catch {
      return null;
    }
  },

  /**
   * Retrieve active detection rule registry catalog.
   */
  async getRules(): Promise<RuleDefinition[] | null> {
    try {
      const res = await fetch(`${API_BASE}/rules`);
      if (res.ok) {
        return await res.json();
      }
      return null;
    } catch {
      return null;
    }
  },

  /**
   * Retrieve vulnerability coverage matrix.
   */
  async getCoverageMatrix(): Promise<CoverageItem[] | null> {
    try {
      const res = await fetch(`${API_BASE}/coverage`);
      if (res.ok) {
        return await res.json();
      }
      return null;
    } catch {
      return null;
    }
  },

  /**
   * Fetch a full structured audit report for a scan.
   */
  async getDetailedReport(scanId: string = 'scan-demo-baseline'): Promise<any | null> {
    try {
      const res = await fetch(`${API_BASE}/report/${encodeURIComponent(scanId)}`, {
        signal: AbortSignal.timeout(4000),
      });
      if (res.ok) {
        return await res.json();
      }
      return null;
    } catch {
      return null;
    }
  },

  /**
   * Fetch a publication-ready Markdown audit report.
   */
  async getMarkdownReport(scanId: string = 'scan-demo-baseline'): Promise<string | null> {
    try {
      const res = await fetch(`${API_BASE}/report/${encodeURIComponent(scanId)}/markdown`, {
        signal: AbortSignal.timeout(4000),
      });
      if (res.ok) {
        return await res.text();
      }
      return null;
    } catch {
      return null;
    }
  },

  /**
   * Direct download URLs for PDF and CSV deliverables.
   */
  getPdfReportUrl(scanId: string = 'scan-demo-baseline'): string {
    return `${API_BASE}/report/${encodeURIComponent(scanId)}/pdf`;
  },

  getCsvReportUrl(scanId: string = 'scan-demo-baseline'): string {
    return `${API_BASE}/report/${encodeURIComponent(scanId)}/csv`;
  },
};
