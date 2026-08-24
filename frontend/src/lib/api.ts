export const API_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export type Finding = {
  id?: number;
  vulnerability: string;
  endpoint: string;
  parameter?: string | null;
  severity: string;
  confidence: number;
  cwe: string;
  evidence: string;
  detection_method: string;
  exploitation_performed: boolean;
  recommendation: string;
  difficulty: string;
  assessment_mode: string;
};

export type ScanSummary = {
  id: number;
  target: string;
  mode: string;
  difficulty: string;
  status: string;
  security_score: number;
  finding_count: number;
  created_at: string;
};

export type ScanDetails = ScanSummary & {
  modules: string[];
  findings: Finding[];
  whitebox_hits: {
    id?: number;
    scan_id?: number;
    category: string;
    file: string;
    pattern: string;
  }[];
  detector_errors: {
    module: string;
    error: string;
  }[];
  crawl: {
    visited_pages?: number;
    endpoints?: {
      path: string;
      method: string;
    }[];
    parameters?: string[];
    forms?: unknown[];
  };
};

export async function getScans(): Promise<ScanSummary[]> {
  const response = await fetch(`${API_URL}/scans`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error("Unable to load scans");
  }

  const data = await response.json();

  return data.scans || [];
}

export async function getScan(id: number): Promise<ScanDetails> {
  const response = await fetch(`${API_URL}/scans/${id}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error("Unable to load scan");
  }

  return response.json();
}

export async function startScan(body: {
  target: string;
  mode: "blackbox" | "whitebox";
  difficulty: "easy" | "medium" | "hard" | "expert";
  modules: string[];
  source_path?: string;
}) {
  const response = await fetch(`${API_URL}/scans`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.detail || "Scan failed");
  }

  return data;
}

export function reportUrl(id: number) {
  return `${API_URL}/reports/${id}`;
}
