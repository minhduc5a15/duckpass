export interface AgentStatus {
  is_unlocked: boolean;
  timeout_remaining_seconds: number;
  total_entries: number;
}

export interface EntrySummary {
  service: string;
  username: string;
}

export interface EntryDetail {
  service: string;
  username: string;
  password: string;
  totp_secret: string;
}

export interface TotpResult {
  code: string;
  remaining_seconds: number;
}
