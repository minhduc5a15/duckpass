import { invoke } from '@tauri-apps/api/core';
import {
  AgentStatus,
  EntryDetail,
  EntrySummary,
  TotpResult,
} from '../types/ipc';

export const api = {
  async ping(): Promise<boolean> {
    return await invoke<boolean>('ping_agent');
  },

  async getStatus(): Promise<AgentStatus> {
    return await invoke<AgentStatus>('get_agent_status');
  },

  async unlock(masterPassword: string): Promise<void> {
    await invoke<void>('unlock_vault', { masterPassword });
  },

  async lock(): Promise<void> {
    await invoke<void>('lock_vault');
  },

  async listEntries(query: string = ''): Promise<EntrySummary[]> {
    return await invoke<EntrySummary[]>('list_entries', { query });
  },

  async getEntry(service: string): Promise<EntryDetail> {
    return await invoke<EntryDetail>('get_entry', { service });
  },

  async addEntry(entry: EntryDetail): Promise<void> {
    await invoke<void>('add_entry', { entry });
  },

  async deleteEntry(service: string): Promise<void> {
    await invoke<void>('delete_entry', { service });
  },

  async getTotp(service: string): Promise<TotpResult> {
    return await invoke<TotpResult>('get_totp', { service });
  },
};
