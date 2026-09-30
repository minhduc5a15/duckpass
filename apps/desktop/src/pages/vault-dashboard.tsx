import React, { useState, useEffect, useCallback } from 'react';
import { AgentStatus, EntryDetail, EntrySummary } from '../types/ipc';
import { api } from '../services/api';
import { Navbar } from '../components/navbar';
import { EntryList } from '../components/entry-list';
import { EntryDetailView } from '../components/entry-detail-view';
import { AddEntryModal } from '../components/add-entry-modal';
import { UnlockPage } from './unlock-page';
import {
  IconAlertTriangle,
  IconRefresh,
  IconTerminal,
  IconCopy,
  IconCheck,
} from '../components/icons';

import { isTauri } from '@tauri-apps/api/core';

export const VaultDashboard: React.FC = () => {
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [selectedService, setSelectedService] = useState<string | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<EntryDetail | null>(
    null
  );
  const [searchQuery, setSearchQuery] = useState('');
  const [loadingEntries, setLoadingEntries] = useState(false);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [agentOffline, setAgentOffline] = useState(false);
  const [offlineType, setOfflineType] = useState<'browser' | 'daemon'>(
    'daemon'
  );
  const [offlineError, setOfflineError] = useState<string | null>(null);
  const [commandCopied, setCommandCopied] = useState(false);

  const fetchStatus = useCallback(async () => {
    if (!isTauri()) {
      setAgentOffline(true);
      setOfflineType('browser');
      setOfflineError(
        'Đang mở trong trình duyệt Web thông thường (thiếu Tauri IPC runtime).'
      );
      return null;
    }

    try {
      const s = await api.getStatus();
      setStatus(s);
      setAgentOffline(false);
      setOfflineError(null);
      return s;
    } catch (err: unknown) {
      console.error('fetchStatus failed:', err);
      setOfflineType('daemon');
      setOfflineError(err instanceof Error ? err.message : String(err));
      setAgentOffline(true);
      return null;
    }
  }, []);

  const fetchEntries = useCallback(async (query: string = '') => {
    try {
      setLoadingEntries(true);
      const list = await api.listEntries(query);
      setEntries(list);
    } catch {
      setEntries([]);
    } finally {
      setLoadingEntries(false);
    }
  }, []);

  const handleSelectService = async (service: string) => {
    setSelectedService(service);
    try {
      setLoadingDetail(true);
      const detail = await api.getEntry(service);
      setSelectedDetail(detail);
    } catch {
      setSelectedDetail(null);
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleLock = async () => {
    try {
      await api.lock();
      setSelectedService(null);
      setSelectedDetail(null);
      setEntries([]);
      await fetchStatus();
    } catch {
      // Ignore error during lock
    }
  };

  const handleDelete = async (service: string) => {
    if (
      !confirm(
        `Are you sure you want to permanently delete credentials for '${service}'?`
      )
    ) {
      return;
    }
    try {
      await api.deleteEntry(service);
      setSelectedService(null);
      setSelectedDetail(null);
      await fetchEntries(searchQuery);
      await fetchStatus();
    } catch (err: unknown) {
      alert(
        `Delete failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  };

  const handleAddSubmit = async (entry: EntryDetail) => {
    await api.addEntry(entry);
    await fetchEntries(searchQuery);
    await fetchStatus();
    await handleSelectService(entry.service);
  };

  const copyCommand = async (cmd: string) => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCommandCopied(true);
      setTimeout(() => setCommandCopied(false), 2000);
    } catch {
      // Ignore
    }
  };

  // Initial load
  useEffect(() => {
    const init = async () => {
      const s = await fetchStatus();
      if (s?.is_unlocked) {
        await fetchEntries();
      }
    };
    init();

    // Auto status poll every 2s
    const statusInterval = setInterval(fetchStatus, 2000);
    return () => clearInterval(statusInterval);
  }, [fetchStatus, fetchEntries]);

  // Debounced search
  useEffect(() => {
    if (!status?.is_unlocked) return;
    const timer = setTimeout(() => {
      fetchEntries(searchQuery);
    }, 200);
    return () => clearTimeout(timer);
  }, [searchQuery, status?.is_unlocked, fetchEntries]);

  if (agentOffline) {
    const isBrowser = offlineType === 'browser';
    return (
      <div className="offline-screen">
        <div className="ambient-background-glow glow-top" />
        <div className="unlock-card offline-card">
          <div className="hero-logo-frame offline-logo-frame">
            <img
              src="/duckpass-logo.png"
              alt="DuckPass Logo"
              className="unlock-hero-logo dimmed"
            />
            <div className="offline-badge-icon">
              <IconAlertTriangle size={20} />
            </div>
          </div>
          <h1 className="unlock-title">
            {isBrowser ? 'Web Browser Detected' : 'Agent Daemon Offline'}
          </h1>
          <p className="unlock-description">
            {isBrowser
              ? 'Trình duyệt web không thể truy cập Unix domain socket IPC (/run/user/1000/duckpass.sock). Cần khởi chạy bằng ứng dụng Desktop (Tauri).'
              : 'The secure DuckPass background agent is not running. Launch the agent daemon to establish an IPC socket session.'}
          </p>

          {offlineError && !isBrowser && (
            <div
              className="alert-error"
              style={{ margin: '10px 0', fontSize: 11.5 }}
            >
              <span className="alert-icon">⚠️</span>
              <span className="alert-text">{offlineError}</span>
            </div>
          )}

          <div className="terminal-command-box">
            <div className="terminal-header">
              <span className="terminal-dots">
                <span className="dot red" />
                <span className="dot yellow" />
                <span className="dot green" />
              </span>
              <span
                className="terminal-title"
                style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}
              >
                <IconTerminal size={12} />
                <span>bash</span>
              </span>
              <button
                className="btn-copy-command"
                onClick={() =>
                  copyCommand(
                    isBrowser ? 'bun run tauri dev' : 'duckpass agent start'
                  )
                }
                title="Copy command to clipboard"
              >
                {commandCopied ? (
                  <IconCheck size={14} />
                ) : (
                  <IconCopy size={14} />
                )}
                <span>{commandCopied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <div className="terminal-body">
              <span className="terminal-prompt">$</span>
              <code>
                {isBrowser ? 'bun run tauri dev' : 'duckpass agent start'}
              </code>
            </div>
          </div>

          <button className="btn btn-primary btn-retry" onClick={fetchStatus}>
            <IconRefresh size={16} />
            <span>
              {isBrowser ? 'Check Desktop Runtime' : 'Retry IPC Connection'}
            </span>
          </button>
        </div>
      </div>
    );
  }

  if (!status?.is_unlocked) {
    return (
      <UnlockPage
        onUnlocked={async () => {
          await fetchStatus();
          await fetchEntries();
        }}
      />
    );
  }

  return (
    <div className="dashboard-layout">
      <Navbar status={status} onLock={handleLock} onRefresh={fetchStatus} />

      <div className="dashboard-content">
        <EntryList
          entries={entries}
          selectedService={selectedService}
          searchQuery={searchQuery}
          loading={loadingEntries}
          onSearchChange={setSearchQuery}
          onSelect={handleSelectService}
          onAddNew={() => setIsAddModalOpen(true)}
        />

        <EntryDetailView
          entry={selectedDetail}
          loading={loadingDetail}
          onDelete={handleDelete}
        />
      </div>

      <AddEntryModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSubmit={handleAddSubmit}
      />
    </div>
  );
};
