import React, { useState } from 'react';
import { AgentStatus } from '../types/ipc';
import { IconLock, IconRefresh } from './icons';

interface NavbarProps {
  status: AgentStatus | null;
  onLock: () => void;
  onRefresh: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  status,
  onLock,
  onRefresh,
}) => {
  const [isRotating, setIsRotating] = useState(false);

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs < 10 ? '0' : ''}${secs}s`;
  };

  const handleRefreshClick = () => {
    setIsRotating(true);
    onRefresh();
    setTimeout(() => setIsRotating(false), 600);
  };

  return (
    <header className="navbar">
      <div className="navbar-brand">
        <div className="navbar-logo-wrapper">
          <img
            src="/duckpass-logo.png"
            alt="DuckPass Logo"
            className="navbar-logo-img"
          />
          <div className="logo-ambient-glow" />
        </div>
        <div className="navbar-title-group">
          <div className="navbar-title-row">
            <h1 className="navbar-title">DuckPass</h1>
            <span className="navbar-badge">ZERO-KNOWLEDGE</span>
          </div>
          <span className="navbar-subtitle">Secure Cryptographic Vault</span>
        </div>
      </div>

      <div className="navbar-actions">
        {status?.is_unlocked && (
          <div
            className="session-badge"
            title="Auto-lock timer based on agent session"
          >
            <span className="status-dot online"></span>
            <span className="session-text">
              Auto-lock:{' '}
              <strong>{formatTime(status.timeout_remaining_seconds)}</strong>
            </span>
          </div>
        )}

        <button
          className={`btn-icon ${isRotating ? 'rotating' : ''}`}
          onClick={handleRefreshClick}
          title="Refresh vault state from daemon"
          aria-label="Refresh"
        >
          <IconRefresh size={16} />
        </button>

        {status?.is_unlocked && (
          <button
            className="btn btn-secondary btn-lock"
            onClick={onLock}
            title="Immediately lock vault and purge cryptographic keys from memory"
          >
            <IconLock size={15} />
            <span>Lock Vault</span>
          </button>
        )}
      </div>
    </header>
  );
};
