import React, { useState, useEffect, useMemo } from 'react';
import { EntryDetail, TotpResult } from '../types/ipc';
import { api } from '../services/api';
import {
  IconEye,
  IconEyeOff,
  IconCopy,
  IconCheck,
  IconTrash,
  IconShield,
  IconClock,
  IconKey,
} from './icons';

interface EntryDetailViewProps {
  entry: EntryDetail | null;
  loading: boolean;
  onDelete: (service: string) => void;
}

const getAvatarGradient = (service: string) => {
  const gradients = [
    'linear-gradient(135deg, #6366f1 0%, #a855f7 100%)',
    'linear-gradient(135deg, #3b82f6 0%, #06b6d4 100%)',
    'linear-gradient(135deg, #10b981 0%, #14b8a6 100%)',
    'linear-gradient(135deg, #f59e0b 0%, #ef4444 100%)',
    'linear-gradient(135deg, #ec4899 0%, #8b5cf6 100%)',
    'linear-gradient(135deg, #0284c7 0%, #4f46e5 100%)',
    'linear-gradient(135deg, #059669 0%, #10b981 100%)',
    'linear-gradient(135deg, #d97706 0%, #f59e0b 100%)',
  ];
  let hash = 0;
  for (let i = 0; i < service.length; i++) {
    hash = service.charCodeAt(i) + ((hash << 5) - hash);
  }
  const index = Math.abs(hash) % gradients.length;
  return gradients[index];
};

// Calculate entropy and strength classification
const evaluatePassword = (password: string) => {
  if (!password) return { bits: 0, label: 'Empty', score: 0, color: '#64748b' };

  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;

  const bits = Math.round(password.length * Math.log2(Math.max(poolSize, 2)));

  if (bits < 40) {
    return { bits, label: 'Weak', score: 1, color: '#ef4444' };
  } else if (bits < 60) {
    return { bits, label: 'Fair', score: 2, color: '#f59e0b' };
  } else if (bits < 80) {
    return { bits, label: 'Strong', score: 3, color: '#10b981' };
  } else {
    return { bits, label: 'Hardened', score: 4, color: '#06b6d4' };
  }
};

export const EntryDetailView: React.FC<EntryDetailViewProps> = ({
  entry,
  loading,
  onDelete,
}) => {
  const [showPassword, setShowPassword] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [totp, setTotp] = useState<TotpResult | null>(null);

  // Poll or refresh TOTP when entry changes or has secret
  useEffect(() => {
    setShowPassword(false);
    setTotp(null);

    if (!entry || !entry.totp_secret) {
      return;
    }

    let isMounted = true;

    const fetchTotp = async () => {
      try {
        const res = await api.getTotp(entry.service);
        if (isMounted) {
          setTotp(res);
        }
      } catch {
        if (isMounted) setTotp(null);
      }
    };

    fetchTotp();
    const interval = setInterval(fetchTotp, 1000);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [entry?.service, entry?.totp_secret]);

  const copyToClipboard = async (text: string, field: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 1800);
    } catch {
      // Ignore clipboard write failures
    }
  };

  const passwordEvaluation = useMemo(() => {
    return evaluatePassword(entry?.password || '');
  }, [entry?.password]);

  if (loading) {
    return (
      <main className="detail-panel loading">
        <div className="empty-state">
          <div className="spinner"></div>
          <h3 className="empty-title">Accessing Secure Memory</h3>
          <p className="empty-subtitle">
            Decrypting authenticated payload via AES-256-GCM...
          </p>
        </div>
      </main>
    );
  }

  if (!entry) {
    return (
      <main className="detail-panel empty">
        <div className="empty-state">
          <div className="empty-shield-wrapper">
            <IconShield size={44} />
            <div className="shield-halo" />
          </div>
          <h2 className="empty-title">DuckPass Vault Unlocked</h2>
          <p className="empty-subtitle">
            Select an account from the sidebar to inspect credentials or
            generate real-time 2FA codes.
          </p>
          <div className="empty-hints-grid">
            <div className="hint-card">
              <span className="hint-icon">⚡</span>
              <span className="hint-text">
                Instant zero-latency lookup via unix IPC socket
              </span>
            </div>
            <div className="hint-card">
              <span className="hint-icon">🔒</span>
              <span className="hint-text">
                Decrypted items live strictly in memory-locked pages
              </span>
            </div>
          </div>
        </div>
      </main>
    );
  }

  const formatTotpCode = (code: string) => {
    if (code.length === 6) {
      return `${code.slice(0, 3)} ${code.slice(3)}`;
    }
    return code;
  };

  const totpRemaining = totp?.remaining_seconds ?? 0;
  const totpPercent = (totpRemaining / 30) * 100;
  const isTotpExpiringSoon = totpRemaining <= 5;

  return (
    <main className="detail-panel">
      {/* Header section */}
      <div className="detail-header">
        <div
          className="detail-avatar"
          style={{ background: getAvatarGradient(entry.service) }}
        >
          {entry.service.charAt(0).toUpperCase()}
        </div>

        <div className="detail-header-text">
          <div className="detail-title-row">
            <h2 className="detail-service-title">{entry.service}</h2>
            <span className="detail-badge-cipher">AES-256-GCM</span>
          </div>
          <span className="detail-service-type">
            Zero-Knowledge Credential Record
          </span>
        </div>

        <button
          className="btn btn-danger btn-delete"
          onClick={() => onDelete(entry.service)}
          title="Permanently remove account from vault"
        >
          <IconTrash size={15} />
          <span>Delete</span>
        </button>
      </div>

      <div className="detail-cards-container">
        {/* Username Card */}
        <div className="field-card">
          <div className="field-label-row">
            <span className="field-label">Username / Email</span>
          </div>
          <div className="field-value-row">
            <span className="field-text user-select-text">
              {entry.username || '—'}
            </span>
            <button
              className={`btn btn-secondary btn-copy ${
                copiedField === 'username' ? 'copied' : ''
              }`}
              onClick={() => copyToClipboard(entry.username, 'username')}
              disabled={!entry.username}
            >
              {copiedField === 'username' ? (
                <>
                  <IconCheck size={14} />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <IconCopy size={14} />
                  <span>Copy</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Password Card */}
        <div className="field-card">
          <div className="field-label-row">
            <span className="field-label">Password</span>
            <div
              className="password-entropy-tag"
              style={{ color: passwordEvaluation.color }}
            >
              <span>{passwordEvaluation.label}</span>
              <span className="entropy-bits">
                ({passwordEvaluation.bits} bits)
              </span>
            </div>
          </div>

          <div className="field-value-row">
            <span
              className={`field-text field-password user-select-text ${!showPassword ? 'masked' : ''}`}
            >
              {showPassword ? entry.password : '••••••••••••••••'}
            </span>

            <div className="field-actions">
              <button
                className="btn-icon"
                onClick={() => setShowPassword(!showPassword)}
                title={showPassword ? 'Hide password' : 'Reveal password'}
              >
                {showPassword ? (
                  <IconEyeOff size={16} />
                ) : (
                  <IconEye size={16} />
                )}
              </button>
              <button
                className={`btn btn-secondary btn-copy ${
                  copiedField === 'password' ? 'copied' : ''
                }`}
                onClick={() => copyToClipboard(entry.password, 'password')}
              >
                {copiedField === 'password' ? (
                  <>
                    <IconCheck size={14} />
                    <span>Copied</span>
                  </>
                ) : (
                  <>
                    <IconCopy size={14} />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Password strength segments */}
          <div className="password-strength-track">
            {[1, 2, 3, 4].map((seg) => (
              <div
                key={seg}
                className="password-strength-segment"
                style={{
                  backgroundColor:
                    seg <= passwordEvaluation.score
                      ? passwordEvaluation.color
                      : 'rgba(255, 255, 255, 0.08)',
                }}
              />
            ))}
          </div>
        </div>

        {/* Two-Factor Authentication (TOTP) Card */}
        {entry.totp_secret ? (
          <div
            className={`field-card field-totp-card ${isTotpExpiringSoon ? 'totp-warning' : ''}`}
          >
            <div className="totp-card-header">
              <div className="totp-header-left">
                <IconClock size={16} className="totp-clock-icon" />
                <span className="field-label totp-label">
                  Two-Factor Authentication (TOTP)
                </span>
              </div>
              {totp && (
                <div
                  className={`totp-timer-pill ${isTotpExpiringSoon ? 'expiring' : ''}`}
                >
                  <span>{totpRemaining}s remaining</span>
                </div>
              )}
            </div>

            <div className="totp-code-display-row">
              <div className="totp-code-wrapper">
                <span className="totp-code">
                  {totp ? formatTotpCode(totp.code) : '••• •••'}
                </span>
              </div>

              <button
                className={`btn btn-primary btn-copy-totp ${
                  copiedField === 'totp' ? 'copied' : ''
                }`}
                onClick={() => totp && copyToClipboard(totp.code, 'totp')}
                disabled={!totp}
              >
                {copiedField === 'totp' ? (
                  <>
                    <IconCheck size={16} />
                    <span>Copied Code</span>
                  </>
                ) : (
                  <>
                    <IconCopy size={16} />
                    <span>Copy Code</span>
                  </>
                )}
              </button>
            </div>

            {/* TOTP Progress bar */}
            <div className="totp-progress-track">
              <div
                className={`totp-progress-bar ${isTotpExpiringSoon ? 'warning' : ''}`}
                style={{ width: `${totpPercent}%` }}
              />
            </div>
          </div>
        ) : (
          <div className="field-card field-card-secondary-info">
            <div className="field-label-row">
              <span className="field-label">Two-Factor Authentication</span>
            </div>
            <div className="field-value-row">
              <span className="field-text text-muted">
                No 2FA secret configured for this account
              </span>
            </div>
          </div>
        )}

        {/* Metadata info strip */}
        <div className="credential-meta-strip">
          <div className="meta-strip-item">
            <IconKey size={13} />
            <span>Encrypted with Master Key derivation salt</span>
          </div>
          <div className="meta-strip-item">
            <IconShield size={13} />
            <span>IPC payload protected against heap dumps</span>
          </div>
        </div>
      </div>
    </main>
  );
};
