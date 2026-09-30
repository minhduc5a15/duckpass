import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import {
  IconUnlock,
  IconEye,
  IconEyeOff,
  IconShield,
  IconKey,
  IconLock,
} from '../components/icons';

interface UnlockPageProps {
  onUnlocked: () => void;
}

export const UnlockPage: React.FC<UnlockPageProps> = ({ onUnlocked }) => {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unlocking, setUnlocking] = useState(false);
  const [capsLockActive, setCapsLockActive] = useState(false);
  const [shake, setShake] = useState(false);

  useEffect(() => {
    const handleKeyUp = (e: KeyboardEvent) => {
      setCapsLockActive(e.getModifierState('CapsLock'));
    };
    window.addEventListener('keyup', handleKeyUp);
    return () => window.removeEventListener('keyup', handleKeyUp);
  }, []);

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password) {
      setError('Please enter your master password to unlock');
      triggerShake();
      return;
    }

    try {
      setUnlocking(true);
      setError(null);
      await api.unlock(password);
      setPassword('');
      onUnlocked();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
      triggerShake();
    } finally {
      setUnlocking(false);
    }
  };

  const triggerShake = () => {
    setShake(true);
    setTimeout(() => setShake(false), 500);
  };

  return (
    <div className="unlock-screen">
      <div className="ambient-background-glow glow-top" />
      <div className="ambient-background-glow glow-bottom" />

      <div className={`unlock-card ${shake ? 'card-shake' : ''}`}>
        <div className="unlock-hero">
          <div className="hero-logo-frame">
            <img
              src="/duckpass-logo.png"
              alt="DuckPass Logo"
              className="unlock-hero-logo"
            />
            <div className="hero-logo-halo" />
          </div>
          <h1 className="unlock-title">DuckPass Vault</h1>
          <p className="unlock-description">
            Your encrypted vault is locked. Authenticate with your master
            password to derive cryptographic keys into protected memory.
          </p>
        </div>

        <form onSubmit={handleUnlock} className="unlock-form">
          {error && (
            <div className="alert-error">
              <span className="alert-icon">⚠️</span>
              <span className="alert-text">{error}</span>
            </div>
          )}

          <div className="input-field-group">
            <div className="input-wrapper">
              <span className="input-prefix-icon">
                <IconKey size={16} />
              </span>
              <input
                type={showPassword ? 'text' : 'password'}
                className="unlock-input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter Master Password"
                autoFocus
                disabled={unlocking}
                onKeyDown={(e) =>
                  setCapsLockActive(e.getModifierState('CapsLock'))
                }
              />
              <button
                type="button"
                className="input-suffix-btn"
                onClick={() => setShowPassword(!showPassword)}
                title={showPassword ? 'Hide password' : 'Show password'}
                tabIndex={-1}
              >
                {showPassword ? (
                  <IconEyeOff size={16} />
                ) : (
                  <IconEye size={16} />
                )}
              </button>
            </div>

            {capsLockActive && (
              <div className="capslock-warning">
                <span>⚠️ Caps Lock is ON</span>
              </div>
            )}
          </div>

          <button
            type="submit"
            className="btn btn-primary btn-unlock"
            disabled={unlocking}
          >
            {unlocking ? (
              <span className="btn-loading-content">
                <span className="spinner-sm" />
                <span>Deriving Key (Argon2id)...</span>
              </span>
            ) : (
              <span className="btn-icon-content">
                <IconUnlock size={16} />
                <span>Unlock Vault</span>
              </span>
            )}
          </button>
        </form>

        <div className="security-badges-row">
          <div
            className="security-badge-item"
            title="RFC 9106 Argon2id 19 MiB Memory-Hard KDF"
          >
            <IconShield size={14} />
            <span>Argon2id KDF</span>
          </div>
          <div className="security-badge-divider">•</div>
          <div
            className="security-badge-item"
            title="OpenSSL SECURE_MALLOC mlock protected pages"
          >
            <IconLock size={14} />
            <span>Secure Heap</span>
          </div>
          <div className="security-badge-divider">•</div>
          <div
            className="security-badge-item"
            title="Zero unencrypted credentials written to disk"
          >
            <IconKey size={14} />
            <span>Zero-Disk Leakage</span>
          </div>
        </div>
      </div>
    </div>
  );
};
