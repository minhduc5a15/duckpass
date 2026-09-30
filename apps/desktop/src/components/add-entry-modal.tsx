import React, { useState } from 'react';
import { EntryDetail } from '../types/ipc';
import {
  IconX,
  IconKey,
  IconEye,
  IconEyeOff,
  IconSparkles,
  IconCheck,
} from './icons';

interface AddEntryModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (entry: EntryDetail) => Promise<void>;
}

// Generate cryptographically secure random password
const generateSecurePassword = (length: number = 22): string => {
  const charset =
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}';
  const array = new Uint32Array(length);
  window.crypto.getRandomValues(array);
  let res = '';
  for (let i = 0; i < length; i++) {
    res += charset[array[i] % charset.length];
  }
  return res;
};

export const AddEntryModal: React.FC<AddEntryModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
}) => {
  const [service, setService] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totpSecret, setTotpSecret] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [generatedNotif, setGeneratedNotif] = useState(false);

  if (!isOpen) return null;

  const handleGeneratePassword = () => {
    const pw = generateSecurePassword(22);
    setPassword(pw);
    setShowPassword(true);
    setGeneratedNotif(true);
    setTimeout(() => setGeneratedNotif(false), 2000);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!service.trim()) {
      setError('Service name is required');
      return;
    }
    if (!username.trim()) {
      setError('Username or email is required');
      return;
    }
    if (!password) {
      setError('Password cannot be empty');
      return;
    }

    try {
      setSubmitting(true);
      setError(null);
      await onSubmit({
        service: service.trim(),
        username: username.trim(),
        password,
        totp_secret: totpSecret.trim().toUpperCase(),
      });
      // Reset form
      setService('');
      setUsername('');
      setPassword('');
      setTotpSecret('');
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-group">
            <div className="modal-icon-badge">
              <IconKey size={18} />
            </div>
            <div>
              <h3 className="modal-title">New Account Credential</h3>
              <p className="modal-subtitle">
                Store encrypted credentials into DuckPass vault
              </p>
            </div>
          </div>
          <button className="btn-icon modal-close-btn" onClick={onClose}>
            <IconX size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="modal-form">
          {error && (
            <div className="alert-error">
              <span className="alert-icon">⚠️</span>
              <span className="alert-text">{error}</span>
            </div>
          )}

          <div className="form-group">
            <label className="form-label">
              Service Identifier <span className="required-star">*</span>
            </label>
            <input
              type="text"
              className="form-input"
              value={service}
              onChange={(e) => setService(e.target.value)}
              placeholder="e.g. github.com, proton.me, aws"
              autoFocus
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">
              Username / Email <span className="required-star">*</span>
            </label>
            <input
              type="text"
              className="form-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. user@example.com"
              required
            />
          </div>

          <div className="form-group">
            <div className="form-label-row">
              <label className="form-label">
                Password <span className="required-star">*</span>
              </label>
              <button
                type="button"
                className="btn-link-action"
                onClick={handleGeneratePassword}
              >
                {generatedNotif ? (
                  <>
                    <IconCheck size={13} />
                    <span>Generated!</span>
                  </>
                ) : (
                  <>
                    <IconSparkles size={13} />
                    <span>Generate Strong</span>
                  </>
                )}
              </button>
            </div>
            <div className="input-with-actions">
              <input
                type={showPassword ? 'text' : 'password'}
                className="form-input input-mono"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter or generate password"
                required
              />
              <button
                type="button"
                className="input-inline-btn"
                onClick={() => setShowPassword(!showPassword)}
                title={showPassword ? 'Hide password' : 'Show password'}
                tabIndex={-1}
              >
                {showPassword ? (
                  <IconEyeOff size={15} />
                ) : (
                  <IconEye size={15} />
                )}
              </button>
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">
              2FA / TOTP Secret Key{' '}
              <span className="label-optional">(Optional Base32)</span>
            </label>
            <input
              type="text"
              className="form-input input-mono"
              value={totpSecret}
              onChange={(e) => setTotpSecret(e.target.value)}
              placeholder="e.g. JBSWY3DPEHPK3PXP"
            />
          </div>

          <div className="modal-actions">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onClose}
              disabled={submitting}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={submitting}
            >
              {submitting ? 'Encrypting & Saving...' : 'Save Credential'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
