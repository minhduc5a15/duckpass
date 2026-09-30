import React from 'react';
import { EntrySummary } from '../types/ipc';
import { IconSearch, IconPlus, IconX, IconShield } from './icons';

interface EntryListProps {
  entries: EntrySummary[];
  selectedService: string | null;
  searchQuery: string;
  loading?: boolean;
  onSearchChange: (q: string) => void;
  onSelect: (service: string) => void;
  onAddNew: () => void;
}

// Generate consistent vibrant color gradients based on service name string
const getAvatarGradient = (service: string) => {
  const gradients = [
    'linear-gradient(135deg, #6366f1 0%, #a855f7 100%)', // Indigo to Purple
    'linear-gradient(135deg, #3b82f6 0%, #06b6d4 100%)', // Blue to Cyan
    'linear-gradient(135deg, #10b981 0%, #14b8a6 100%)', // Emerald to Teal
    'linear-gradient(135deg, #f59e0b 0%, #ef4444 100%)', // Amber to Red
    'linear-gradient(135deg, #ec4899 0%, #8b5cf6 100%)', // Pink to Violet
    'linear-gradient(135deg, #0284c7 0%, #4f46e5 100%)', // Sky to Indigo
    'linear-gradient(135deg, #059669 0%, #10b981 100%)', // Green to Emerald
    'linear-gradient(135deg, #d97706 0%, #f59e0b 100%)', // Orange to Amber
  ];
  let hash = 0;
  for (let i = 0; i < service.length; i++) {
    hash = service.charCodeAt(i) + ((hash << 5) - hash);
  }
  const index = Math.abs(hash) % gradients.length;
  return gradients[index];
};

export const EntryList: React.FC<EntryListProps> = ({
  entries,
  selectedService,
  searchQuery,
  loading = false,
  onSearchChange,
  onSelect,
  onAddNew,
}) => {
  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="search-bar-wrapper">
          <span className="search-icon">
            <IconSearch size={15} />
          </span>
          <input
            type="text"
            className="search-input"
            placeholder="Search accounts..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
          />
          {searchQuery ? (
            <button
              className="btn-clear-search"
              onClick={() => onSearchChange('')}
              title="Clear search"
            >
              <IconX size={13} />
            </button>
          ) : (
            <span className="search-shortcut-hint">/</span>
          )}
        </div>

        <button className="btn btn-primary btn-add" onClick={onAddNew}>
          <IconPlus size={16} />
          <span>New Account</span>
        </button>
      </div>

      <div className="entries-count-bar">
        <span className="entries-count-label">VAULT ITEMS</span>
        <span className="badge-count">{entries.length}</span>
      </div>

      <div className="entry-list-scroll">
        {loading ? (
          <div className="empty-list-placeholder">
            <div className="spinner-sm"></div>
            <p className="placeholder-text">Searching vault entries...</p>
          </div>
        ) : entries.length === 0 ? (
          <div className="empty-list-placeholder">
            <div className="empty-icon-circle">
              <IconShield size={24} />
            </div>
            <p className="empty-title">
              {searchQuery ? 'No matching accounts' : 'Vault is empty'}
            </p>
            <p className="empty-subtitle">
              {searchQuery
                ? 'Try searching for a different service name'
                : 'Add your first encrypted account credential'}
            </p>
            {!searchQuery && (
              <button
                className="btn btn-secondary btn-empty-action"
                onClick={onAddNew}
              >
                <IconPlus size={14} />
                <span>Create Entry</span>
              </button>
            )}
          </div>
        ) : (
          entries.map((entry) => {
            const isSelected = selectedService === entry.service;
            return (
              <div
                key={entry.service}
                className={`entry-card ${isSelected ? 'active' : ''}`}
                onClick={() => onSelect(entry.service)}
              >
                <div
                  className="entry-card-avatar"
                  style={{ background: getAvatarGradient(entry.service) }}
                >
                  {entry.service.charAt(0).toUpperCase()}
                </div>
                <div className="entry-card-info">
                  <span className="entry-card-service">{entry.service}</span>
                  <span className="entry-card-username">
                    {entry.username || 'No username'}
                  </span>
                </div>
                <div className="entry-card-active-indicator" />
              </div>
            );
          })
        )}
      </div>
    </aside>
  );
};
