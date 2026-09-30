/**
 * Advanced Client-Side Password Strength & Pattern Evaluator.
 *
 * Mitigates the naive length*log2(pool) vulnerability by:
 * 1. Penalizing common dictionary words and repeated tokens.
 * 2. Identifying keyboard and sequential patterns.
 * 3. Detecting single-character repeats.
 * 4. Calculating effective entropy bits and realistic threat ratings.
 */

export interface PasswordEvaluation {
  bits: number;
  label: 'Empty' | 'Very Weak' | 'Weak' | 'Fair' | 'Strong' | 'Hardened';
  score: number; // 0 (Very Weak) to 4 (Hardened)
  color: string;
  warning?: string;
}

const COMMON_DICTIONARY_PATTERNS = [
  'password',
  '123456',
  'qwerty',
  'admin',
  'welcome',
  'letmein',
  'monkey',
  'dragon',
  'football',
  'master',
  'secret',
  'access',
  'duckpass',
  'login',
  'iloveyou',
  'computer',
  'trustno1',
  'shadow',
  'superman',
  'batman',
  'pass',
];

const KEYBOARD_SEQUENCES = [
  '1234567890',
  '0987654321',
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm',
];

export const evaluatePassword = (password: string): PasswordEvaluation => {
  if (!password) {
    return { bits: 0, label: 'Empty', score: 0, color: '#64748b' };
  }

  const len = password.length;
  const lower = password.toLowerCase();

  // 1. Check for immediate repeat of identical characters e.g. "11111111", "aaaaaaaa"
  const uniqueChars = new Set(password).size;
  if (uniqueChars === 1) {
    return {
      bits: Math.round(Math.log2(len + 1)),
      label: 'Very Weak',
      score: 0,
      color: '#ef4444',
      warning: 'Password consists of a single repeating character.',
    };
  }

  // 2. Check for common dictionary words & collapse them to calculate effective sanitized length
  let sanitized = lower;
  const dictionaryMatches: string[] = [];
  for (const pat of COMMON_DICTIONARY_PATTERNS) {
    if (sanitized.includes(pat)) {
      dictionaryMatches.push(pat);
      sanitized = sanitized.split(pat).join('_');
    }
  }

  // 3. Check for keyboard sequences e.g. "qwerty", "asdfgh", "12345"
  let hasSequence = false;
  for (const seq of KEYBOARD_SEQUENCES) {
    for (let i = 0; i <= seq.length - 4; i++) {
      const sub = seq.substring(i, i + 4);
      if (lower.includes(sub)) {
        hasSequence = true;
        sanitized = sanitized.split(sub).join('#');
      }
    }
  }

  // 4. Character diversity pool
  let poolSize = 0;
  let hasLower = false;
  let hasUpper = false;
  let hasDigit = false;
  let hasSpecial = false;

  if (/[a-z]/.test(password)) {
    poolSize += 26;
    hasLower = true;
  }
  if (/[A-Z]/.test(password)) {
    poolSize += 26;
    hasUpper = true;
  }
  if (/[0-9]/.test(password)) {
    poolSize += 10;
    hasDigit = true;
  }
  if (/[^a-zA-Z0-9]/.test(password)) {
    poolSize += 33;
    hasSpecial = true;
  }

  // Effective length accounts for patterns collapsed into single symbols
  const effectiveLength = Math.max(
    1,
    sanitized.length + dictionaryMatches.length
  );
  let rawBits = effectiveLength * Math.log2(Math.max(poolSize, 2));

  // If dictionary patterns were found, apply steep penalty
  if (dictionaryMatches.length > 0) {
    rawBits *= Math.pow(0.65, dictionaryMatches.length);
  }
  if (hasSequence) {
    rawBits *= 0.7;
  }

  // Deduct penalty for low character diversity in longer passwords
  const diversityCount =
    (hasLower ? 1 : 0) +
    (hasUpper ? 1 : 0) +
    (hasDigit ? 1 : 0) +
    (hasSpecial ? 1 : 0);
  if (len > 8 && diversityCount <= 1) {
    rawBits *= 0.5; // 50% penalty for single character set
  } else if (len > 10 && diversityCount === 2) {
    rawBits *= 0.75; // 25% penalty
  }

  // Deduct penalty for high frequency of identical characters
  const repeatRatio = 1 - uniqueChars / len;
  if (repeatRatio > 0.4) {
    rawBits *= 1 - repeatRatio * 0.6;
  }

  const finalBits = Math.max(0, Math.round(rawBits));

  let warning: string | undefined;
  if (dictionaryMatches.length > 0) {
    warning = `Contains dictionary word "${dictionaryMatches[0]}".`;
  } else if (hasSequence) {
    warning = 'Contains sequential keyboard pattern.';
  }

  if (finalBits < 30 || len < 6) {
    return {
      bits: finalBits,
      label: 'Very Weak',
      score: 0,
      color: '#ef4444',
      warning,
    };
  } else if (finalBits < 50 || len < 8) {
    return {
      bits: finalBits,
      label: 'Weak',
      score: 1,
      color: '#f97316',
      warning,
    };
  } else if (finalBits < 70 || len < 12) {
    return {
      bits: finalBits,
      label: 'Fair',
      score: 2,
      color: '#f59e0b',
      warning,
    };
  } else if (finalBits < 90 || len < 16) {
    return {
      bits: finalBits,
      label: 'Strong',
      score: 3,
      color: '#10b981',
      warning,
    };
  } else {
    return {
      bits: finalBits,
      label: 'Hardened',
      score: 4,
      color: '#06b6d4',
      warning,
    };
  }
};
