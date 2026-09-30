/**
 * Secure Clipboard Manager with automatic clearing timeout.
 *
 * Matches DuckPass core security: automatically wipes clipboard after a delay
 * (30s for passwords, 15s for OTPs) to prevent shoulder-surfing and cross-process data leakage.
 */

let activeClearTimer: ReturnType<typeof setTimeout> | null = null;
let lastCopiedSecret: string | null = null;

export const secureCopyToClipboard = async (
  text: string,
  timeoutSeconds: number = 30,
  onCleared?: () => void
): Promise<boolean> => {
  try {
    if (activeClearTimer) {
      clearTimeout(activeClearTimer);
      activeClearTimer = null;
    }

    await navigator.clipboard.writeText(text);
    lastCopiedSecret = text;

    activeClearTimer = setTimeout(async () => {
      try {
        let shouldClear = true;
        // Verify if user hasn't copied another text in the meantime
        if (navigator.clipboard && navigator.clipboard.readText) {
          try {
            const current = await navigator.clipboard.readText();
            if (current !== lastCopiedSecret) {
              shouldClear = false;
            }
          } catch {
            // Permission denied or focus lost, clear unconditionally
            shouldClear = true;
          }
        }

        if (shouldClear) {
          await navigator.clipboard.writeText('');
        }
      } catch (err) {
        console.warn('Could not clear clipboard automatically:', err);
      } finally {
        lastCopiedSecret = null;
        activeClearTimer = null;
        if (onCleared) {
          onCleared();
        }
      }
    }, timeoutSeconds * 1000);

    return true;
  } catch (err) {
    console.error('Failed to copy text to clipboard:', err);
    return false;
  }
};

// Attempt to purge clipboard if user closes/refreshes window while secret is active
if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', () => {
    if (activeClearTimer && lastCopiedSecret) {
      try {
        navigator.clipboard.writeText('');
      } catch {
        // Suppress on unload
      }
    }
  });
}
