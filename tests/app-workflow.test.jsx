import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from '@/components/App';

const mocks = vi.hoisted(() => ({
  ensureReadAccess: vi.fn(),
  ensureWriteAccess: vi.fn(),
  fetchAllFiles: vi.fn(),
  getUserInfo: vi.fn(),
  requestReadAccess: vi.fn(),
  requestWriteAccess: vi.fn(),
}));

vi.mock('next/navigation', () => ({
  usePathname: () => '/app',
  useRouter: () => ({ replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock('next/script', () => ({ default: () => null }));
vi.mock('next/dynamic', () => ({ default: () => () => null }));
vi.mock('@/components/Header', () => ({ default: () => null }));
vi.mock('@/components/Footer', () => ({ default: () => null }));
vi.mock('@/lib/auth', () => ({
  hasWriteAccess: () => false,
  initAuth: vi.fn(),
  invalidateAuth: vi.fn(),
  isAuthExpiredError: (error) => error?.code === 'AUTH_EXPIRED',
  ensureReadAccess: mocks.ensureReadAccess,
  ensureWriteAccess: mocks.ensureWriteAccess,
  requestReadAccess: mocks.requestReadAccess,
  requestWriteAccess: mocks.requestWriteAccess,
  signOut: vi.fn(),
}));
vi.mock('@/lib/drive', () => ({
  clearFolderCache: vi.fn(),
  getUserInfo: mocks.getUserInfo,
  fetchAllFiles: mocks.fetchAllFiles,
}));
vi.mock('@/lib/preview', () => ({ clearPreviewCache: vi.fn() }));
vi.mock('@/lib/state', () => ({
  getSettings: () => ({ dupesFolder: '_dupes', batchSize: 10 }),
  purgeAppBrowserData: vi.fn(() => Promise.resolve()),
}));
vi.mock('@/lib/analytics', () => ({
  trackEvent: vi.fn(),
  trackException: vi.fn(),
}));

async function signInAndStartScan() {
  fireEvent.click(screen.getByRole('button', { name: /sign in with google/i }));
  const startButton = await screen.findByRole('button', { name: /start scan/i });
  fireEvent.click(startButton);
}

describe('top-level scan outcomes', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.requestReadAccess.mockResolvedValue('token');
    mocks.ensureReadAccess.mockResolvedValue('token');
    mocks.getUserInfo.mockResolvedValue({
      displayName: 'Drive User',
      emailAddress: 'drive@example.com',
    });
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  it('returns a signed-in user to Account with a success notice after a zero-result scan', async () => {
    mocks.fetchAllFiles.mockResolvedValue([]);
    render(<App />);

    await signInAndStartScan();

    expect(await screen.findByText('No duplicates found. Your Drive was left unchanged.')).toBeInTheDocument();
    expect(screen.getByText('Drive User')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /start scan/i })).toBeEnabled();
  });

  it('returns a signed-in user to Account with a retry message after a non-auth scan failure', async () => {
    mocks.fetchAllFiles.mockRejectedValue(new Error('Drive unavailable'));
    render(<App />);

    await signInAndStartScan();

    await waitFor(() => {
      expect(screen.getByText('Scan failed: Drive unavailable. You can try again.')).toBeInTheDocument();
    });
    expect(screen.getByText('Drive User')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /start scan/i })).toBeEnabled();
  });
});
