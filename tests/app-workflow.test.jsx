import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from '@/components/App';

const mocks = vi.hoisted(() => ({
  ensureReadAccess: vi.fn(),
  ensureWriteAccess: vi.fn(),
  fetchAllFiles: vi.fn(),
  getDriveRootId: vi.fn(),
  getSettings: vi.fn(),
  getUserInfo: vi.fn(),
  initAuth: vi.fn(),
  requestReadAccess: vi.fn(),
  requestWriteAccess: vi.fn(),
  saveSettings: vi.fn(),
}));

const FOLDER = 'application/vnd.google-apps.folder';

vi.mock('next/navigation', () => ({
  usePathname: () => '/app',
  useRouter: () => ({ replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock('next/script', () => ({
  default: ({ onLoad, onError }) => (
    <div>
      <button data-testid="gsi-load" onClick={onLoad}>Load GIS</button>
      <button data-testid="gsi-error" onClick={onError}>Fail GIS</button>
    </div>
  ),
}));
vi.mock('next/dynamic', () => {
  let dynamicIndex = 0;
  return {
    default: () => {
      const componentIndex = dynamicIndex++;
      if (componentIndex === 1) {
        return function ReviewStub({ decisions, dupGroups, onDecision, onExecute, workflowError }) {
          const group = dupGroups[0];
          return (
            <div>
              {workflowError && <div role="alert">{workflowError}</div>}
              <div>Decision count: {Object.keys(decisions).length}</div>
              <button
                onClick={() => onDecision(group.md5, {
                  action: 'discard',
                  discardIds: group.files.map((file) => file.id),
                })}
              >
                Set unsafe decision
              </button>
              <button onClick={onExecute}>Attempt execute</button>
            </div>
          );
        };
      }
      return () => null;
    },
  };
});
vi.mock('@/components/Header', () => ({ default: () => null }));
vi.mock('@/components/Footer', () => ({ default: () => null }));
vi.mock('@/lib/auth', () => ({
  hasWriteAccess: () => false,
  initAuth: mocks.initAuth,
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
  getDriveRootId: mocks.getDriveRootId,
  getUserInfo: mocks.getUserInfo,
  fetchAllFiles: mocks.fetchAllFiles,
}));
vi.mock('@/lib/preview', () => ({ clearPreviewCache: vi.fn() }));
vi.mock('@/lib/state', () => ({
  getSettings: mocks.getSettings,
  saveSettings: mocks.saveSettings,
  purgeAppBrowserData: vi.fn(() => Promise.resolve()),
}));
vi.mock('@/lib/analytics', () => ({
  trackEvent: vi.fn(),
  trackException: vi.fn(),
}));

async function signInAndStartScan() {
  fireEvent.click(screen.getByTestId('gsi-load'));
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
    mocks.getDriveRootId.mockResolvedValue('root-id');
    mocks.getSettings.mockReturnValue({
      dupesFolder: '_dupes',
      batchSize: 10,
      blacklistedPathPrefixes: [],
    });
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  it.each([
    [0, true, false],
    [1023, true, false],
    [1024, true, true],
    [1025, true, true],
    [1023, false, true],
  ])('scans size %i with ignoreSmallFiles=%s, duplicates=%s', async (size, enabled, hasDuplicates) => {
    mocks.fetchAllFiles.mockResolvedValue(['a', 'b'].map((id) => ({
      id,
      name: `${id}.txt`,
      mimeType: 'text/plain',
      size: String(size),
      md5Checksum: 'same-checksum',
      ownedByMe: true,
      parents: ['root-id'],
    })));
    render(<App clientId="test-client-id" />);
    const toggle = screen.getByRole('checkbox', { name: /ignore files smaller than 1 KB/i });
    expect(toggle).toBeChecked();
    if (!enabled) {
      fireEvent.click(toggle);
      expect(toggle).not.toBeChecked();
      expect(mocks.saveSettings).toHaveBeenCalledWith({ ignoreSmallFiles: false });
    }
    await signInAndStartScan();
    if (hasDuplicates) {
      expect(await screen.findByText('Decision count: 0')).toBeInTheDocument();
    } else {
      expect(await screen.findByText('No duplicates found. Your Drive was left unchanged.')).toBeInTheDocument();
    }
  });

  it('restores a disabled small-file filter from settings', () => {
    mocks.getSettings.mockReturnValue({ blacklistedPathPrefixes: [], ignoreSmallFiles: false });
    render(<App clientId="test-client-id" />);
    expect(screen.getByRole('checkbox', { name: /ignore files smaller than 1 KB/i })).not.toBeChecked();
  });

  it('returns a signed-in user to Account with a success notice after a zero-result scan', async () => {
    mocks.fetchAllFiles.mockResolvedValue([]);
    render(<App clientId="test-client-id" />);

    await signInAndStartScan();

    expect(await screen.findByText('No duplicates found. Your Drive was left unchanged.')).toBeInTheDocument();
    expect(screen.getByText('Drive User')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /start scan/i })).toBeEnabled();
  });

  it('returns a signed-in user to Account with a retry message after a non-auth scan failure', async () => {
    mocks.fetchAllFiles.mockRejectedValue(new Error('Drive unavailable'));
    render(<App clientId="test-client-id" />);

    await signInAndStartScan();

    await waitFor(() => {
      expect(screen.getByText('Scan failed: Drive unavailable. You can try again.')).toBeInTheDocument();
    });
    expect(screen.getByText('Drive User')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /start scan/i })).toBeEnabled();
  });

  it('keeps sign-in disabled until GIS initialization succeeds', () => {
    render(<App clientId="test-client-id" />);

    const loadingButton = screen.getByRole('button', { name: /loading google sign-in/i });
    expect(loadingButton).toBeDisabled();
    fireEvent.click(loadingButton);
    expect(mocks.requestReadAccess).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('gsi-load'));
    expect(mocks.initAuth).toHaveBeenCalledWith('test-client-id');
    expect(screen.getByRole('button', { name: /sign in with google/i })).toBeEnabled();
  });

  it('keeps sign-in disabled when GIS fails to load', () => {
    render(<App clientId="test-client-id" />);
    fireEvent.click(screen.getByTestId('gsi-error'));

    expect(screen.getByRole('button', { name: /google sign-in unavailable/i })).toBeDisabled();
    expect(screen.getByText(/check your connection and refresh/i)).toBeInTheDocument();
  });

  it('keeps sign-in disabled when GIS initialization throws', () => {
    mocks.initAuth.mockImplementationOnce(() => {
      throw new Error('Initialization failed');
    });
    render(<App clientId="test-client-id" />);
    fireEvent.click(screen.getByTestId('gsi-load'));

    expect(screen.getByRole('button', { name: /google sign-in unavailable/i })).toBeDisabled();
    expect(screen.getByText(/could not initialize/i)).toBeInTheDocument();
  });

  it('surfaces a missing OAuth client configuration', () => {
    render(<App clientId="" />);

    expect(screen.getByRole('button', { name: /google sign-in unavailable/i })).toBeDisabled();
    expect(screen.getByText(/oauth client id is not configured/i)).toBeInTheDocument();
  });

  it('removes an unsafe stored decision and returns the group to review', async () => {
    mocks.fetchAllFiles.mockResolvedValue([
      {
        id: 'first',
        name: 'copy.txt',
        size: '2048',
        md5Checksum: 'checksum',
        mimeType: 'text/plain',
        ownedByMe: true,
        parents: ['root-id'],
      },
      {
        id: 'second',
        name: 'copy.txt',
        size: '2048',
        md5Checksum: 'checksum',
        mimeType: 'text/plain',
        ownedByMe: true,
        parents: ['root-id'],
      },
    ]);
    render(<App clientId="test-client-id" />);
    await signInAndStartScan();

    const unsafeButton = await screen.findByRole('button', { name: 'Set unsafe decision' });
    fireEvent.click(unsafeButton);
    expect(screen.getByText('Decision count: 1')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Attempt execute' }));

    await waitFor(() => expect(screen.getByText('Decision count: 0')).toBeInTheDocument());
    expect(screen.getByRole('alert')).toHaveTextContent(/unsafe or stale selection/i);
  });

  it('persists blacklisted path prefixes added before a scan', async () => {
    render(<App clientId="test-client-id" />);
    fireEvent.click(screen.getByTestId('gsi-load'));
    fireEvent.click(screen.getByRole('button', { name: /sign in with google/i }));

    const input = await screen.findByLabelText(/path prefix to exclude from scans/i);
    fireEvent.change(input, { target: { value: '/Archive/' } });
    fireEvent.click(screen.getByRole('button', { name: /^add$/i }));

    expect(screen.getByText('/Archive')).toBeInTheDocument();
    expect(mocks.saveSettings).toHaveBeenCalledWith({
      blacklistedPathPrefixes: ['/Archive'],
    });
  });

  it('excludes files under blacklisted path prefixes from the scan', async () => {
    mocks.getSettings.mockReturnValue({
      dupesFolder: '_dupes',
      batchSize: 10,
      blacklistedPathPrefixes: ['/Archive'],
    });
    mocks.fetchAllFiles.mockResolvedValue([
      { id: 'archive-folder', name: 'Archive', mimeType: FOLDER, ownedByMe: true, parents: ['root-id'] },
      {
        id: 'archived-copy',
        name: 'copy.txt',
        size: '2048',
        md5Checksum: 'checksum',
        mimeType: 'text/plain',
        ownedByMe: true,
        parents: ['archive-folder'],
      },
      {
        id: 'kept-copy',
        name: 'copy.txt',
        size: '2048',
        md5Checksum: 'checksum',
        mimeType: 'text/plain',
        ownedByMe: true,
        parents: ['root-id'],
      },
    ]);
    render(<App clientId="test-client-id" />);

    await signInAndStartScan();

    expect(await screen.findByText('No duplicates found. Your Drive was left unchanged.')).toBeInTheDocument();
  });
});
