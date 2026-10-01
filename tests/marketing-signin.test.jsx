import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import MarketingHero from '@/components/MarketingHero';

const mocks = vi.hoisted(() => ({
  initAuth: vi.fn(),
  requestReadAccess: vi.fn(),
  push: vi.fn(),
}));

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: mocks.push }) }));
vi.mock('next/font/local', () => ({ default: () => ({ variable: 'font-variable' }) }));
vi.mock('next/image', () => ({ default: ({ loading, ...props }) => <img {...props} /> }));
vi.mock('next/link', () => ({ default: ({ children, ...props }) => <a {...props}>{children}</a> }));
vi.mock('next/script', () => ({ default: ({ onReady, onError }) => (
  <>
    <button onClick={onReady}>Load GIS</button>
    <button onClick={onError}>Fail GIS</button>
  </>
) }));
vi.mock('@/lib/auth', () => ({ initAuth: mocks.initAuth, requestReadAccess: mocks.requestReadAccess }));
vi.mock('@/lib/analytics', () => ({ trackEvent: vi.fn() }));

describe('home-page Google sign-in', () => {
  beforeEach(() => { vi.resetAllMocks(); });

  it('opens Google from the first CTA click and only enters the app after access is granted', async () => {
    let grantAccess;
    mocks.requestReadAccess.mockImplementation(() => new Promise((resolve) => { grantAccess = resolve; }));
    render(<MarketingHero clientId="test-client-id" />);

    const button = screen.getByRole('button', { name: 'Find duplicates' });
    expect(button).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Load GIS' }));
    expect(mocks.initAuth).toHaveBeenCalledWith('test-client-id');
    fireEvent.click(button);
    expect(mocks.requestReadAccess).toHaveBeenCalledOnce();
    expect(mocks.push).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: /signing in/i })).toBeDisabled();

    grantAccess('token');
    await waitFor(() => expect(mocks.push).toHaveBeenCalledWith('/app'));
    expect(mocks.requestReadAccess).toHaveBeenCalledOnce();
  });

  it('stays on the home page after cancellation and allows another sign-in attempt', async () => {
    mocks.requestReadAccess.mockRejectedValueOnce(new Error('Google sign-in was cancelled.')).mockResolvedValueOnce('token');
    render(<MarketingHero clientId="test-client-id" />);
    fireEvent.click(screen.getByRole('button', { name: 'Load GIS' }));
    fireEvent.click(screen.getByRole('button', { name: 'Find duplicates' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Google sign-in was cancelled.');
    expect(mocks.push).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Find duplicates' }));
    await waitFor(() => expect(mocks.push).toHaveBeenCalledWith('/app'));
    expect(mocks.requestReadAccess).toHaveBeenCalledTimes(2);
  });

  it.each(['configuration', 'script'])('keeps the user on the home page when %s is unavailable', async (failure) => {
    render(<MarketingHero clientId={failure === 'configuration' ? '' : 'test-client-id'} />);
    if (failure === 'script') fireEvent.click(screen.getByRole('button', { name: 'Fail GIS' }));
    expect(screen.getByRole('alert')).toHaveTextContent(/google sign-in/i);
    const button = screen.getByRole('button', { name: 'Find duplicates' });
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(mocks.requestReadAccess).not.toHaveBeenCalled();
    expect(mocks.push).not.toHaveBeenCalled();
  });
});
