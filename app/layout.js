import './globals.css';
import {
  defaultTitle,
  siteAssets,
  siteName,
  siteUrl,
  titleTemplate,
} from '@/lib/site';

export const metadata = {
  title: {
    default: defaultTitle,
    template: titleTemplate,
  },
  applicationName: siteName,
  metadataBase: new URL(siteUrl),
  icons: {
    icon: [
      { url: siteAssets.faviconIco, type: 'image/x-icon', sizes: 'any' },
      { url: siteAssets.faviconPng, type: 'image/png', sizes: '32x32' },
      { url: siteAssets.androidChrome192, type: 'image/png', sizes: '192x192' },
    ],
    apple: [{ url: siteAssets.appleTouchIcon, type: 'image/png', sizes: '180x180' }],
    shortcut: [siteAssets.faviconIco],
  },
  manifest: '/manifest.webmanifest',
  formatDetection: {
    telephone: false,
    address: false,
    email: false,
  },
  referrer: 'same-origin',
};

export const viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: '#0d0d0d',
  colorScheme: 'dark',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
