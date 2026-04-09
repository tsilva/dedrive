const DEFAULT_SITE_URL = 'https://dedrive.tsilva.eu';

export const siteName = 'dedrive';
export const siteUrl = (process.env.NEXT_PUBLIC_SITE_URL || DEFAULT_SITE_URL).replace(/\/$/, '');
export const siteTitle = 'Google Drive Duplicate Finder | dedrive';
export const defaultTitle = siteName;
export const titleTemplate = '%s | dedrive';
export const siteDescription =
  'Find duplicate files in Google Drive with a private browser-based scanner that starts read-only, lets you review matches side by side, and safely moves extras into a _dupes folder.';
export const socialDescription =
  'Private Google Drive duplicate finder with read-only scanning, side-by-side previews, and safe cleanup into a _dupes folder.';
export const secureAppDescription = 'Private Google Drive duplicate cleanup workspace.';
export const siteClassification = 'Private Google Drive duplicate cleanup and storage optimization';
export const siteKeywords = [
  'google drive duplicate finder',
  'find duplicate files in google drive',
  'google drive duplicate remover',
  'google drive cleanup',
  'private google drive tools',
  'browser based duplicate finder',
  'google drive storage cleanup',
  'safe duplicate file cleanup',
  'google drive file dedupe',
  'free google drive duplicate finder',
];

export const siteAssets = {
  logo: '/brand/logo/logo-1024.png',
  icon: '/brand/icon/icon-1024.png',
  faviconIco: '/brand/web-seo/favicon/favicon.ico',
  faviconPng: '/brand/web-seo/favicon/favicon-32.png',
  androidChrome192: '/brand/web-seo/android-chrome-192.png',
  androidChrome512: '/brand/web-seo/android-chrome-512.png',
  appleTouchIcon: '/brand/web-seo/apple-touch-icon.png',
  openGraphImage: '/brand/web-seo/og-image-1200x630.png',
};

export function absoluteUrl(path = '/') {
  return new URL(path, siteUrl).toString();
}
