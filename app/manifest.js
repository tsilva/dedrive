import { siteAssets, siteDescription, siteName } from '@/lib/site';

export default function manifest() {
  return {
    name: 'dedrive | Google Drive Duplicate Finder',
    short_name: siteName,
    description: siteDescription,
    start_url: '/',
    display: 'standalone',
    background_color: '#0d0d0d',
    theme_color: '#0d0d0d',
    categories: ['productivity', 'utilities'],
    icons: [
      {
        src: siteAssets.androidChrome192,
        sizes: '192x192',
        type: 'image/png',
      },
      {
        src: siteAssets.androidChrome512,
        sizes: '512x512',
        type: 'image/png',
      },
      {
        src: siteAssets.appleTouchIcon,
        sizes: '180x180',
        type: 'image/png',
      },
    ],
  };
}
