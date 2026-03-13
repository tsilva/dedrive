import { Analytics } from '@vercel/analytics/next';
import { SpeedInsights } from '@vercel/speed-insights/next';
import Script from 'next/script';

const SITE_URL = 'https://dedrive.tsilva.eu';
const SITE_NAME = 'dedrive';
const SITE_TITLE = 'dedrive | Find and Remove Duplicate Files in Google Drive';
const SITE_DESCRIPTION = 'Scan Google Drive for true duplicate files, review matches side by side, and move extras into a safe _dupes folder. Private, browser-based, and free.';
const SOCIAL_DESCRIPTION = 'Clean up duplicate Google Drive files with a private browser-based tool. Preview matches, keep the right copy, and safely move extras.';
const GA_MEASUREMENT_ID = process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID;
const GOOGLE_SITE_VERIFICATION = process.env.GOOGLE_SITE_VERIFICATION;
const BING_SITE_VERIFICATION = process.env.BING_SITE_VERIFICATION;
const YANDEX_SITE_VERIFICATION = process.env.YANDEX_SITE_VERIFICATION;

export const metadata = {
  title: {
    absolute: SITE_TITLE,
  },
  description: SITE_DESCRIPTION,
  alternates: {
    canonical: '/',
  },
  category: 'productivity',
  classification: 'File management and storage optimization',
  keywords: [
    'google drive duplicate finder',
    'remove duplicate files google drive',
    'google drive cleanup',
    'duplicate file manager',
    'storage cleanup tool',
    'browser based file organizer',
    'private google drive tools',
    'duplicate file scanner',
    'free duplicate file finder',
    'google drive storage saver',
  ],
  authors: [{ name: 'Tiago Silva' }],
  creator: 'Tiago Silva',
  publisher: 'Tiago Silva',
  appleWebApp: {
    capable: true,
    title: SITE_NAME,
    statusBarStyle: 'black-translucent',
  },
  verification: {
    google: GOOGLE_SITE_VERIFICATION || undefined,
    yandex: YANDEX_SITE_VERIFICATION || undefined,
    other: BING_SITE_VERIFICATION
      ? {
          'msvalidate.01': BING_SITE_VERIFICATION,
        }
      : undefined,
  },
  openGraph: {
    title: SITE_TITLE,
    description: SOCIAL_DESCRIPTION,
    type: 'website',
    url: SITE_URL,
    siteName: SITE_NAME,
    locale: 'en_US',
    images: [
      {
        url: '/opengraph-image',
        width: 1200,
        height: 630,
        alt: 'dedrive preview card showing Google Drive duplicate cleanup',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: SITE_TITLE,
    description: SOCIAL_DESCRIPTION,
    creator: '@tiagosilva',
    images: ['/opengraph-image'],
  },
  robots: {
    index: true,
    follow: true,
    nocache: false,
    googleBot: {
      index: true,
      follow: true,
      'max-image-preview': 'large',
      'max-snippet': -1,
      'max-video-preview': -1,
    },
  },
};

const jsonLd = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'WebSite',
      name: SITE_NAME,
      url: SITE_URL,
      description: SITE_DESCRIPTION,
      publisher: {
        '@type': 'Person',
        name: 'Tiago Silva',
        url: 'https://www.tsilva.eu',
      },
    },
    {
      '@type': 'SoftwareApplication',
      name: SITE_NAME,
      url: SITE_URL,
      image: `${SITE_URL}/opengraph-image`,
      screenshot: `${SITE_URL}/opengraph-image`,
      description: SITE_DESCRIPTION,
      applicationCategory: 'UtilityApplication',
      applicationSubCategory: 'FileManagementApplication',
      operatingSystem: 'Any',
      browserRequirements: 'Requires JavaScript and a Google account.',
      isAccessibleForFree: true,
      featureList: [
        'Find Google Drive duplicates by MD5 checksum',
        'Preview image, PDF, and text files before deciding',
        'Keep one copy and move extras into a _dupes folder',
        'Request write access only when moving files',
      ],
      offers: {
        '@type': 'Offer',
        price: '0',
        priceCurrency: 'USD',
      },
      author: {
        '@type': 'Person',
        name: 'Tiago Silva',
        url: 'https://www.tsilva.eu',
      },
    },
  ],
};

export default function MarketingLayout({ children }) {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      {GA_MEASUREMENT_ID && (
        <>
          <Script
            src={`https://www.googletagmanager.com/gtag/js?id=${GA_MEASUREMENT_ID}`}
            strategy="afterInteractive"
          />
          <Script id="google-analytics" strategy="afterInteractive">
            {`
              window.dataLayer = window.dataLayer || [];
              function gtag(){dataLayer.push(arguments);}
              window.gtag = gtag;
              gtag('js', new Date());
              gtag('config', '${GA_MEASUREMENT_ID}');
            `}
          </Script>
        </>
      )}
      {children}
      <Analytics />
      <SpeedInsights />
    </>
  );
}
