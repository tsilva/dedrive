import { Analytics } from '@vercel/analytics/next';
import { SpeedInsights } from '@vercel/speed-insights/next';
import Script from 'next/script';
import {
  absoluteUrl,
  siteAssets,
  siteClassification,
  siteDescription,
  siteKeywords,
  siteName,
  siteTitle,
  siteUrl,
  socialDescription,
} from '@/lib/site';

const GA_MEASUREMENT_ID = process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID;
const GOOGLE_SITE_VERIFICATION = process.env.GOOGLE_SITE_VERIFICATION;
const BING_SITE_VERIFICATION = process.env.BING_SITE_VERIFICATION;
const YANDEX_SITE_VERIFICATION = process.env.YANDEX_SITE_VERIFICATION;
const SHOULD_LOAD_VERCEL_SCRIPTS = process.env.VERCEL === '1' || Boolean(process.env.NEXT_PUBLIC_VERCEL_ENV);

export const metadata = {
  title: {
    absolute: siteTitle,
  },
  description: siteDescription,
  alternates: {
    canonical: '/',
  },
  category: 'productivity',
  classification: siteClassification,
  keywords: siteKeywords,
  authors: [{ name: 'Tiago Silva' }],
  creator: 'Tiago Silva',
  publisher: 'Tiago Silva',
  appleWebApp: {
    capable: true,
    title: siteName,
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
    title: siteTitle,
    description: socialDescription,
    type: 'website',
    url: siteUrl,
    siteName: siteName,
    locale: 'en_US',
    images: [
      {
        url: siteAssets.openGraphImage,
        width: 1200,
        height: 630,
        alt: 'dedrive social card for a private Google Drive duplicate finder',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: siteTitle,
    description: socialDescription,
    creator: '@tiagosilva',
    images: [siteAssets.openGraphImage],
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
      name: siteName,
      url: siteUrl,
      description: siteDescription,
      publisher: {
        '@type': 'Person',
        name: 'Tiago Silva',
        url: 'https://www.tsilva.eu',
      },
    },
    {
      '@type': 'SoftwareApplication',
      name: siteName,
      url: siteUrl,
      image: absoluteUrl(siteAssets.openGraphImage),
      screenshot: absoluteUrl(siteAssets.openGraphImage),
      description: siteDescription,
      applicationCategory: 'UtilityApplication',
      applicationSubCategory: 'FileManagementApplication',
      operatingSystem: 'Any',
      browserRequirements: 'Requires JavaScript and a Google account.',
      isAccessibleForFree: true,
      featureList: [
        'Find duplicate files in Google Drive by checksum',
        'Scan with read-only access before any write permission is requested',
        'Preview image, PDF, and text matches before choosing what to keep',
        'Move extra copies into a _dupes folder instead of deleting them',
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
      {SHOULD_LOAD_VERCEL_SCRIPTS && (
        <>
          <Analytics />
          <SpeedInsights />
        </>
      )}
    </>
  );
}
