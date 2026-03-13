import { Analytics } from "@vercel/analytics/next";
import { SpeedInsights } from "@vercel/speed-insights/next";
import Script from "next/script";
import './globals.css';

const SITE_URL = "https://dedrive.tsilva.eu";
const SITE_TITLE = "Dedrive | Google Drive Duplicate File Manager";
const SITE_DESCRIPTION = "Find and manage duplicate files in your Google Drive automatically. Identify duplicates by MD5 hash, review and clean up storage. Runs entirely in your browser - private and secure. Free tool.";
const GA_MEASUREMENT_ID = process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID;

export const metadata = {
  title: SITE_TITLE,
  description: SITE_DESCRIPTION,
  keywords: [
    "Google Drive",
    "duplicate files",
    "file manager",
    "storage cleanup",
    "duplicate finder",
    "cloud storage",
    "file organization",
    "Google Drive tools",
    "storage management",
    "duplicate detection",
    "browser tool",
    "privacy focused",
  ],
  authors: [{ name: "Tiago Silva" }],
  creator: "Tiago Silva",
  metadataBase: new URL(SITE_URL),
  alternates: {
    canonical: "/",
  },
  openGraph: {
    title: SITE_TITLE,
    description: "Find and clean up duplicate files in Google Drive. Browser-based, private, and secure. Free duplicate file manager.",
    type: "website",
    url: SITE_URL,
    siteName: "Dedrive",
    locale: "en_US",
  },
  twitter: {
    card: "summary_large_image",
    title: SITE_TITLE,
    description: "Find and manage duplicate files in Google Drive. Private browser-based tool.",
    creator: "@tiagosilva",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
    },
  },
};

const jsonLd = {
  "@context": "https://schema.org",
  "@type": "WebSite",
  name: "Dedrive",
  url: SITE_URL,
  description: SITE_DESCRIPTION,
  author: {
    "@type": "Person",
    name: "Tiago Silva",
    url: "https://www.tsilva.eu",
  },
  applicationCategory: "UtilityApplication",
  offers: {
    "@type": "Offer",
    price: "0",
    priceCurrency: "USD",
  },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
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
      </head>
      <body>
        {children}
        <Analytics />
        <SpeedInsights />
      </body>
    </html>
  );
}
