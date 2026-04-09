import { secureAppDescription } from '@/lib/site';

export const metadata = {
  title: 'dedrive App',
  description: secureAppDescription,
  robots: {
    index: false,
    follow: false,
    googleBot: {
      index: false,
      follow: false,
    },
  },
};

export default function SecureAppLayout({ children }) {
  return children;
}
