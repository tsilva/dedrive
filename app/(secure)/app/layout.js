export const metadata = {
  title: 'Secure App',
  description: 'Secure Google Drive duplicate review workspace.',
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
