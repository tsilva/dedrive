import { connection } from 'next/server';

import App from '@/components/App';

export default async function SecureAppPage() {
  await connection();
  return <App />;
}
