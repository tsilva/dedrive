import MarketingFooter from '@/components/MarketingFooter';
import MarketingHeader from '@/components/MarketingHeader';
import MarketingHero from '@/components/MarketingHero';

export default function MarketingPage() {
  return (
    <div className="app">
      <MarketingHeader />
      <main className="main">
        <MarketingHero />
      </main>
      <MarketingFooter />
    </div>
  );
}
