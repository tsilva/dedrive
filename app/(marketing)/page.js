import Footer from '@/components/Footer';
import Header from '@/components/Header';
import MarketingHero from '@/components/MarketingHero';

export default function MarketingPage() {
  return (
    <div className="app">
      <Header />
      <main className="main">
        <MarketingHero />
      </main>
      <Footer />
    </div>
  );
}
