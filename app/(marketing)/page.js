import Header from '@/components/Header';
import AccountScreen from '@/components/screens/AccountScreen';
import Footer from '@/components/Footer';

export default function MarketingPage() {
  return (
    <div className="app">
      <Header screen="account" user={null} />
      <div className="main">
        <AccountScreen
          signInHref="/app?start=signin"
          signInHelper="You will be redirected to the secure app page, where you can sign in with Google."
          signInLabel="Start"
          user={null}
        />
      </div>
      <Footer />
    </div>
  );
}
