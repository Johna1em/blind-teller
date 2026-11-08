import { useEffect, useState } from 'react';
import { TELLER } from './config';
import { getConfig, type Config } from './lib/teller';
import { Cheat } from './ui/Cheat';
import { How } from './ui/How';
import { Proof } from './ui/Proof';
import { Window } from './ui/Window';
import { Mark } from './ui/Art';

const ROUTES = [
  { hash: '#/', label: 'The window' },
  { hash: '#/cheat', label: 'Try to cheat' },
  { hash: '#/proof', label: 'Proof' },
  { hash: '#/how', label: 'How it works' },
];

function useRoute() {
  const [hash, setHash] = useState(location.hash || '#/');
  useEffect(() => {
    const on = () => {
      setHash(location.hash || '#/');
      scrollTo(0, 0);
    };
    addEventListener('hashchange', on);
    return () => removeEventListener('hashchange', on);
  }, []);
  return hash;
}

export function App() {
  const route = useRoute();
  const [config, setConfig] = useState<Config | null>(null);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    getConfig().then(setConfig).catch(() => setOffline(true));
  }, [route]);

  return (
    <>
      <a className="skip" href="#main">Skip to content</a>
      <header className="masthead">
        <div className="masthead-in">
          <a className="nameplate" href="#/" aria-label="Blind Teller home">
            <Mark />
            <span>Blind Teller</span>
          </a>
          <nav aria-label="Main">
            {ROUTES.map((r) => (
              <a key={r.hash} href={r.hash} aria-current={route === r.hash ? 'page' : undefined}>{r.label}</a>
            ))}
          </nav>
          <span className="netchip"><span className="netdot" aria-hidden="true" />NEAR testnet</span>
        </div>
      </header>

      <main id="main">
        {route === '#/cheat' ? <Cheat config={config} /> : route === '#/proof' ? <Proof config={config} /> : route === '#/how' ? <How /> : <Window config={config} offline={offline} />}
      </main>

      <footer className="colophon">
        <div className="colophon-in">
          <p>This site is static files stored on NEAR. There&rsquo;s no server of ours and no cookies. A strict browser policy lets this page talk only to NEAR, the enclave, and the attestation and quote services it uses.</p>
          <p className="mono">{TELLER} · NEAR testnet · sandbox banks are fictional, and tokens are test tokens</p>
        </div>
      </footer>
    </>
  );
}
