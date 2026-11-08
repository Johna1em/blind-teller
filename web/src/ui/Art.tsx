import type { ReactNode } from 'react';

const ICONS: Record<string, ReactNode> = {
  check: <path d="M5 12.5l4.5 4.5L19 7.5" />,
  x: <path d="M6 6l12 12M18 6L6 18" />,
  lock: (
    <>
      <rect x="5" y="11" width="14" height="9" rx="2" />
      <path d="M8 11V8a4 4 0 0 1 8 0v3" />
    </>
  ),
  mail: (
    <>
      <rect x="3" y="5.5" width="18" height="13" rx="2" />
      <path d="M3.5 7l8.5 6.5L20.5 7" />
    </>
  ),
  bank: <path d="M3 10l9-6 9 6M5 10v8M9.5 10v8M14.5 10v8M19 10v8M3 20h18" />,
  shield: <path d="M12 3l7.5 3v5.5c0 4.6-3.2 7.9-7.5 9.5-4.3-1.6-7.5-4.9-7.5-9.5V6L12 3zM8.5 12l2.5 2.5 4.5-4.5" />,
  chip: (
    <>
      <rect x="7" y="7" width="10" height="10" rx="1.5" />
      <path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4" />
    </>
  ),
  link: <path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" />,
  arrow: <path d="M5 12h14M13 6l6 6-6 6" />,
  eyeoff: <path d="M3 3l18 18M10.6 10.6a2 2 0 0 0 2.8 2.8M9.4 5.3A10 10 0 0 1 12 5c5 0 8.5 4 9.5 7a13 13 0 0 1-3 4.4M6.3 6.8C4.4 8.2 3.2 10.1 2.5 12c1 3 4.5 7 9.5 7 1.5 0 2.9-.4 4.1-1" />,
  upload: <path d="M12 16V5M7.5 9.5L12 5l4.5 4.5M4 19h16" />,
  coin: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5v9M14.8 9.5c-.5-1-1.5-1.5-2.8-1.5-1.7 0-3 .8-3 2s1.3 1.8 3 2 3 .8 3 2-1.3 2-3 2c-1.3 0-2.4-.5-2.9-1.5" />
    </>
  ),
};

export type IconName = keyof typeof ICONS;

export function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return (
    <svg className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {ICONS[name]}
    </svg>
  );
}

/** The logo: an arched teller's window with its bars. */
export function Mark() {
  return (
    <svg className="mark" width="30" height="34" viewBox="0 0 30 34" fill="none" aria-hidden="true">
      <path d="M2 32V15a13 13 0 0 1 26 0v17z" stroke="var(--brass)" strokeWidth="2" />
      <path d="M8.5 32V10M15 32V6M21.5 32V10M2.5 19h25" stroke="var(--brass)" strokeWidth="1.6" />
      <path d="M0 32.8h30" stroke="var(--brass-hi)" strokeWidth="2.2" />
    </svg>
  );
}

const CENTER = { x: 210, y: 190 };

/** The teller at the window: behind brass, and blindfolded. */
export function TellerArt() {
  const rays = Array.from({ length: 13 }, (_, i) => {
    const angle = Math.PI + (i * Math.PI) / 12;
    return {
      x1: CENTER.x + 44 * Math.cos(angle),
      y1: CENTER.y + 44 * Math.sin(angle),
      x2: CENTER.x + 128 * Math.cos(angle),
      y2: CENTER.y + 128 * Math.sin(angle),
    };
  });
  const bars = [114, 146, 178, 210, 242, 274, 306];

  return (
    <div className="art" aria-hidden="true">
      <svg viewBox="0 0 420 450" fill="none">
        <defs>
          <linearGradient id="art-brass" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#f8e8bd" />
            <stop offset="0.45" stopColor="#d6b069" />
            <stop offset="0.75" stopColor="#8f6e34" />
            <stop offset="1" stopColor="#e7ca89" />
          </linearGradient>
          <linearGradient id="art-glass" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#1f4a3c" />
            <stop offset="1" stopColor="#0d1f19" />
          </linearGradient>
          <radialGradient id="art-lamp" cx="0.5" cy="0.42" r="0.55">
            <stop offset="0" stopColor="#57b58e" stopOpacity="0.32" />
            <stop offset="1" stopColor="#57b58e" stopOpacity="0" />
          </radialGradient>
          <clipPath id="art-window">
            <path d="M82 340V190a128 128 0 0 1 256 0v150z" />
          </clipPath>
        </defs>

        <ellipse cx="210" cy="200" rx="208" ry="200" fill="url(#art-lamp)" />

        <path d="M60 340V190a150 150 0 0 1 300 0v150z" fill="#101b17" stroke="url(#art-brass)" strokeWidth="4" />
        <path d="M71 340V190a139 139 0 0 1 278 0v150" stroke="url(#art-brass)" strokeWidth="1" opacity="0.6" />
        <path d="M82 340V190a128 128 0 0 1 256 0v150z" fill="url(#art-glass)" />

        <g clipPath="url(#art-window)">
          {rays.map((r, i) => (
            <line key={i} x1={r.x1} y1={r.y1} x2={r.x2} y2={r.y2} stroke="url(#art-brass)" strokeWidth="1.4" opacity="0.55" />
          ))}

          <path d="M126 342c4-44 40-62 72-66h24c32 4 68 22 72 66z" fill="#17302a" stroke="#d6b069" strokeWidth="1.5" />
          <path d="M198 276l12 16 12-16" fill="#efe7d3" />
          <path d="M210 293l-10-6v12zM210 293l10-6v12z" fill="#d6b069" />
          <rect x="198" y="256" width="24" height="24" fill="#1d3a31" />
          <ellipse cx="210" cy="228" rx="31" ry="37" fill="#254a3f" stroke="#d6b069" strokeWidth="1.5" />
          <path className="art-blindfold" d="M177 222q33-7 66 0v17q-33 7-66 0z" fill="url(#art-brass)" />
          <path d="M243 226l15-7-3 11 5 8-17-3z" fill="#b78f4c" />
          <path d="M172 212q38-30 76 0l14 11q-52-24-104 0z" fill="#2f8a68" stroke="#7fd8ae" strokeWidth="0.8" />
        </g>

        <g stroke="url(#art-brass)" strokeWidth="3.2">
          {bars.map((x) => {
            const rise = Math.sqrt(128 ** 2 - (x - CENTER.x) ** 2);
            return <line key={x} x1={x} y1={CENTER.y - rise + 1} x2={x} y2="340" opacity="0.92" />;
          })}
          <line x1="82" y1="190" x2="338" y2="190" />
          <line x1="82" y1="284" x2="338" y2="284" />
        </g>

        <path d="M100 340L250 66h48L148 340z" fill="#ffffff" opacity="0.035" clipPath="url(#art-window)" />

        <rect x="36" y="340" width="348" height="20" rx="2" fill="url(#art-brass)" />
        <rect x="154" y="346" width="112" height="8" rx="2" fill="#07100d" />

        <rect x="144" y="20" width="132" height="32" rx="3" fill="#0d1713" stroke="url(#art-brass)" strokeWidth="2" />
        <text x="210" y="42" textAnchor="middle" fill="#f5e2b3" fontFamily="Marcellus, Georgia, serif" fontSize="16" letterSpacing="6">TELLER</text>

        <g className="art-mail">
          <rect x="164" y="362" width="92" height="60" rx="3" fill="#f6f0e2" />
          <path d="M165 364l45 34 45-34" stroke="#c9bfa5" strokeWidth="1.6" />
          <circle cx="210" cy="400" r="10" fill="#b5362b" />
          <path d="M206 400l3 3 5-6" stroke="#fff3df" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </g>
      </svg>

      <span className="art-chip art-chip-a"><Icon name="mail" size={15} />Bank&rsquo;s stamp checked</span>
      <span className="art-chip art-chip-b"><Icon name="chip" size={15} />Read in sealed hardware</span>
      <span className="art-chip art-chip-c"><Icon name="coin" size={15} />Paid by a NEAR contract</span>
    </div>
  );
}
