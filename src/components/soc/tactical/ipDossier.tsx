import React from 'react';

/**
 * IP DOSSIER — any address on screen opens everything the platform knows about it.
 *
 * A context rather than props, because addresses appear in a dozen components at
 * different depths (feed, kill chain, decoys, containment, device table, audit) and
 * threading a callback through each would couple all of them to the cockpit. Outside the
 * cockpit the provider is absent and IpLink renders plain text, so nothing breaks.
 */

export const IpDossierContext = React.createContext<{ open: (ip: string) => void } | null>(null);

export const useIpDossier = () => React.useContext(IpDossierContext);

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

export type IpClass = 'LOOPBACK' | 'LAN' | 'LINK_LOCAL' | 'CARRIER_NAT' | 'DOCUMENTATION' | 'PUBLIC' | 'UNKNOWN';

/** What kind of address this is, from the address alone — a fact, not a reputation. */
export function classifyIp(ip: string): IpClass {
  if (!IPV4.test(ip)) return ip === '::1' ? 'LOOPBACK' : 'UNKNOWN';
  const [a, b, c] = ip.split('.').map(Number);
  if (a === 127) return 'LOOPBACK';
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'LAN';
  if (a === 169 && b === 254) return 'LINK_LOCAL';
  if (a === 100 && b >= 64 && b <= 127) return 'CARRIER_NAT';
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return 'DOCUMENTATION';
  return 'PUBLIC';
}

/** A clickable address. Keyboard-reachable; plain text where no dossier is available. */
export const IpLink: React.FC<{ ip: string | null | undefined; className?: string; style?: React.CSSProperties }> = ({
  ip,
  className = '',
  style
}) => {
  const ctx = useIpDossier();
  if (!ip) return <span className={className} style={style}>—</span>;
  if (!ctx || !IPV4.test(ip)) {
    return (
      <span className={`font-mono ${className}`} style={style} dir="ltr">
        {ip}
      </span>
    );
  }
  return (
    <button
      type="button"
      onClick={e => {
        e.stopPropagation();
        ctx.open(ip);
      }}
      className={`font-mono underline decoration-dotted decoration-1 underline-offset-2 transition-colors hover:text-cyan-200 focus-visible:ring-1 focus-visible:ring-cyan-400 focus-visible:outline-none ${className}`}
      style={style}
      dir="ltr"
      title={`${ip} — open dossier`}
    >
      {ip}
    </button>
  );
};
