import DomainView, { type DomainStat } from './DomainView'
import type { Artifact } from '../ipc'

function computeStats(artifacts: Artifact[]): DomainStat[] {
  const onion = artifacts.filter(
    (a) => /\.onion/i.test(a.value) || /\.onion/i.test(a.name) || /\.onion/i.test(a.source_path),
  ).length
  const torConfirmed = artifacts.some(
    (a) => /tor browser|torbrowser|onion/i.test(`${a.name} ${a.value} ${a.source_file}`),
  )
  const vpn = artifacts.filter((a) =>
    /vpn|proxy|i2p|proxychains/i.test(`${a.name} ${a.value} ${a.source_path}`),
  ).length
  return [
    { label: 'Total', value: artifacts.length },
    { label: '.onion URLs', value: onion },
    {
      label: 'Tor Confirmed',
      value: torConfirmed ? 'YES' : 'No',
      emphasis: torConfirmed ? 'critical' : 'normal',
    },
    { label: 'VPN/Proxy', value: vpn },
  ]
}

export default function DarkWebView() {
  return (
    <DomainView
      title="Dark Web"
      subtitle="Tor, .onion history, anonymizing proxies"
      icon="\u{26A0}"
      category="Dark Web"
      computeStats={computeStats}
      highlightCritical
    />
  )
}
