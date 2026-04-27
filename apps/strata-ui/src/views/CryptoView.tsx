import DomainView, { type DomainStat } from './DomainView'
import type { Artifact } from '../ipc'

function computeStats(artifacts: Artifact[]): DomainStat[] {
  const wallets = artifacts.filter((a) => /wallet|wallet\.dat/i.test(a.name)).length
  const btc = artifacts.filter((a) => /bitcoin|btc|wallet\.dat/i.test(`${a.name} ${a.value}`)).length
  const eth = artifacts.filter((a) => /ethereum|eth|metamask/i.test(`${a.name} ${a.value}`)).length
  const xmr = artifacts.filter((a) => /monero|xmr/i.test(`${a.name} ${a.value}`)).length
  const hardware = artifacts.filter((a) =>
    /ledger|trezor|hardware wallet/i.test(`${a.name} ${a.value} ${a.source_path}`),
  ).length
  const exchanges = artifacts.filter((a) =>
    /coinbase|binance|kraken|gemini|exchange/i.test(`${a.name} ${a.value} ${a.source_path}`),
  ).length
  return [
    { label: 'Wallet Files', value: wallets },
    { label: 'BTC', value: btc },
    { label: 'ETH', value: eth },
    { label: 'XMR', value: xmr },
    { label: 'Hardware', value: hardware },
    { label: 'Exchanges', value: exchanges },
  ]
}

export default function CryptoView() {
  return (
    <DomainView
      title="Cryptocurrency"
      subtitle="Wallets, addresses, exchanges, hardware devices"
      icon="\u{1FA99}"
      category="Cryptocurrency"
      computeStats={computeStats}
      highlightCritical
    />
  )
}
