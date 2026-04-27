import DomainView, { type DomainStat } from './DomainView'
import type { Artifact } from '../ipc'

function computeStats(artifacts: Artifact[]): DomainStat[] {
  const apps = new Set(
    artifacts
      .filter((a) => /quickbooks|quicken|mint|turbotax|sage/i.test(`${a.name} ${a.source_path}`))
      .map((a) => a.plugin),
  )
  const transactions = artifacts.filter((a) =>
    /transaction|transfer|wire|deposit/i.test(a.name),
  ).length
  const structuring = artifacts.filter(
    (a) => /structuring|smurfing/i.test(`${a.name} ${a.value}`) || a.forensic_value === 'high',
  ).length
  const quickbooks = artifacts.filter((a) =>
    /quickbooks|qbo|qbb|\.qbw/i.test(`${a.name} ${a.source_path}`),
  ).length
  return [
    { label: 'Total', value: artifacts.length },
    { label: 'Apps Detected', value: apps.size },
    { label: 'Transactions', value: transactions },
    {
      label: 'Structuring Alerts',
      value: structuring,
      emphasis: structuring > 0 ? 'amber' : 'normal',
    },
    { label: 'QuickBooks', value: quickbooks },
  ]
}

export default function FinancialView() {
  return (
    <DomainView
      title="Financial"
      subtitle="Transactions, accounting, structuring patterns"
      icon="\u{1F4B5}"
      category="Financial"
      computeStats={computeStats}
      highlightCritical
    />
  )
}
