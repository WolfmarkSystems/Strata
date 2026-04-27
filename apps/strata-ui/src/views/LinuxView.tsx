import DomainView, { type DomainStat } from './DomainView'
import type { Artifact } from '../ipc'

function computeStats(artifacts: Artifact[]): DomainStat[] {
  const users = artifacts.filter((a) =>
    /\/etc\/passwd|user account/i.test(`${a.name} ${a.source_path}`),
  ).length
  const suspicious = artifacts.filter(
    (a) =>
      /uid=0|root|locked/i.test(`${a.name} ${a.value}`) && a.forensic_value === 'high',
  ).length
  const history = artifacts.filter((a) =>
    /bash_history|zsh_history|fish_history|shell history/i.test(`${a.name} ${a.source_path}`),
  ).length
  const cron = artifacts.filter((a) =>
    /cron|crontab|systemd timer/i.test(`${a.name} ${a.source_path}`),
  ).length
  return [
    { label: 'Total', value: artifacts.length },
    { label: 'Users', value: users },
    {
      label: 'Suspicious Accts',
      value: suspicious,
      emphasis: suspicious > 0 ? 'critical' : 'normal',
    },
    { label: 'Shell History', value: history },
    { label: 'Cron / Timers', value: cron },
  ]
}

export default function LinuxView() {
  return (
    <DomainView
      title="Linux"
      subtitle="Accounts, persistence, shell history, cron"
      icon="\u{1F5A5}"
      category="Linux System"
      computeStats={computeStats}
      highlightCritical
    />
  )
}
