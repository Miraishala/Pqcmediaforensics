import { useEffect, useState } from 'react'
import { api, enc } from '../api.js'
import { go } from '../App.jsx'
import { Chip, Verdict } from '../status.jsx'
import { BundlePicker, Timeline } from './Verify.jsx'

export default function Repair({ params }) {
  const [bundle, setBundle] = useState(params.b || '')
  const [plan, setPlan] = useState(null)
  const [report, setReport] = useState(null)
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  async function load(b) {
    setPlan(null); setResult(null); setErr(''); setBusy(true)
    try {
      setPlan(await api.get(`/api/bundles/${enc(b)}/repair/plan`))
      setReport(await api.get(`/api/bundles/${enc(b)}/report`))
    } catch (e) { setErr(e.message) }
    setBusy(false)
  }
  useEffect(() => { if (bundle) load(bundle) }, [bundle])

  async function run() {
    setBusy(true); setErr('')
    try { const r = await api.post(`/api/bundles/${enc(bundle)}/repair/run`); setResult(r); setReport(r.report); setPlan(await api.get(`/api/bundles/${enc(bundle)}/repair/plan`)) }
    catch (e) { setErr(e.message) }
    setBusy(false)
  }

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="h1">Repair</h1>
        <BundlePicker value={bundle} onChange={(b) => { setBundle(b); go('repair', { b }) }} filter={(b) => !b.clip} />
      </div>
      <p className="text-sm text-slate-500">Damaged units are located by AEAD tag failure (erasures), rebuilt from Reed–Solomon parity, and accepted only if they match the signed Rᵢ. Tampering is never "repaired".</p>
      {busy && <div className="card animate-pulse text-sm">Working…</div>}
      {err && <div className="card text-sm text-red-600">✕ {err}</div>}
      {report && <Verdict overall={report.overall} sub={`manifest from ${report.manifest_source}`} />}
      {report && <div className="card"><Timeline units={report.units} selected={null} onSelect={() => {}} /></div>}
      {plan && (
        <div className="card space-y-3">
          <div className="flex items-center justify-between">
            <div className="font-semibold">Repair plan {plan.ec && <span className="text-sm font-normal text-slate-500">· RS {plan.ec.k}+{plan.ec.m}, interleave {plan.ec.interleave}</span>}</div>
            <button className="btn-primary" disabled={busy || !plan.damaged.length && plan.manifest_source === 'manifest.json'} onClick={run}>↻ Run repair &amp; re-verify</button>
          </div>
          {plan.damaged.length === 0 ? <div className="text-sm text-emerald-700">✓ No damaged units{plan.manifest_source !== 'manifest.json' ? ` (manifest recovered from ${plan.manifest_source}; repair rewrites all copies)` : ''}.</div> : (
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase text-slate-500"><tr><th className="py-1">Unit</th><th>Status now</th><th>Stripes</th><th>Repairable</th><th>Detail</th></tr></thead>
              <tbody>{plan.damaged.map((d) => (
                <tr key={d.i} className="border-t border-slate-200 dark:border-slate-800">
                  <td className="py-1.5">#{d.i}</td><td><Chip status={d.status} small /></td><td className="mono">{d.stripes.join(', ') || '—'}</td>
                  <td>{d.repairable ? '✓ yes' : '✕ beyond parity'}</td><td className="text-slate-500">{d.detail}</td>
                </tr>))}</tbody>
            </table>
          )}
        </div>
      )}
      {result && (
        <div className="card text-sm">
          Before <Chip status={result.before} small /> → after <Chip status={result.after} small /> · repaired units: {result.repaired.join(', ') || 'none'} · custody record appended.
        </div>
      )}
    </div>
  )
}
