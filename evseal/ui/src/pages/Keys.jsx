import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Badge } from './Profiles.jsx'

export default function Keys() {
  const [data, setData] = useState(null)
  const [schema, setSchema] = useState(null)
  const [rot, setRot] = useState([])
  const [name, setName] = useState('collector')
  const [alg, setAlg] = useState('ML-DSA-87')
  const [msg, setMsg] = useState('')
  const load = () => { api.get('/api/keys').then(setData); api.get('/api/keys/rotation').then((d) => setRot(d.certs)) }
  useEffect(() => { load(); api.get('/api/schema').then(setSchema) }, [])

  async function gen() {
    setMsg('')
    try { const k = await api.post('/api/keys', { name, alg }); setMsg(`✓ Generated ${k.name} (${k.alg})`); load() } catch (e) { setMsg(`✕ ${e.message}`) }
  }
  if (!data || !schema) return <div className="text-sm">Loading…</div>
  const algs = Object.entries(schema.algorithms).filter(([a, v]) => !a.startsWith('ML-KEM') && v.class !== 'classical')
  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <h1 className="h1">Keys</h1>
      <div className="rounded-xl border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950/50 dark:text-amber-300">⚠ {data.dev_only_warning}</div>
      <div className="card flex flex-wrap items-end gap-3">
        <label><span className="label">Name</span><input className="input" value={name} onChange={(e) => setName(e.target.value.replace(/[^A-Za-z0-9._-]/g, '-'))} /></label>
        <label><span className="label">Root algorithm</span>
          <select className="input" value={alg} onChange={(e) => setAlg(e.target.value)}>{algs.map(([a]) => <option key={a}>{a}</option>)}</select></label>
        <Badge info={schema.algorithms[alg]} />
        <button className="btn-primary" onClick={gen}>Generate root / collector key</button>
        {msg && <span className="text-sm">{msg}</span>}
      </div>
      <div className="card">
        <div className="mb-2 font-semibold">Root keys (trusted by this workspace's verifier)</div>
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-slate-500"><tr><th className="py-1">Name</th><th>Algorithm</th><th>Fingerprint (SHA3-256)</th><th>Private key</th></tr></thead>
          <tbody>
            {data.keys.map((k) => (
              <tr key={k.fp} className="border-t border-slate-200 dark:border-slate-800">
                <td className="py-1.5 font-medium">{k.name}</td><td><span className="mr-2">{k.alg}</span><Badge info={schema.algorithms[k.alg]} /></td>
                <td className="mono">{k.fp}</td><td>{k.has_private ? '🔑 file (dev-only)' : 'public only'}</td>
              </tr>
            ))}
            <tr className="border-t border-slate-200 dark:border-slate-800"><td className="py-1.5 font-medium">{data.tsa.name} <span className="text-xs text-slate-500">(local test TSA)</span></td><td>{data.tsa.alg}</td><td className="mono">{data.tsa.fp}</td><td>timestamps only</td></tr>
          </tbody>
        </table>
      </div>
      <div className="card">
        <div className="mb-1 font-semibold">Certificates & rotation log</div>
        <p className="mb-2 text-xs text-slate-500">Each seal certifies a fresh ephemeral signing key per <code>keys.rotation_s</code> period plus a checkpoint key; ephemeral private keys are wiped at period end (forward security).</p>
        <div className="max-h-96 overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-white text-left uppercase text-slate-500 dark:bg-slate-900"><tr><th className="py-1">Bundle</th><th>Cert</th><th>Role</th><th>Alg</th><th>Period</th><th>Issued</th><th>Key fp</th></tr></thead>
            <tbody>{rot.map((c, n) => (
              <tr key={n} className="border-t border-slate-200 dark:border-slate-800"><td className="py-1">{c.bundle}</td><td>{c.id}</td><td>{c.role}</td><td>{c.alg}</td><td>{c.period}</td>
                <td>{new Date(c.not_before * 1000).toLocaleString()}</td><td className="mono">{c.fp.slice(0, 16)}…</td></tr>))}</tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
