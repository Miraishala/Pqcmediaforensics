import { useEffect, useMemo, useState } from 'react'
import { api, enc } from '../api.js'

const GROUP_LABEL = {
  segment: 'Video', audio: 'Audio', image: 'Images', unit: 'Unit rules', hash: 'Hashing', sign: 'Signatures', keys: 'Keys',
  checkpoint: 'Checkpoints', timestamps: 'Time', anchors: 'Anchors', aead: 'Encryption', kdf: 'Key derivation',
  ec: 'Erasure coding', outer: 'DR outer layer', dr: 'DR geo-split', parallel: 'Performance',
}

export function Badge({ info }) {
  if (!info) return null
  const cls = { pq: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-300', hybrid: 'bg-sky-100 text-sky-800 dark:bg-sky-900/50 dark:text-sky-300', classical: 'bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300' }[info.class]
  const label = { pq: '🛡 PQ', hybrid: '⛨ Hybrid', classical: '⚠ Classical (NON-PQ)' }[info.class]
  return (
    <span className="inline-flex gap-1">
      <span className={`rounded px-1.5 text-[11px] font-medium ${cls}`}>{label}</span>
      <span className={`rounded px-1.5 text-[11px] ${info.backend === 'liboqs' ? 'bg-emerald-50 text-emerald-700' : info.backend ? 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300' : 'bg-slate-200 text-slate-600'}`}>
        {info.backend === 'pure-python' ? 'DEV-ONLY fallback' : info.backend || 'unavailable'}
      </span>
    </span>
  )
}

function FieldInput({ f, value, onChange, algs }) {
  if (f.kind === 'bool') return <input type="checkbox" checked={!!value} onChange={(e) => onChange(e.target.checked)} />
  if (f.kind === 'enum') return (
    <div className="space-y-1">
      <select className="input" value={value} onChange={(e) => onChange(e.target.value)}>
        {f.options.map((o) => <option key={o} value={o}>{o}{algs[o]?.class === 'classical' ? ' (NON-PQ)' : ''}{algs[o] && !algs[o].backend ? ' — unavailable' : ''}</option>)}
      </select>
      {algs[value] && <Badge info={algs[value]} />}
    </div>
  )
  if (f.kind === 'list') return (
    <div className="flex flex-wrap gap-2">
      {f.options.map((o) => (
        <label key={o} className="flex items-center gap-1 text-sm">
          <input type="checkbox" checked={value.includes(o)} onChange={(e) => onChange(e.target.checked ? [...value, o] : value.filter((x) => x !== o))} />{o}
        </label>
      ))}
    </div>
  )
  if (f.kind === 'num' || f.kind === 'int') return (
    <div className="flex items-center gap-2">
      <input className="input" type="number" step={f.kind === 'int' ? 1 : 0.1} min={f.min} max={f.max} value={value}
        onChange={(e) => onChange(e.target.value === '' ? '' : f.kind === 'int' ? parseInt(e.target.value) : parseFloat(e.target.value))} />
      <span className="whitespace-nowrap text-xs text-slate-500">{f.min}–{f.max}</span>
    </div>
  )
  if (f.kind === 'workers') return <input className="input" value={value} onChange={(e) => onChange(e.target.value === 'auto' || e.target.value === '' ? 'auto' : parseInt(e.target.value) || 'auto')} />
  if (f.kind === 'urls') return <input className="input" placeholder="https://tsa.example/tsr, … (empty = local test TSA)" value={value.join(', ')} onChange={(e) => onChange(e.target.value.split(',').map((s) => s.trim()).filter(Boolean))} />
  if (f.kind === 'map') return <input className="input" placeholder=".dav=video, .amr=audio" value={Object.entries(value).map(([k, v]) => `${k}=${v}`).join(', ')}
    onChange={(e) => onChange(Object.fromEntries(e.target.value.split(',').map((s) => s.trim().split('=')).filter((p) => p.length === 2 && p[0])))} />
  return <input className="input" value={String(value)} onChange={(e) => onChange(e.target.value)} />
}

export default function Profiles() {
  const [schema, setSchema] = useState(null)
  const [list, setList] = useState({ presets: [], saved: [] })
  const [base, setBase] = useState('court-grade')
  const [p, setP] = useState(null)
  const [name, setName] = useState('')
  const [val, setVal] = useState(null)
  const [env, setEnv] = useState({ bitrate_mbps: 2, hours: 12, cores: 8 })
  const [msg, setMsg] = useState('')
  const [diffAB, setDiffAB] = useState(['court-grade', 'low-storage'])
  const [diff, setDiff] = useState(null)

  const reload = () => api.get('/api/profiles').then(setList)
  useEffect(() => { api.get('/api/schema').then(setSchema); reload() }, [])
  useEffect(() => { api.get(`/api/profiles/${enc(base)}`).then((x) => { setP(x); setName(list.presets.includes(base) ? `${base}-copy` : base) }) }, [base])
  useEffect(() => {
    if (!p) return
    const t = setTimeout(() => api.post('/api/profiles/validate', { profile: p, ...env }).then(setVal), 250)
    return () => clearTimeout(t)
  }, [p, env])

  const groups = useMemo(() => {
    const g = {}
    for (const f of schema?.fields || []) (g[f.group] ||= []).push(f)
    return g
  }, [schema])
  if (!schema || !p) return <div className="text-sm">Loading…</div>
  const set = (g, k, v) => setP({ ...p, [g]: { ...p[g], [k]: v } })

  async function save() {
    setMsg('')
    try { await api.put(`/api/profiles/${enc(name)}`, { profile: p }); setMsg(`✓ Saved ${name}`); reload() } catch (e) { setMsg(`✕ ${e.message}`) }
  }
  async function runDiff() { setDiff((await api.post('/api/profiles/diff', { a: diffAB[0], b: diffAB[1] })).diff) }
  const all = [...list.presets, ...list.saved]
  const est = val?.estimates

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div><h1 className="h1">Profiles</h1><p className="text-sm text-slate-500">Every tunable (SPEC §4). The profile is embedded in the signed manifest and bound into C₀.</p></div>
        <div className="flex items-end gap-2">
          <label><span className="label">Start from</span>
            <select className="input" value={base} onChange={(e) => setBase(e.target.value)}>{all.map((x) => <option key={x}>{x}</option>)}</select></label>
          <label><span className="label">Save as</span><input className="input" value={name} onChange={(e) => setName(e.target.value.replace(/[^A-Za-z0-9._-]/g, '-'))} /></label>
          <button className="btn-primary" disabled={!!val?.errors?.length} onClick={save}>Save</button>
          {list.saved.includes(base) && <button className="btn-ghost" onClick={async () => { await api.del(`/api/profiles/${enc(base)}`); reload(); setBase('court-grade') }}>Delete</button>}
        </div>
      </div>
      {msg && <div className="text-sm">{msg}</div>}
      <div className="grid gap-5 lg:grid-cols-[1fr_320px]">
        <div className="grid gap-4 md:grid-cols-2">
          {Object.entries(groups).map(([g, fields]) => (
            <div key={g} className="card">
              <div className="mb-2 font-semibold">{GROUP_LABEL[g] || g}</div>
              <div className="space-y-3">
                {fields.map((f) => (
                  <label key={f.key} className="block">
                    <span className="label">{g}.{f.key}</span>
                    <FieldInput f={f} value={p[g][f.key]} onChange={(v) => set(g, f.key, v)} algs={schema.algorithms} />
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>
        <div className="space-y-4">
          <div className="card sticky top-0 space-y-3">
            <div className="font-semibold">Live estimates</div>
            <div className="grid grid-cols-3 gap-2">
              {[['bitrate_mbps', 'Mbps'], ['hours', 'hours'], ['cores', 'cores']].map(([k, l]) => (
                <label key={k}><span className="label">{l}</span><input className="input" type="number" value={env[k]} onChange={(e) => setEnv({ ...env, [k]: +e.target.value || 1 })} /></label>
              ))}
            </div>
            {est ? (
              <dl className="space-y-1.5 text-sm">
                <div className="flex justify-between"><dt>Storage overhead</dt><dd className="font-semibold">{est.storage_overhead_pct}%</dd></div>
                <div className="flex justify-between text-slate-500"><dt>· signing</dt><dd>{est.signing_overhead_pct}%</dd></div>
                <div className="flex justify-between text-slate-500"><dt>· parity</dt><dd>{est.parity_overhead_pct}%</dd></div>
                <div className="flex justify-between"><dt>Signatures / day</dt><dd>{est.signatures_per_day.toLocaleString()}</dd></div>
                <div className="flex justify-between"><dt>Checkpoints / day</dt><dd>{est.checkpoints_per_day}</dd></div>
                <div className="flex justify-between"><dt>Est. seal time</dt><dd>{est.seal_time_s} s</dd></div>
                <div className="rounded bg-slate-100 p-2 text-xs dark:bg-slate-800">{est.survives}</div>
                <div className="text-[11px] text-slate-500">Formula estimates (design-session constants); benchmarks replace them on liboqs.</div>
              </dl>
            ) : <div className="text-sm text-slate-500">Fix errors to see estimates.</div>}
            {val?.errors?.length > 0 && <ul className="space-y-1 text-sm text-red-700 dark:text-red-400">{val.errors.map((e) => <li key={e}>✕ {e}</li>)}</ul>}
            {val?.warnings?.length > 0 && <ul className="space-y-1 text-xs text-amber-700 dark:text-amber-400">{val.warnings.map((e) => <li key={e}>⚠ {e}</li>)}</ul>}
          </div>
          <div className="card space-y-2">
            <div className="font-semibold">Diff profiles</div>
            <div className="flex gap-2">
              {[0, 1].map((n) => <select key={n} className="input" value={diffAB[n]} onChange={(e) => setDiffAB(n ? [diffAB[0], e.target.value] : [e.target.value, diffAB[1]])}>{all.map((x) => <option key={x}>{x}</option>)}</select>)}
            </div>
            <button className="btn-ghost" onClick={runDiff}>Compare</button>
            {diff && (diff.length ? <table className="w-full text-xs"><tbody>{diff.map((d) => <tr key={d.key} className="border-t border-slate-200 dark:border-slate-800"><td className="py-1 font-mono">{d.key}</td><td>{JSON.stringify(d.a)}</td><td>→ {JSON.stringify(d.b)}</td></tr>)}</tbody></table> : <div className="text-sm">Identical.</div>)}
          </div>
        </div>
      </div>
    </div>
  )
}
