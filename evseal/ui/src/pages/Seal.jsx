import { useEffect, useRef, useState } from 'react'
import { api } from '../api.js'
import { go } from '../App.jsx'

const STAGES = [
  ['segment', 'Segment / order units'],
  ['hash', 'Hash ∥ (dual content hash, tile Merkle)'],
  ['chain', 'Chain fold Cᵢ = Hc(i ‖ Rᵢ ‖ Cᵢ₋₁)'],
  ['seal', 'Sign + encrypt ∥ (verify-to-open)'],
  ['parity', 'Parity (Reed–Solomon stripes)'],
  ['finalize', 'Final seal + manifest copies'],
]

export default function Seal() {
  const [profiles, setProfiles] = useState({ presets: [], saved: [] })
  const [keys, setKeys] = useState([])
  const [files, setFiles] = useState([])
  const [profile, setProfile] = useState('court-grade')
  const [key, setKey] = useState('')
  const [name, setName] = useState('')
  const [job, setJob] = useState(null)
  const [stage, setStage] = useState({})
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const fileRef = useRef(), dirRef = useRef()

  useEffect(() => {
    api.get('/api/profiles').then(setProfiles)
    api.get('/api/keys').then((d) => { setKeys(d.keys.filter((k) => k.has_private)); if (d.keys[0]) setKey(d.keys.find((k) => k.has_private)?.name || '') })
  }, [])

  async function quickKey() {
    const k = await api.post('/api/keys', { name: 'collector', alg: 'ML-DSA-87' })
    setKeys([...keys, { ...k, has_private: true }]); setKey(k.name)
  }

  async function start() {
    setErr(''); setBusy(true); setStage({})
    try {
      const fd = new FormData()
      for (const f of files) fd.append('files', f, f.name)
      setStage({ upload: 'running' })
      const up = await api.form('/api/uploads', fd)
      const j = await api.post('/api/seal', { upload_id: up.upload_id, profile, key, name: name || undefined })
      setJob(j)
      const es = new EventSource(`/api/jobs/${j.job}/events`)
      es.onmessage = (e) => {
        const ev = JSON.parse(e.data)
        if (ev.stage === 'end') {
          es.close(); setBusy(false)
          if (ev.status === 'error') setErr(ev.error)
          else setStage((s) => ({ ...s, done: true }))
          return
        }
        setStage((s) => {
          const order = STAGES.map((x) => x[0]); const k = order.indexOf(ev.stage)
          const next = { ...s, upload: 'ok' }
          order.forEach((o, idx) => { if (idx < k) next[o] = 'ok' })
          if (ev.stage === 'done') order.forEach((o) => { next[o] = 'ok' })
          else next[ev.stage] = ev.total ? `${ev.done}/${ev.total}` : 'running'
          return next
        })
      }
      es.onerror = () => { es.close(); setBusy(false) }
    } catch (e) { setErr(e.message); setBusy(false) }
  }

  const total = files.reduce((a, f) => a + f.size, 0)
  return (
    <div className="mx-auto max-w-4xl space-y-5">
      <div>
        <h1 className="h1">Seal evidence</h1>
        <p className="text-sm text-slate-500">One video or audio file per bundle, or a set of photos (sealed as one ordered, chained set).</p>
      </div>
      <div className="card grid gap-4 md:grid-cols-2">
        <div className="md:col-span-2">
          <span className="label">Input</span>
          <div className="flex flex-wrap gap-2">
            <button className="btn-ghost" onClick={() => fileRef.current.click()}>Choose file(s)…</button>
            <button className="btn-ghost" onClick={() => dirRef.current.click()}>Choose photo folder…</button>
            <input ref={fileRef} type="file" multiple hidden onChange={(e) => setFiles([...e.target.files])} />
            <input ref={dirRef} type="file" webkitdirectory="" hidden onChange={(e) => setFiles([...e.target.files])} />
          </div>
          {files.length > 0 && (
            <div className="mt-2 text-sm text-slate-600 dark:text-slate-400">
              {files.length} file(s), {(total / 1e6).toFixed(2)} MB: {files.slice(0, 6).map((f) => f.name).join(', ')}{files.length > 6 ? '…' : ''}
            </div>
          )}
        </div>
        <label>
          <span className="label">Profile</span>
          <select className="input" value={profile} onChange={(e) => setProfile(e.target.value)}>
            <optgroup label="Presets">{profiles.presets.map((p) => <option key={p}>{p}</option>)}</optgroup>
            {profiles.saved.length > 0 && <optgroup label="Saved">{profiles.saved.map((p) => <option key={p}>{p}</option>)}</optgroup>}
          </select>
        </label>
        <label>
          <span className="label">Collector (root) key</span>
          {keys.length ? (
            <select className="input" value={key} onChange={(e) => setKey(e.target.value)}>
              {keys.map((k) => <option key={k.name} value={k.name}>{k.name} · {k.alg} · {k.fp.slice(0, 12)}</option>)}
            </select>
          ) : <button className="btn-primary" onClick={quickKey}>Generate a collector key (ML-DSA-87)</button>}
        </label>
        <label className="md:col-span-2">
          <span className="label">Bundle name (optional)</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value.replace(/[^A-Za-z0-9._-]/g, '-'))} placeholder="auto" />
        </label>
        <div className="md:col-span-2 flex items-center gap-3">
          <button className="btn-primary" disabled={!files.length || !key || busy} onClick={start}>{busy ? 'Sealing…' : 'Seal'}</button>
          {err && <span className="text-sm text-red-600">✕ {err}</span>}
        </div>
      </div>

      {(job || stage.upload) && (
        <div className="card">
          <div className="mb-3 flex items-center justify-between">
            <div className="font-medium">Progress {job && <span className="mono text-slate-500">· {job.bundle}</span>}</div>
            {stage.done && <button className="btn-primary" onClick={() => go('verify', { b: job.bundle })}>Verify bundle →</button>}
          </div>
          <ol className="space-y-1.5">
            {[['upload', 'Upload'], ...STAGES].map(([k, label]) => {
              const s = stage[k]
              const ok = s === 'ok' || stage.done
              return (
                <li key={k} className="flex items-center gap-3 text-sm">
                  <span className={`flex h-5 w-5 items-center justify-center rounded-full text-[11px] text-white ${ok ? 'bg-emerald-500' : s ? 'animate-pulse bg-accent-500' : 'bg-slate-300 dark:bg-slate-700'}`} aria-hidden>{ok ? '✓' : s ? '•' : ''}</span>
                  <span className={ok ? '' : s ? 'font-medium' : 'text-slate-400'}>{label}</span>
                  {s && !ok && <span className="mono text-slate-500">{s}</span>}
                  {ok && <span className="sr-only">done</span>}
                </li>
              )
            })}
          </ol>
        </div>
      )}
    </div>
  )
}
