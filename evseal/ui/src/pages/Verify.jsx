import { useEffect, useMemo, useState } from 'react'
import { api, enc } from '../api.js'
import { go } from '../App.jsx'
import { Chip, Legend, Verdict, meta } from '../status.jsx'

export function BundlePicker({ value, onChange, filter }) {
  const [list, setList] = useState([])
  const load = () => api.get('/api/bundles').then((d) => setList(d.bundles.filter(filter || (() => true))))
  useEffect(() => { load() }, [])
  return (
    <div className="flex items-center gap-2">
      <select className="input max-w-xl" value={value || ''} onChange={(e) => onChange(e.target.value)}>
        <option value="" disabled>Select a bundle…</option>
        {list.map((b) => (
          <option key={b.name} value={b.name}>
            {b.clip ? '✂ ' : ''}{b.name} · {b.kind} · {b.units} units{b.overall ? ` · ${b.overall}` : ''}
          </option>
        ))}
      </select>
      <button className="btn-ghost" onClick={load} title="Refresh list">⟳</button>
    </div>
  )
}

const short = (h, n = 16) => (h ? `${h.slice(0, n)}…${h.slice(-6)}` : '—')
const fmtT = (t) => { const s = Math.max(0, t); const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60); return `${h ? h + ':' : ''}${String(m).padStart(h ? 2 : 1, '0')}:${(s % 60).toFixed(1).padStart(4, '0')}` }

export function Timeline({ units, selected, onSelect, range }) {
  const [zoom, setZoom] = useState(units.length > 400 ? 3 : units.length > 80 ? 10 : 28)
  return (
    <div>
      <div className="mb-2 flex items-center gap-3 text-xs text-slate-500">
        <span>Zoom</span>
        <input type="range" min="2" max="48" value={zoom} onChange={(e) => setZoom(+e.target.value)} aria-label="Timeline zoom" />
        <span>{units.length} units · cell = 1 unit · click for details{range ? ' · shift-click to set range end' : ''}</span>
      </div>
      <div className="overflow-x-auto rounded-lg border border-slate-200 bg-slate-100 p-2 dark:border-slate-800 dark:bg-slate-950">
        <div className="flex gap-px" style={{ minWidth: units.length * (zoom + 1) }}>
          {units.map((u) => {
            const m = meta(u.status)
            const inRange = range && u.i >= range[0] && u.i <= range[1]
            return (
              <button key={u.i} onClick={(e) => onSelect(u, e)} title={`#${u.i} ${u.role} ${u.status} t=${fmtT(u.t)}`}
                className={`relative h-10 shrink-0 rounded-sm ${m.cls} ${selected === u.i ? 'ring-2 ring-offset-1 ring-slate-900 dark:ring-white' : ''} ${u.role !== 'data' && u.role !== 'gap' ? 'opacity-60' : ''}`}
                style={{ width: zoom }}>
                {zoom >= 14 && <span className="absolute inset-0 flex items-center justify-center text-[11px] font-bold text-white" aria-hidden>{m.icon}</span>}
                {inRange && <span className="absolute -bottom-1.5 left-0 right-0 h-1 rounded bg-accent-600" />}
              </button>
            )
          })}
        </div>
        <div className="mt-1 flex justify-between text-[10px] text-slate-500">
          <span>{fmtT(units[0]?.t ?? 0)}</span><span>{fmtT((units.at(-1)?.t ?? 0) + (units.at(-1)?.dur ?? 0))}</span>
        </div>
      </div>
    </div>
  )
}

function Field({ k, v, mono }) {
  return <div className="grid grid-cols-[120px_1fr] gap-2 py-0.5 text-sm"><span className="text-slate-500">{k}</span><span className={mono ? 'mono' : ''}>{v ?? '—'}</span></div>
}

function UnitDetail({ u, report }) {
  const cert = report.certs.find((c) => c.id === u.cert)
  const ck = [...report.checkpoints].filter((c) => c.i <= u.i).at(-1)
  const tst = ck?.tst?.[0] || report.final?.tst?.[0]
  return (
    <div className="card space-y-3">
      <div className="flex items-center justify-between">
        <div className="font-semibold">Unit #{u.i} <span className="text-sm font-normal text-slate-500">({u.role}{u.name ? ` · ${u.name}` : ''})</span></div>
        <Chip status={u.status} />
      </div>
      {u.detail && <div className="rounded-lg bg-slate-100 p-2 text-sm dark:bg-slate-800">{u.detail}</div>}
      <div>
        <div className="label">Hashes</div>
        <Field k="t / dur" v={`${fmtT(u.t)} / ${u.dur.toFixed(3)} s`} />
        <Field k="Rᵢ (signed)" v={u.R} mono />
        <Field k="Cᵢ (signed)" v={u.C} mono />
      </div>
      <div>
        <div className="label">Signed record</div>
        {u.block ? <>
          <Field k="block" v={`units ${u.block.i_start}–${u.block.i_end}`} />
          <Field k="signature" v={short(u.block.sig, 24)} mono />
        </> : <div className="text-sm text-red-600">✕ no valid signed block covers this unit</div>}
      </div>
      <div>
        <div className="label">Key certificate</div>
        {cert ? <>
          <Field k="id / role" v={`${cert.id} · ${cert.role}`} />
          <Field k="algorithm" v={cert.alg} />
          <Field k="key fp" v={short(cert.fp)} mono />
          <Field k="validity" v={`footage ${cert.t_from}s–${cert.t_to}s · ${new Date(cert.not_before * 1000).toLocaleString()}`} />
          <Field k="root fp" v={short(cert.root_fp)} mono />
        </> : '—'}
      </div>
      <div>
        <div className="label">Checkpoint / timestamp</div>
        <Field k="checkpoint" v={ck ? `#${ck.i} ${ck.valid ? '✓ valid' : '✕ invalid'}` : 'none before this unit (final seal covers it)'} />
        <Field k="timestamp" v={tst ? `${tst.kind} · ${new Date(tst.time * 1000).toLocaleString()}` : '—'} />
      </div>
      <div>
        <div className="label">Repair history</div>
        <div className="text-sm">{u.repaired_chunks?.length ? `rebuilt chunk(s) ${u.repaired_chunks.join(', ')} (in memory; run Repair to write back)` : 'none'}</div>
      </div>
    </div>
  )
}

function ImageViewer({ bundle, unit }) {
  const [overlay, setOverlay] = useState(true)
  const [tiles, setTiles] = useState(null)
  const [tile, setTile] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    setTile(null); setErr('')
    api.get(`/api/bundles/${enc(bundle)}/tiles/${unit.i}`).then(setTiles).catch((e) => setErr(e.message))
  }, [bundle, unit.i])
  const opened = unit.status === 'VERIFIED' || unit.status === 'REPAIRED'
  const src = `/api/bundles/${enc(bundle)}/image/${unit.i}${overlay || !opened ? '?heat=1' : ''}`
  if (err) return <div className="card text-sm text-red-600">✕ {err}</div>
  if (!tiles) return <div className="card text-sm">Loading tiles…</div>
  const canShow = opened || unit.status === 'TAMPERED'
  return (
    <div className="card space-y-3">
      <div className="flex items-center justify-between">
        <div className="font-semibold">{unit.name} <span className="text-sm font-normal text-slate-500">· {tiles.w}×{tiles.h} · {tiles.tile}px tiles · basis {tiles.basis}</span></div>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={overlay} onChange={(e) => setOverlay(e.target.checked)} disabled={!opened} /> Tile overlay</label>
      </div>
      {canShow ? (
        <div className="relative inline-block max-w-full">
          <img src={src} alt={unit.name} className="block max-h-[480px] max-w-full rounded" style={{ imageRendering: 'pixelated' }} />
          <div className="absolute inset-0 grid" style={{ gridTemplateColumns: `repeat(${Math.ceil(tiles.w / tiles.tile)}, 1fr)`, gridTemplateRows: `repeat(${Math.ceil(tiles.h / tiles.tile)}, 1fr)` }}>
            {tiles.tiles.sort((a, b) => a.y - b.y || a.x - b.x).map((t) => (
              <button key={`${t.x},${t.y}`} onClick={() => setTile(t)} title={`tile ${t.x},${t.y}: ${t.status}`}
                className={`border border-transparent hover:border-white ${tile && tile.x === t.x && tile.y === t.y ? 'border-white ring-2 ring-slate-900' : ''}`} />
            ))}
          </div>
        </div>
      ) : <div className="rounded-lg bg-slate-100 p-6 text-center text-sm dark:bg-slate-800">{meta(unit.status).icon} Not opened: unit is {unit.status}. Verify-to-open refuses unverified data.</div>}
      {!opened && unit.status === 'TAMPERED' && <div className="text-xs text-slate-500">Shown only as an overlay on the tampered bytes, never as evidence.</div>}
      {tiles.metadata_changed.length > 0 && <div className="text-sm">ⓘ Metadata leaves changed: <span className="mono">{tiles.metadata_changed.join(', ')}</span></div>}
      <Legend statuses={[...new Set(tiles.tiles.map((t) => t.status))]} />
      {tile && (
        <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-700">
          <div className="mb-1 flex items-center gap-2 font-medium">Tile ({tile.x}, {tile.y}) <Chip status={tile.status} small /></div>
          <Field k="signed leaf" v={tile.leaf} mono />
          <Field k="perceptual" v={tile.perceptual ? short(tile.perceptual, 32) : 'off'} mono />
          {tile.confidence !== undefined && <Field k="confidence" v={`${tile.confidence} (advisory, Δ=${tile.distance})`} />}
        </div>
      )}
    </div>
  )
}

function Compare({ bundle, unit }) {
  const [res, setRes] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  async function run(file) {
    setBusy(true); setErr(''); setRes(null)
    const fd = new FormData(); fd.append('unit', unit.i); fd.append('file', file)
    try { setRes(await api.form(`/api/bundles/${enc(bundle)}/compare`, fd)) } catch (e) { setErr(e.message) }
    setBusy(false)
  }
  const counts = {}
  for (const t of res?.tiles || []) counts[t.status] = (counts[t.status] || 0) + 1
  return (
    <div className="card space-y-2">
      <div className="font-semibold">Check an external copy of {unit.name}</div>
      <p className="text-sm text-slate-500">Upload a copy (e.g. one shared on a phone). Tiles are checked cryptographically; recompressed copies fall back to the signed perceptual layer (advisory only).</p>
      <input type="file" accept="image/*" disabled={busy} onChange={(e) => e.target.files[0] && run(e.target.files[0])} className="text-sm" />
      {err && <div className="text-sm text-red-600">✕ {err}</div>}
      {res && (
        <div className="space-y-2">
          <div className="flex items-center gap-2"><Chip status={res.verdict} /> <span className="text-sm text-slate-500">{res.detail}</span></div>
          <div className="flex flex-wrap gap-2">{Object.entries(counts).map(([s, n]) => <span key={s} className="flex items-center gap-1"><Chip status={s} small /> × {n}</span>)}</div>
          {res.heatmap_png && <img src={`data:image/png;base64,${res.heatmap_png}`} alt="comparison heatmap" className="max-h-80 rounded" style={{ imageRendering: 'pixelated' }} />}
        </div>
      )}
    </div>
  )
}

function TamperDemo({ bundle }) {
  const [list, setList] = useState([])
  const [atk, setAtk] = useState('reencrypt_edit')
  const [seed, setSeed] = useState(1)
  const [err, setErr] = useState('')
  useEffect(() => { api.get('/api/attacks').then((d) => setList(d.attacks)) }, [])
  async function run() {
    setErr('')
    try { const r = await api.post(`/api/bundles/${enc(bundle)}/tamper`, { attack: atk, seed }); go('verify', { b: r.bundle }) } catch (e) { setErr(e.message) }
  }
  return (
    <details className="card">
      <summary className="cursor-pointer font-semibold">Try an attack on a copy (Stress Lab preview)</summary>
      <div className="mt-3 flex flex-wrap items-end gap-2">
        <label className="min-w-64 flex-1"><span className="label">Attack / fault</span>
          <select className="input" value={atk} onChange={(e) => setAtk(e.target.value)}>
            {list.map((a) => <option key={a.name} value={a.name}>{a.name} · {a.doc}</option>)}
          </select>
        </label>
        <label className="w-24"><span className="label">Seed</span><input className="input" type="number" value={seed} onChange={(e) => setSeed(+e.target.value)} /></label>
        <button className="btn-primary" onClick={run}>Create tampered copy & verify</button>
      </div>
      {err && <div className="mt-2 text-sm text-red-600">✕ {err}</div>}
      <p className="mt-2 text-xs text-slate-500">The original bundle is never modified; the copy is named after the attack and seed.</p>
    </details>
  )
}

export default function Verify({ params }) {
  const [bundle, setBundle] = useState(params.b || '')
  const [report, setReport] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [sel, setSel] = useState(null)

  useEffect(() => {
    if (!bundle) return
    setBusy(true); setErr(''); setReport(null); setSel(null)
    api.post(`/api/bundles/${enc(bundle)}/verify`).then((r) => {
      setReport(r)
      const firstBad = r.units.find((u) => u.status !== 'VERIFIED') || r.units.find((u) => u.role === 'data')
      setSel(firstBad?.i ?? null)
    }).catch((e) => setErr(e.message)).finally(() => setBusy(false))
  }, [bundle])

  const unit = report?.units.find((u) => u.i === sel)
  const isImage = report?.media?.kind === 'image'
  const failedChecks = useMemo(() => (report?.checks || []).filter((c) => !c.ok), [report])
  function exportJson() {
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([JSON.stringify(report, null, 1)], { type: 'application/json' }))
    a.download = `${bundle}.report.json`; a.click()
  }

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="h1">Verify</h1>
        <BundlePicker value={bundle} onChange={(b) => { setBundle(b); go('verify', { b }) }} />
      </div>
      {busy && <div className="card animate-pulse text-sm">Verifying signatures, chain, AEAD and hashes…</div>}
      {err && <div className="card text-sm text-red-600">✕ {err}</div>}
      {report && (
        <>
          <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
            <Verdict overall={report.overall} sub={`${report.media.kind} · ${report.media.source_name || ''}${report.clip ? ` · clip of units ${report.clip.i}–${report.clip.j}` : ''} · manifest from ${report.manifest_source}`} />
            <div className="flex items-center gap-2">
              <button className="btn-ghost" onClick={exportJson}>⭳ Export report JSON</button>
              <button className="btn-ghost" onClick={() => go('clip', { b: bundle })}>✂ Clip & Open</button>
              {Object.keys(report.counts).some((s) => s === 'CORRUPT' || s === 'REPAIRED') && <button className="btn-ghost" onClick={() => go('repair', { b: bundle })}>↻ Repair</button>}
            </div>
          </div>
          <div className="flex flex-wrap gap-3 text-sm">
            {Object.entries(report.counts).map(([s, n]) => <span key={s} className="flex items-center gap-1"><Chip status={s} /> × {n}</span>)}
          </div>
          {failedChecks.length > 0 && (
            <div className="card border-red-200 dark:border-red-900">
              <div className="mb-1 font-semibold text-red-700 dark:text-red-400">Why it is not VERIFIED</div>
              <ul className="list-inside list-disc text-sm">{failedChecks.map((c, k) => <li key={k}><b>{c.name}</b>: {c.detail}</li>)}</ul>
            </div>
          )}
          {isImage ? (
            <div className="card">
              <div className="label">Image set filmstrip (chained order)</div>
              <div className="flex gap-3 overflow-x-auto pb-2">
                {report.units.map((u) => {
                  const ok = u.status === 'VERIFIED' || u.status === 'REPAIRED'
                  return (
                    <button key={u.i} onClick={() => setSel(u.i)} className={`w-36 shrink-0 rounded-lg border p-1.5 text-left ${sel === u.i ? 'border-accent-600 ring-2 ring-accent-500' : 'border-slate-200 dark:border-slate-700'}`}>
                      <div className="flex h-24 items-center justify-center overflow-hidden rounded bg-slate-100 dark:bg-slate-800">
                        {ok || u.status === 'TAMPERED' ? <img src={`/api/bundles/${enc(bundle)}/image/${u.i}${ok ? '' : '?heat=1'}`} alt={u.name} className="max-h-24" /> : <span className="text-2xl" aria-hidden>{meta(u.status).icon}</span>}
                      </div>
                      <div className="mt-1 truncate text-xs">#{u.i} {u.name || u.detail}</div>
                      <Chip status={u.status} small />
                    </button>
                  )
                })}
              </div>
            </div>
          ) : (
            <div className="card"><div className="label">Timeline</div><Timeline units={report.units} selected={sel} onSelect={(u) => setSel(u.i)} /></div>
          )}
          <div className={`grid gap-4 ${isImage ? 'lg:grid-cols-[1.4fr_1fr]' : 'lg:grid-cols-[1fr_1fr]'}`}>
            {unit && isImage && unit.role === 'data' && <ImageViewer bundle={bundle} unit={unit} />}
            {unit && <UnitDetail u={unit} report={report} />}
            {!isImage && (
              <div className="card space-y-2">
                <div className="label">Global checks</div>
                <ul className="space-y-1 text-sm">{report.checks.map((c, k) => <li key={k} className="flex gap-2"><span className={c.ok ? 'text-emerald-600' : 'text-red-600'} aria-hidden>{c.ok ? '✓' : '✕'}</span><span><b>{c.name}</b>{c.detail && <span className="text-slate-500"> · {c.detail}</span>}</span></li>)}</ul>
              </div>
            )}
          </div>
          {unit && isImage && unit.role === 'data' && (unit.status === 'VERIFIED' || unit.status === 'REPAIRED') && <Compare bundle={bundle} unit={unit} />}
          <TamperDemo bundle={bundle} />
        </>
      )}
    </div>
  )
}
