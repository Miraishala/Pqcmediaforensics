import { useEffect, useState } from 'react'
import { api, enc } from '../api.js'
import { go } from '../App.jsx'
import { Chip, Verdict } from '../status.jsx'
import { BundlePicker, Timeline } from './Verify.jsx'

export default function ClipOpen({ params }) {
  const [bundle, setBundle] = useState(params.b || '')
  const [report, setReport] = useState(null)
  const [range, setRange] = useState(null)
  const [opened, setOpened] = useState(null)
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!bundle) return
    setReport(null); setOpened(null); setRange(null); setMsg('')
    api.get(`/api/bundles/${enc(bundle)}/report`).then((r) => {
      setReport(r)
      const d = r.units.filter((u) => u.role === 'data')
      if (d.length) setRange([d[Math.min(1, d.length - 1)].i, d[Math.min(2, d.length - 1)].i])
    })
  }, [bundle])

  function pick(u, e) {
    if (u.role !== 'data' && u.role !== 'gap') return
    if (e.shiftKey && range) setRange([Math.min(range[0], u.i), Math.max(range[0], u.i)])
    else setRange([u.i, u.i])
  }

  async function exportClip() {
    setBusy(true); setMsg('')
    try {
      const r = await api.post(`/api/bundles/${enc(bundle)}/clip`, { i: range[0], j: range[1] })
      setMsg(`✓ Clip exported as ${r.bundle}`)
      setBundle(r.bundle); go('clip', { b: r.bundle })
    } catch (e) { setMsg(`✕ ${e.message}`) }
    setBusy(false)
  }

  async function open(partial = false) {
    setBusy(true); setOpened(null); setMsg('')
    try { setOpened(await api.post(`/api/bundles/${enc(bundle)}/open`, { partial })) }
    catch (e) { setOpened({ refused: true, ...(e.data || {}), message: e.message }) }
    setBusy(false)
  }

  const units = report?.units || []
  const sel = units.filter((u) => range && u.i >= range[0] && u.i <= range[1])
  const t0 = sel[0]?.t ?? 0, t1 = (sel.at(-1)?.t ?? 0) + (sel.at(-1)?.dur ?? 0)
  const isClip = !!report?.clip
  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="h1">Clip &amp; Open</h1>
        <BundlePicker value={bundle} onChange={(b) => { setBundle(b); go('clip', { b }) }} />
      </div>
      {report && (
        <>
          <Verdict overall={report.overall} sub={isClip ? `Standalone clip: units ${report.clip.i}–${report.clip.j} (${report.clip.t_from.toFixed(1)}s–${report.clip.t_to.toFixed(1)}s). Verifies without the source.` : `${report.media.kind} · ${units.length} units`} />
          {!isClip && (
            <div className="card space-y-3">
              <div className="font-semibold">1 · Select a range and export a standalone clip</div>
              <Timeline units={units} selected={range?.[0]} onSelect={pick} range={range} />
              <div className="flex flex-wrap items-center gap-3 text-sm">
                <span>Range: units <b>{range?.[0]}–{range?.[1]}</b> · {t0.toFixed(2)}s → {t1.toFixed(2)}s · {sel.length} unit(s) (+ container header/trailer)</span>
                <button className="btn-primary" disabled={!range || busy} onClick={exportClip}>✂ Export clip</button>
              </div>
            </div>
          )}
          <div className="card space-y-3">
            <div className="font-semibold">{isClip ? '' : '2 · '}Open (verify-to-open)</div>
            <p className="text-sm text-slate-500">Restores the bit-exact {isClip ? 'clip bytes' : 'original'} only if verification passes, plus a playable preview.</p>
            <div className="flex gap-2">
              <button className="btn-primary" disabled={busy} onClick={() => open(false)}>Open {isClip ? 'clip' : 'bundle'}</button>
              <button className="btn-ghost" disabled={busy} onClick={() => open(true)} title="Examiner override: exports only VERIFIED/REPAIRED units">Open verified parts only</button>
            </div>
            {busy && <div className="animate-pulse text-sm">Working…</div>}
            {msg && <div className="text-sm">{msg}</div>}
            {opened?.refused && (
              <div className="rounded-lg border border-red-300 bg-red-50 p-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-950/50 dark:text-red-300">
                ⛔ Refused to open: overall <b>{opened.overall}</b>. {(opened.reasons || []).slice(0, 4).join('; ') || opened.message}
              </div>
            )}
            {opened && !opened.refused && (
              <div className="space-y-3">
                <div className="flex items-center gap-2 text-sm"><Chip status={opened.overall} /> outputs:</div>
                <ul className="space-y-1 text-sm">
                  {opened.outputs.restored && <li>⭳ <a className="text-accent-700 underline" href={opened.outputs.restored}>Restored file</a> {opened.overall === 'VERIFIED' ? '(bit-exact)' : '(partial)'}</li>}
                  {opened.outputs.files && opened.outputs.files.map((f) => <li key={f}>⭳ <a className="text-accent-700 underline" href={f}>{decodeURIComponent(f.split('/').pop())}</a></li>)}
                  <li>⭳ <a className="text-accent-700 underline" href={opened.outputs.report}>Verification report (JSON)</a></li>
                  {opened.outputs.preview_error && <li className="text-amber-700">Preview unavailable: {opened.outputs.preview_error}</li>}
                </ul>
                {opened.outputs.preview && (report.media.kind === 'video'
                  ? <video src={opened.outputs.preview} controls className="max-h-96 rounded-lg bg-black" />
                  : <audio src={opened.outputs.preview} controls />)}
                {opened.outputs.files && <div className="flex flex-wrap gap-2">{opened.outputs.files.map((f) => <img key={f} src={f} alt="" className="h-28 rounded" />)}</div>}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
