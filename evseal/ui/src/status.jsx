// Status is always colour + icon + text (SPEC §6: never colour alone).
export const STATUS = {
  VERIFIED: { icon: '✓', cls: 'bg-emerald-500', chip: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-300', text: 'Verified' },
  REPAIRED: { icon: '↻', cls: 'bg-sky-500', chip: 'bg-sky-100 text-sky-800 dark:bg-sky-900/50 dark:text-sky-300', text: 'Repaired' },
  CORRUPT: { icon: '✕', cls: 'bg-violet-600', chip: 'bg-violet-100 text-violet-800 dark:bg-violet-900/50 dark:text-violet-300', text: 'Corrupt' },
  TAMPERED: { icon: '⚠', cls: 'bg-red-600', chip: 'bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300', text: 'Tampered' },
  SEQUENCE_ERROR: { icon: '⇄', cls: 'bg-orange-500', chip: 'bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-300', text: 'Sequence error' },
  GAP_DECLARED: { icon: '∅', cls: 'bg-slate-400', chip: 'bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300', text: 'Gap declared' },
  UNSEALED_TAIL: { icon: '…', cls: 'bg-amber-400', chip: 'bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-300', text: 'Unsealed tail' },
  METADATA_CHANGED: { icon: 'ⓘ', cls: 'bg-yellow-400', chip: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300', text: 'Metadata changed' },
  LIKELY_EDITED: { icon: '≈', cls: 'bg-orange-400', chip: 'bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-300', text: 'Likely edited (advisory)' },
  DERIVED_COPY: { icon: '⧉', cls: 'bg-cyan-500', chip: 'bg-cyan-100 text-cyan-800 dark:bg-cyan-900/50 dark:text-cyan-300', text: 'Derived copy' },
  RECOMPRESSED: { icon: '≋', cls: 'bg-slate-500', chip: 'bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300', text: 'Recompressed copy' },
  UNVERIFIED: { icon: '?', cls: 'bg-slate-300', chip: 'bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300', text: 'Unverified (no perceptual signal)' },
  UNRELATED: { icon: '✕', cls: 'bg-slate-500', chip: 'bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300', text: 'Unrelated image' },
  UNVERIFIABLE: { icon: '?', cls: 'bg-slate-500', chip: 'bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300', text: 'Unverifiable' },
  NOT_VERIFIED: { icon: '✕', cls: 'bg-red-600', chip: 'bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300', text: 'Not verified' },
  REJECTED: { icon: '⛔', cls: 'bg-red-800', chip: 'bg-red-200 text-red-900 dark:bg-red-950 dark:text-red-200', text: 'Rejected' },
}
const FALLBACK = { icon: '•', cls: 'bg-slate-400', chip: 'bg-slate-200 text-slate-700', text: '' }
export const meta = (s) => STATUS[s] || { ...FALLBACK, text: s }

export function Chip({ status, small }) {
  const m = meta(status)
  return (
    <span className={`inline-flex items-center gap-1 rounded-full font-medium ${m.chip} ${small ? 'px-1.5 py-0 text-[11px]' : 'px-2 py-0.5 text-xs'}`}>
      <span aria-hidden>{m.icon}</span>{m.text || status}
    </span>
  )
}

export function Verdict({ overall, sub }) {
  const m = meta(overall)
  const tone = overall === 'VERIFIED' ? 'border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-200'
    : 'border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950/60 dark:text-red-200'
  return (
    <div className={`flex items-center gap-4 rounded-xl border px-5 py-4 ${tone}`}>
      <div className="text-4xl leading-none" aria-hidden>{m.icon}</div>
      <div>
        <div className="text-2xl font-bold tracking-tight">{overall.replace('_', ' ')}</div>
        {sub && <div className="text-sm opacity-80">{sub}</div>}
      </div>
    </div>
  )
}

export function Legend({ statuses }) {
  return (
    <div className="flex flex-wrap gap-2">
      {statuses.map((s) => <Chip key={s} status={s} small />)}
    </div>
  )
}
