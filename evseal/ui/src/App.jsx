import { useEffect, useState } from 'react'
import Profiles from './pages/Profiles.jsx'
import Keys from './pages/Keys.jsx'
import Seal from './pages/Seal.jsx'
import Verify from './pages/Verify.jsx'
import ClipOpen from './pages/ClipOpen.jsx'
import Repair from './pages/Repair.jsx'
import Doctor from './pages/Doctor.jsx'

const PAGES = [
  { id: 'seal', label: 'Seal', icon: '⬢', C: Seal },
  { id: 'verify', label: 'Verify', icon: '✓', C: Verify },
  { id: 'clip', label: 'Clip & Open', icon: '✂', C: ClipOpen },
  { id: 'repair', label: 'Repair', icon: '↻', C: Repair },
  { id: 'profiles', label: 'Profiles', icon: '⚙', C: Profiles },
  { id: 'keys', label: 'Keys', icon: '⚿', C: Keys },
  { id: 'doctor', label: 'Environment', icon: '⌁', C: Doctor },
]

// Hash routing: #/verify?b=name
function parse() {
  const [path, q] = (window.location.hash.slice(2) || 'seal').split('?')
  return { page: path || 'seal', params: Object.fromEntries(new URLSearchParams(q || '')) }
}
export function go(page, params = {}) {
  const q = new URLSearchParams(params).toString()
  window.location.hash = `/${page}${q ? '?' + q : ''}`
}

export default function App() {
  const [route, setRoute] = useState(parse())
  const [dark, setDark] = useState(() => {
    try { return localStorage.getItem('theme') ? localStorage.getItem('theme') === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches } catch { return false }
  })
  useEffect(() => { const f = () => setRoute(parse()); addEventListener('hashchange', f); return () => removeEventListener('hashchange', f) }, [])
  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
    try { localStorage.setItem('theme', dark ? 'dark' : 'light') } catch { /* private mode */ }
  }, [dark])
  const page = PAGES.find((p) => p.id === route.page) || PAGES[0]
  const Page = page.C
  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="flex items-center gap-2 px-4 py-4">
          <img src="/favicon.svg" alt="" className="h-7 w-7" />
          <div>
            <div className="font-semibold leading-tight">EviSeal</div>
            <div className="text-[11px] text-slate-500">PQ sealed evidence</div>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 px-2">
          {PAGES.map((p) => (
            <a key={p.id} href={`#/${p.id}`}
              className={`flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm ${p.id === page.id ? 'bg-accent-50 font-semibold text-accent-700 dark:bg-accent-700/20 dark:text-accent-500' : 'hover:bg-slate-100 dark:hover:bg-slate-800'}`}>
              <span className="w-4 text-center" aria-hidden>{p.icon}</span>{p.label}
            </a>
          ))}
        </nav>
        <div className="space-y-2 p-3 text-xs text-slate-500">
          <button className="btn-ghost w-full justify-center" onClick={() => setDark(!dark)}>{dark ? '☀ Light' : '☾ Dark'} theme</button>
          <div className="rounded-lg bg-amber-50 p-2 text-amber-800 dark:bg-amber-950/50 dark:text-amber-300">DEV build: pure-Python PQ fallback, file-based keys. Not for real evidence.</div>
        </div>
      </aside>
      <main className="min-w-0 flex-1 overflow-y-auto p-6">
        <Page params={route.params} key={page.id + JSON.stringify(route.params)} />
      </main>
    </div>
  )
}
