async function req(method, url, body, isForm) {
  const opts = { method, headers: {} }
  if (body !== undefined) {
    if (isForm) opts.body = body
    else { opts.body = JSON.stringify(body); opts.headers['Content-Type'] = 'application/json' }
  }
  const r = await fetch(url, opts)
  const ct = r.headers.get('content-type') || ''
  const data = ct.includes('json') ? await r.json() : await r.text()
  if (!r.ok) {
    const d = data?.detail ?? data
    const msg = typeof d === 'string' ? d : (d?.errors ? d.errors.join('; ') : JSON.stringify(d))
    const err = new Error(msg || r.statusText); err.status = r.status; err.data = data; throw err
  }
  return data
}
export const api = {
  get: (u) => req('GET', u),
  post: (u, b) => req('POST', u, b ?? {}),
  put: (u, b) => req('PUT', u, b),
  del: (u) => req('DELETE', u),
  form: (u, fd) => req('POST', u, fd, true),
}
export const enc = encodeURIComponent
