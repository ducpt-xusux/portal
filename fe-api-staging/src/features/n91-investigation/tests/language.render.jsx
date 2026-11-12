import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import assert from 'node:assert/strict'
import Sidebar from '../../../components/Sidebar.jsx'
import { Badge, FieldGrid, SelectFilter } from '../../../portal/PortalUI.jsx'

export function runLanguageRenderCases() {
  const previous = globalThis.window
  // SSR-only viewport stub; no browser or computer interaction.
  globalThis.window = { matchMedia: () => ({ matches: false }) }
  try {
    const sidebar = renderToStaticMarkup(<Sidebar mode="v4" user={{ login: 'ACTIVE', role: 'Viewer' }} />)
    assert.match(sidebar, /Trang chủ/)
    assert.match(sidebar, /Sự kiện bảo mật/)
    assert.match(sidebar, /href="#\/dashboard"/)
    assert.doesNotMatch(sidebar, />Dashboard</)
    assert.match(sidebar, />ACTIVE</)
    const status = renderToStaticMarkup(<Badge value="BLOCK" />)
    assert.match(status, /v4-badge danger/)
    assert.match(status, /Chặn/)
    const fields = renderToStaticMarkup(<FieldGrid rows={[
      ['Tên máy ảo', 'ACTIVE'], ['Mã sự cố', 'INC-TEST-1'], ['Tên Security Group', 'PRIMARY'],
    ]} />)
    assert.match(fields, /<dd>ACTIVE<\/dd>/)
    assert.match(fields, /<dd>PRIMARY<\/dd>/)
    assert.match(fields, /INC-TEST-1/)
    const filter = renderToStaticMarkup(<SelectFilter label="Quyết định" value="BLOCK" options={[
      ['', 'Tất cả'], ['ALLOW', 'Cho phép'], ['BLOCK', 'Chặn'],
    ]} onChange={() => {}} />)
    assert.match(filter, /value="BLOCK" selected="">Chặn/)
    assert.match(filter, /value="ALLOW">Cho phép/)
    return { checks: 4, browser_verified: false, kind: 'SSR_LANGUAGE_AND_WIRE_VALUES' }
  } finally {
    if (previous === undefined) delete globalThis.window
    else globalThis.window = previous
  }
}
