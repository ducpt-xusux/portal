export function consoleSocketUrl(session, portalOrigin) {
  const url = new URL(session.url), path = url.searchParams.get('path')
  const socket = new URL(url.origin)
  socket.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  if (path) {
    const at = path.indexOf('?')
    socket.pathname = '/' + path.slice(0, at).replace(/^\//, '')
    socket.search = path.slice(at)
  } else {
    socket.pathname = '/websockify'
    socket.search = new URLSearchParams({ token: url.searchParams.get('token') }).toString()
  }
  if (portalOrigin) {
    const local = new URL(portalOrigin)
    local.protocol = local.protocol === 'https:' ? 'wss:' : 'ws:'
    local.pathname = '/console-ws' + socket.pathname
    local.search = socket.search
    return local.toString()
  }
  return socket.toString()
}

export function typingText(value, allowNewlines = false) {
  const text = value.replace(/\r\n?/g, '\n')
  if (!text || text.length > 2000) throw new Error('Nhập từ 1 đến 2.000 ký tự.')
  if (/[^\x20-\x7e\n]/.test(text)) throw new Error('Hiện hỗ trợ chữ không dấu và ký hiệu ASCII. Không hỗ trợ Tab hoặc ký tự điều khiển.')
  if (!allowNewlines && text.includes('\n')) throw new Error('Nội dung có xuống dòng. Bật tùy chọn Enter hoặc sửa thành một dòng.')
  return text
}

export async function typeConsoleText(text, { sendKey, signal, connected, pause = () => new Promise(resolve => setTimeout(resolve, 20)), progress = () => {} }) {
  for (let i = 0; i < text.length; i++) {
    if (signal.aborted || !connected()) return { complete: false, sent: i }
    const char = text[i], key = asciiKey(char)
    if (key.shift) sendKey(0xffe1, 'ShiftLeft', true)
    try { sendKey(char === '\n' ? 0xff0d : char.charCodeAt(0), key.code) }
    finally { if (key.shift) sendKey(0xffe1, 'ShiftLeft', false) }
    progress(i + 1)
    await pause()
  }
  return { complete: true, sent: text.length }
}

export function asciiKey(char) {
  if (/[a-z]/i.test(char)) return { code: 'Key' + char.toUpperCase(), shift: char !== char.toLowerCase() }
  if (/[0-9]/.test(char)) return { code: 'Digit' + char, shift: false }
  const plain = '`-=[]\\;\',./', shifted = '~_+{}|:"<>?', codes = ['Backquote','Minus','Equal','BracketLeft','BracketRight','Backslash','Semicolon','Quote','Comma','Period','Slash']
  let at = plain.indexOf(char)
  if (at >= 0) return { code: codes[at], shift: false }
  at = shifted.indexOf(char)
  if (at >= 0) return { code: codes[at], shift: true }
  at = ')!@#$%^&*('.indexOf(char)
  if (at >= 0) return { code: 'Digit' + at, shift: true }
  return { code: char === '\n' ? 'Enter' : 'Space', shift: false }
}
