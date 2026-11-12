import { uiLabel, uiRoleList } from '../services/uiLanguage.js'
import { useEffect, useRef, useState } from 'react'
import {
  consoleSocketUrl,
  typingText,
  typeConsoleText,
} from '../services/consoleTyping'

export default function NativeConsole({ session }) {
  const target = useRef(null),
    client = useRef(null),
    connected = useRef(false),
    job = useRef(null)
  const [status, setStatus] = useState('Đang kết nối noVNC…'),
    [ready, setReady] = useState(false)
  const [text, setText] = useState(''),
    [newlines, setNewlines] = useState(false),
    [sending, setSending] = useState(false)
  const [notice, setNotice] = useState(''),
    [sent, setSent] = useState(0)
  useEffect(() => {
    let rfb,
      disposed = false
    const start = async () => {
      try {
        const { default: RFB } = await import('@novnc/novnc')
        if (disposed) return
        rfb = new RFB(
          target.current,
          consoleSocketUrl(session, window.location.origin),
          { shared: true }
        )
        client.current = rfb
        rfb.scaleViewport = true
        rfb.resizeSession = false
        rfb.addEventListener('connect', () => {
          if (!disposed) {
            connected.current = true
            setReady(true)
            setStatus('Đã kết nối QEMU')
          }
        })
        rfb.addEventListener('disconnect', () => {
          connected.current = false
          job.current?.abort()
          if (!disposed) {
            setReady(false)
            setStatus('Console đã ngắt kết nối. Hãy lấy phiên mới.')
          }
        })
        rfb.addEventListener('securityfailure', () => {
          if (!disposed)
            setStatus('Không xác thực được phiên noVNC. Hãy lấy phiên mới.')
        })
        rfb.addEventListener('credentialsrequired', () => {
          if (!disposed)
            setStatus('VNC yêu cầu xác thực bổ sung. Hãy dùng tab noVNC riêng.')
          rfb.disconnect()
        })
      } catch {
        setStatus('Chưa mở được noVNC. Hãy lấy phiên mới hoặc mở ở tab mới.')
      }
    }
    start()
    return () => {
      disposed = true
      connected.current = false
      job.current?.abort()
      client.current = null
      rfb?.disconnect()
    }
  }, [session])
  const send = async () => {
    if (!connected.current || job.current) return
    let value
    try {
      value = typingText(text, newlines)
    } catch (error) {
      setNotice(error.message)
      return
    }
    const controller = new AbortController(),
      rfb = client.current
    job.current = controller
    rfb.blur()
    rfb.viewOnly = true
    setSending(true)
    setSent(0)
    setNotice('')
    try {
      const result = await typeConsoleText(value, {
        signal: controller.signal,
        connected: () => connected.current,
        sendKey: (...args) => {
          rfb.viewOnly = false
          try {
            rfb.sendKey(...args)
          } finally {
            rfb.viewOnly = true
          }
        },
        progress: setSent,
      })
      if (client.current !== rfb) return
      setNotice(
        result.complete
          ? `Đã gửi ${result.sent} ký tự. Kiểm tra màn hình VM; không tự thêm Enter.`
          : `Đã dừng sau ${result.sent} ký tự. Nội dung đã gửi vẫn còn trên VM.`
      )
      if (result.complete) setText('')
    } catch {
      if (client.current === rfb)
        setNotice('Gửi bị gián đoạn; kiểm tra màn hình VM trước khi gửi lại.')
    } finally {
      rfb.viewOnly = false
      job.current = null
      if (client.current === rfb) setSending(false)
    }
  }
  return (
    <>
      <p className="v4-panel-note" role="status">
        {uiLabel(status)}
      </p>
      <div
        ref={target}
        className="v4-console-native"
        aria-label="Màn hình console VM"
      />
      <div className="v4-console-paste">
        <label htmlFor="console-paste">Dán văn bản từ máy của bạn</label>
        <p>
          Dán bằng chuột phải → Paste hoặc Ctrl+V vào ô này, rồi nhấn Gửi vào
          console. Chọn đúng dấu nhắc trên VM trước khi gửi. Hỗ trợ chữ không
          dấu và ký hiệu ASCII; kết quả phụ thuộc bố cục bàn phím của VM.
        </p>
        <textarea
          id="console-paste"
          rows={4}
          maxLength={2000}
          value={text}
          disabled={sending}
          onChange={(event) => {
            setText(event.target.value)
            setNotice('')
          }}
          autoComplete="off"
          spellCheck={false}
          placeholder="Dán nội dung tại đây · tối đa 2.000 ký tự"
        />
        <label className="v4-console-newlines">
          <input
            type="checkbox"
            checked={newlines}
            disabled={sending}
            onChange={(event) => setNewlines(event.target.checked)}
          />
          Cho phép xuống dòng: mỗi xuống dòng gửi Enter và có thể chạy lệnh.
        </label>
        <div className="v4-console-actions">
          <button
            className="button primary"
            onClick={send}
            disabled={!ready || sending || !text}
          >
            Gửi vào console
          </button>
          <button
            className="button secondary"
            onClick={() => setText('')}
            disabled={sending || !text}
          >
            Xóa nội dung
          </button>
          {sending && (
            <button
              className="button secondary"
              onClick={() => job.current?.abort()}
            >
              Dừng gửi
            </button>
          )}
          <span aria-live="polite">
            {sending ? `Đang gửi: ${sent} ký tự` : `${text.length}/2.000 ký tự`}
          </span>
        </div>
        {notice && <p role="status">{notice}</p>}
      </div>
    </>
  )
}
