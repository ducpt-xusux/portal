import { useEffect, useRef, useState } from 'react'
import { Monitor } from 'lucide-react'
import NativeConsole from './NativeConsole'
import { freshness } from '../services/portalApi'
import { createConsole, consoleMessage } from '../services/consoleApi'
import { useV4Resource } from './IncidentPages'
import { Badge, Panel, useTime } from './PortalUI'

export default function WorkloadConsole({ vm, meta, error }) {
  const time = useTime()
  const capability = useV4Resource(
    `/workloads/${encodeURIComponent(vm.server_id)}/console`,
    { interval: 0 }
  )
  const [session, setSession] = useState(null),
    [failure, setFailure] = useState(null),
    [pending, setPending] = useState(false)
  const operation = useRef(null)
  useEffect(() => () => operation.current?.abort(), [])
  const state =
    freshness(meta, Boolean(error)) === 'FRESH' ? vm.nova_status : 'UNKNOWN'
  const connect = async () => {
    if (operation.current) return
    const controller = new AbortController()
    operation.current = controller
    setPending(true)
    setFailure(null)
    setSession(null)
    try {
      setSession(
        await createConsole(vm.server_id, capability.data, {
          signal: controller.signal,
        })
      )
    } catch (err) {
      if (!controller.signal.aborted) setFailure(err)
    } finally {
      if (!controller.signal.aborted) {
        operation.current = null
        setPending(false)
      }
    }
  }
  return (
    <section aria-label="Console máy ảo">
      <Panel
        title="Console máy ảo"
        subtitle="noVNC · màn hình quản trị máy ảo"
        action={
          <Badge value={session ? 'AVAILABLE' : 'UNKNOWN'}>
            {session ? 'Đã cấp phiên' : 'Chưa kết nối'}
          </Badge>
        }
      >
        <div className="v4-console-actions">
          <button
            type="button"
            className="button primary"
            onClick={connect}
            disabled={
              pending || !capability.data?.enabled || state !== 'ACTIVE'
            }
          >
            {pending
              ? 'Đang lấy phiên…'
              : session
                ? 'Lấy phiên mới'
                : 'Kết nối console'}
          </button>
          {session && (
            <>
              <a
                className="button secondary"
                href={session.url}
                target="_blank"
                rel="noopener noreferrer"
                referrerPolicy="no-referrer"
              >
                Mở ở tab mới
              </a>
              <button
                className="button secondary"
                onClick={() => setSession(null)}
              >
                Đóng khung console
              </button>
            </>
          )}
        </div>
        {(failure || capability.error) && (
          <div className="v4-notice warn" role="alert">
            <div>
              <strong>Chưa mở được console</strong>
              <p>{consoleMessage(failure || capability.error)}</p>
              <code>{(failure || capability.error).code}</code>
            </div>
          </div>
        )}
        {!capability.loading && capability.data?.enabled === false && (
          <p role="status">Chức năng Console chưa được bật.</p>
        )}
        <div className="v4-workload-console">
          <div className="v4-workload-console-bar">
            <span>{vm.name || vm.server_id}</span>
            <span>
              {session
                ? 'Phiên noVNC · trạng thái kết nối bên dưới'
                : 'Chưa có phiên console'}
            </span>
          </div>
          {session ? (
            <NativeConsole key={session.issued_at} session={session} />
          ) : (
            <div className="v4-workload-console-placeholder">
              <Monitor size={34} />
              <h3>Console máy ảo</h3>
              <p>
                Nhấn Kết nối console để lấy phiên noVNC mới cho máy này. Đăng
                nhập hệ điều hành trực tiếp trong màn hình console.
              </p>
            </div>
          )}
        </div>
        <p className="v4-panel-note">
          Nova: <Badge value={state} /> · Quan sát lúc {time(vm.observed_at)}.{' '}
          {state !== 'ACTIVE' &&
            'Cần inventory mới và VM ACTIVE để mở console.'}
        </p>
        {session && (
          <p className="v4-panel-note">
            Cấp phiên lúc {time(session.issued_at)}. Nova chưa cung cấp thời
            điểm hết hạn. Nếu phiên không mở được, lấy phiên mới hoặc mở ở tab
            mới. Đóng khung chỉ đóng màn hình trên Portal.
          </p>
        )}
      </Panel>
    </section>
  )
}
