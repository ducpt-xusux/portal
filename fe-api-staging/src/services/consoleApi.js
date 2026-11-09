import { portalRequest, PortalApiError } from './portalApi.js'

export function validateConsole(data, serverId, capabilities) {
  const reject = () => { throw new PortalApiError('Phản hồi console không hợp lệ.', 502, 'CONSOLE_URL_REJECTED') }
  try {
    if (data?.server_id !== serverId || data?.project_id !== capabilities?.project_id || data?.protocol !== 'vnc' || data?.type !== 'novnc' || typeof data.url !== 'string' || data.url.length > 4096 || /[\s\\]/.test(data.url)) return reject()
    const url = new URL(data.url)
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== new URL(capabilities.console_origin).origin || url.username || url.password || url.hash || !['/vnc_lite.html', '/vnc_auto.html', '/vnc.html'].includes(url.pathname)) return reject()
    let query = url.searchParams
    if ([...query.keys()].length === 1 && query.has('path')) {
      const path = query.get('path')
      if (!/^(?:\/?websockify)?\?token=/.test(path)) return reject()
      query = new URLSearchParams(path.slice(path.indexOf('?') + 1))
    }
    if ([...query.keys()].length !== 1 || !/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/i.test(query.get('token') || '')) return reject()
    return data
  } catch { return reject() }
}

export async function createConsole(serverId, capabilities, { signal, fetcher = globalThis.fetch } = {}) {
  const result = await portalRequest(`/workloads/${encodeURIComponent(serverId)}/console`, {
    method: 'POST', body: { protocol: 'vnc', type: 'novnc' }, signal, timeout: 25000,
    fetcher: (url, options) => fetcher(url, { ...options, headers: { ...options.headers, 'X-Portal-Console': 'connect' } }),
  })
  return validateConsole(result.data, serverId, capabilities)
}

export function consoleMessage(error) {
  return ({ CONSOLE_PERMISSION_DENIED: 'Nova từ chối quyền console (403). Cần cấu hình credential riêng được phép mở console; credential inventory reader hiện chưa có quyền này.',
    CONSOLE_VM_NOT_ACTIVE: 'Máy ảo chưa ở trạng thái ACTIVE. Hãy kiểm tra trạng thái VM trước.',
    CONSOLE_NOT_CONFIGURED: 'Backend chưa bật kết nối console.',
    CONSOLE_REQUEST_RATE_LIMITED: 'Vui lòng chờ 10 giây trước khi lấy phiên mới.',
    CONSOLE_ORIGIN_REJECTED: 'Yêu cầu kết nối không đến từ địa chỉ Portal được phép.',
    CONSOLE_CREDENTIAL_SCOPE_REQUIRED: 'Credential console chưa đúng project hoặc role được cho phép.',
  })[error?.code] || error?.message || 'Chưa kết nối được console.'
}
