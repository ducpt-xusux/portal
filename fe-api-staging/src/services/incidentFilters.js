const responseStates = ['NONE', 'QUARANTINED', 'RESTORED', 'UNKNOWN']
const reviewStates = ['UNREVIEWED', 'ACKNOWLEDGED', 'REVIEWED']
const periods = ['15', '60', '1440', '10080']
const keys = [
  'source_ip',
  'signal_rule',
  'severity',
  'status',
  'review_state',
  'response_state',
  'from',
  'to',
]

export function readIncidentFilterSupport(value) {
  return {
    review_state: value?.review_state === true,
    response_states: Array.isArray(value?.response_states)
      ? [
          ...new Set(
            value.response_states.filter((state) =>
              responseStates.includes(state)
            )
          ),
        ]
      : [],
  }
}

export function initialIncidentDraft(params) {
  const explicit = Boolean(params.from || params.to)
  return {
    ...params,
    from: params.from || '',
    to: params.to || '',
    window:
      explicit && periods.includes(params.window)
        ? params.window
        : explicit
          ? 'custom'
          : 'all',
  }
}

function validTime(value) {
  return (
    typeof value === 'string' &&
    /(Z|[+-]\d{2}:\d{2})$/.test(value) &&
    Number.isFinite(Date.parse(value))
  )
}

export function incidentRequestFilters(params, support) {
  const filters = Object.fromEntries(
    keys
      .filter((key) => params[key] && params[key] !== 'ALL')
      .map((key) => [key, params[key]])
  )
  if (
    filters.review_state &&
    (!support.review_state || !reviewStates.includes(filters.review_state))
  ) {
    return {
      filters,
      error: 'Nguồn hiện chưa hỗ trợ bộ lọc Portal review đã chọn.',
      unsupported: true,
    }
  }
  if (
    filters.response_state &&
    !support.response_states.includes(filters.response_state)
  ) {
    return {
      filters,
      error: 'Nguồn hiện chưa hỗ trợ trạng thái phản ứng đã chọn.',
      unsupported: true,
    }
  }
  if (['from', 'to'].some((key) => filters[key] && !validTime(filters[key]))) {
    return {
      filters,
      error: 'Khoảng thời gian chưa hợp lệ hoặc thiếu múi giờ.',
    }
  }
  if (filters.from && filters.to) {
    const duration = Date.parse(filters.to) - Date.parse(filters.from)
    if (duration < 0)
      return {
        filters,
        error: 'Thời điểm bắt đầu phải trước hoặc bằng thời điểm kết thúc.',
      }
    if (duration > 30 * 86400000)
      return {
        filters,
        error: 'Khoảng lọc tối đa là 30 ngày. Hãy chọn khoảng ngắn hơn.',
      }
  }
  return { filters, error: '' }
}

export function incidentFilterSearch(draft, support, now = Date.now()) {
  const values = { ...draft }
  if (periods.includes(draft.window)) {
    values.to = new Date(now).toISOString()
    values.from = new Date(now - Number(draft.window) * 60000).toISOString()
  } else if (draft.window === 'all') {
    delete values.from
    delete values.to
  } else if (!values.from && !values.to) {
    return {
      error: 'Chọn ít nhất một mốc thời gian hoặc chuyển về toàn bộ lịch sử.',
    }
  }
  const result = incidentRequestFilters(values, support)
  if (result.error) return result
  return {
    error: '',
    search: new URLSearchParams({
      ...result.filters,
      ...(periods.includes(draft.window) ? { window: draft.window } : {}),
    }).toString(),
  }
}

export function withoutUnsupportedIncidentFilters(params, support) {
  const values = { ...params }
  if (!support.review_state || !reviewStates.includes(values.review_state))
    delete values.review_state
  if (!support.response_states.includes(values.response_state))
    delete values.response_state
  return new URLSearchParams(values).toString()
}

export function incidentLocalTime(value, timezone) {
  return validTime(value)
    ? new Date(Date.parse(value) + (timezone === 'UTC' ? 0 : 7 * 3600000))
        .toISOString()
        .slice(0, 19)
    : ''
}

export function incidentUtcTime(value, timezone) {
  if (!value) return ''
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(value)) return null
  const result = new Date(`${value}${timezone === 'UTC' ? 'Z' : '+07:00'}`)
  if (!Number.isFinite(result.getTime())) return null
  const iso = result.toISOString()
  return incidentLocalTime(iso, timezone) ===
    (value.length === 16 ? `${value}:00` : value)
    ? iso
    : null
}
