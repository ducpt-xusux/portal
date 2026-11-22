import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { portalRequest } from '../services/portalApi'
import usePortalResource from './usePortalResource'

vi.mock('../services/portalApi', async (importOriginal) => ({
  ...(await importOriginal()),
  portalRequest: vi.fn(),
}))

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.useRealTimers()
})

it('allows a slow request to settle before polling again', async () => {
  vi.useFakeTimers()
  vi.spyOn(document, 'hidden', 'get').mockReturnValue(false)
  let complete
  portalRequest.mockImplementation(() => new Promise((resolve) => { complete = resolve }))
  const { result, unmount } = renderHook(() =>
    usePortalResource('/system/automatic-response', { interval: 5000 })
  )

  await act(() => vi.advanceTimersByTimeAsync(7000))
  expect(portalRequest).toHaveBeenCalledTimes(1)
  expect(portalRequest.mock.calls[0][1].signal.aborted).toBe(false)

  await act(async () => complete({ data: { configured: true }, meta: {} }))
  expect(result.current.loading).toBe(false)
  expect(result.current.data).toEqual({ configured: true })

  await act(() => vi.advanceTimersByTimeAsync(5000))
  expect(portalRequest).toHaveBeenCalledTimes(2)
  unmount()
  expect(portalRequest.mock.calls[1][1].signal.aborted).toBe(true)
})
