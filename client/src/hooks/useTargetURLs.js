import { useQuery } from '@tanstack/react-query';

/**
 * useTargetURLs — react-query hook for a scope target's target-urls list (G1.7).
 *
 * One hook for every heavy target-urls read (ROI / Metadata / Screenshots / config). Benefits
 * over the old imperative fetches:
 *   - cancel-on-switch: the query is keyed by scope-target id, so changing targets aborts the
 *     in-flight request (AbortSignal) and a late response can't overwrite the new target's data.
 *   - de-dup: concurrent callers with the same key share a single network request.
 *   - cache: revisiting a screen paints instantly from cache, then revalidates.
 *
 * `projection` selects the server-side payload shape (see GetTargetURLsForScopeTarget). It is
 * part of the query key, so different shapes are cached independently:
 *   - 'full'          every column incl. screenshot + http_response (legacy default)
 *   - 'lean'          ?lean=true — ids/url/status/tech/roi + has_screenshot, no blobs
 *   - 'no-screenshot' ?screenshot=false — everything except the base64 screenshot (ROI report)
 *   - 'meta'          ?screenshot=false&response=false — drops screenshot + raw body (Metadata)
 */

const PROJECTION_QUERY = {
  full: '',
  lean: '?lean=true',
  'no-screenshot': '?screenshot=false',
  meta: '?screenshot=false&response=false',
};

export const targetURLsKey = (scopeTargetId, projection = 'full') => [
  'target-urls',
  scopeTargetId,
  projection,
];

export function useTargetURLs(scopeTargetId, { projection = 'full', enabled = true } = {}) {
  return useQuery({
    queryKey: targetURLsKey(scopeTargetId, projection),
    enabled: !!scopeTargetId && enabled,
    queryFn: async ({ signal }) => {
      const qs = PROJECTION_QUERY[projection] ?? '';
      const response = await fetch(
        `/api/api/scope-targets/${scopeTargetId}/target-urls${qs}`,
        { signal }
      );
      if (!response.ok) {
        throw new Error('Failed to fetch target URLs');
      }
      return (await response.json()) || [];
    },
  });
}

export default useTargetURLs;
