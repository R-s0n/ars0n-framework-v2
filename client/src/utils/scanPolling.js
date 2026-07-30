// G1.9: a single cancelable scheduler for all scan-status pollers.
//
// Every monitor*ScanStatus util reschedules its next poll through pollTimeout() instead of the
// raw setTimeout(). pollTimeout tags each scheduled callback with the current "epoch". When the
// active scope target changes (App.js calls cancelAllScanPolls() on switch / unmount), the epoch
// is bumped and all outstanding timers are cleared, so the previous target's recursive polling
// chains stop firing.
//
// This fixes the timer leak (chains used to accumulate on every target switch — the effects had
// no cleanup, so each switch started a fresh recursive setTimeout chain while the old ones kept
// running forever) and the bulk of the stale-write races (a cancelled chain no longer fetches +
// setState for a target you've navigated away from). The only residual is a single fetch that is
// already in flight at the moment of a switch; it resolves once and is immediately corrected by
// the new target's pollers.

let epoch = 0;
const timers = new Set();

// Drop-in replacement for setTimeout(fn, delay) inside the scan monitors. The scheduled callback
// runs only if no cancellation happened in the meantime, so polls for a stale target are dropped.
export const pollTimeout = (fn, delay) => {
  const scheduledEpoch = epoch;
  const id = setTimeout(() => {
    timers.delete(id);
    if (scheduledEpoch === epoch) {
      fn();
    }
  }, delay);
  timers.add(id);
  return id;
};

// Cancel every scheduled poll. Called when the active target changes or the app unmounts, so old
// recursive polling chains stop instead of leaking and racing the new target's pollers.
export const cancelAllScanPolls = () => {
  epoch += 1;
  for (const id of timers) {
    clearTimeout(id);
  }
  timers.clear();
};

// Exposed for debugging / verification (the live-timer count should stay bounded, not grow per
// target switch).
export const getPendingScanPollCount = () => timers.size;
