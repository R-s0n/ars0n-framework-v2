import { useState, useEffect } from 'react';

/**
 * useDebounce — returns a copy of `value` that only updates after `value` has stopped changing
 * for `delay` ms (G1.10).
 *
 * Used so a filter <input> can stay controlled by immediate state (typing feels instant) while
 * the expensive derivation (filtering/sorting thousands of rows) keys off the debounced value
 * and only runs once the user pauses. Keeps filter-keystroke latency low at 10k rows.
 */
export function useDebounce(value, delay = 250) {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const handle = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(handle);
  }, [value, delay]);

  return debounced;
}

export default useDebounce;
