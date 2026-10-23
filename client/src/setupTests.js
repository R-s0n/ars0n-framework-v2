// jest-dom adds custom matchers for asserting on DOM nodes, e.g. expect(el).toHaveTextContent(/x/i).
// See https://github.com/testing-library/jest-dom. The /vitest entry registers them with Vitest's
// expect.
import '@testing-library/jest-dom/vitest';

// jsdom implements no layout, so it has no ResizeObserver. Any component that measures itself uses
// one, and VirtualizedList does, which means rendering a modal containing a list throws
// "ResizeObserver is not defined" before a single assertion runs. A stub that observes nothing is
// correct here: there is no layout to observe, and the component falls back to its default height.
if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = class {
    observe() {}

    unobserve() {}

    disconnect() {}
  };
}
