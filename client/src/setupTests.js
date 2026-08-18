// jest-dom adds custom matchers for asserting on DOM nodes, e.g. expect(el).toHaveTextContent(/x/i).
// See https://github.com/testing-library/jest-dom
//
// It is loaded ONLY IF PRESENT. It is not a declared dependency of this project and is not installed,
// and importing it unconditionally made every test in the repo fail before it started: jest reports
// "Cannot find module '@testing-library/jest-dom' from 'src/setupTests.js'" as a suite-level failure,
// so a test that uses none of its matchers could not run either.
try {
  require('@testing-library/jest-dom');
} catch {
  // Matchers unavailable. Tests that do not rely on them still run, which is the point.
}

// jsdom implements no layout, so it has no ResizeObserver. Any component that measures itself uses
// one, and VirtualizedList does, which means rendering a modal containing a list throws
// "ResizeObserver is not defined" before a single assertion runs. A stub that observes nothing is
// correct here: there is no layout to observe, and the component falls back to its default height.
if (typeof global.ResizeObserver === 'undefined') {
  global.ResizeObserver = class {
    observe() {}

    unobserve() {}

    disconnect() {}
  };
}
