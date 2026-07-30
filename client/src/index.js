import React from 'react';
import ReactDOM from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';
import reportWebVitals from './reportWebVitals';
import 'bootstrap/dist/css/bootstrap.css';
import './index.css';

// Configure browser to remember scroll position on refresh
if ('scrollRestoration' in window.history) {
  window.history.scrollRestoration = 'auto';
}

// G1.7: react-query is the data-fetching layer for the heavy reads (target-urls / ROI /
// screenshots). It gives us in-flight de-duplication, caching, and cancel-on-target-switch (via
// AbortSignal) so stale responses can't overwrite the current target's data. Defaults are tuned
// for this app: no refetch-on-focus (the UI is scan-driven, not focus-driven), one retry, and a
// short stale window so reopening a screen is instant but still revalidates.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      gcTime: 5 * 60_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <div>
    <React.StrictMode>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </React.StrictMode>
  </div>
);

reportWebVitals();
