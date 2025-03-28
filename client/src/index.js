import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import reportWebVitals from './reportWebVitals';
import 'bootstrap/dist/css/bootstrap.css';
import './index.css';

// Configure browser to remember scroll position on refresh
if ('scrollRestoration' in window.history) {
  window.history.scrollRestoration = 'auto';
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <div>
    <React.StrictMode>
      <App />
    </React.StrictMode>
  </div>
);

reportWebVitals();
