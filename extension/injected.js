// MAIN-world page hook.
//
// chrome.webRequest sees the network but never the bodies, which is why an app whose entire API
// surface is fetch/XHR looked almost empty: paths were recorded, payloads and responses were not.
// This script runs in the page's own JavaScript context, wraps fetch and XMLHttpRequest, and
// reports the request body and the response body as the application itself sees them.
//
// Constraints this file must respect, because it runs inside someone else's page:
//   - never change observable behaviour of fetch/XHR (same return values, same timing, same errors)
//   - never throw into the page
//   - do no work at all while recording is off
//
// It talks to the isolated content script over window.postMessage. It has no chrome.* access.

(() => {
  const CHANNEL = '__ars0n_capture__';
  const CONTROL = '__ars0n_control__';

  if (window[CHANNEL + '_installed']) return;
  window[CHANNEL + '_installed'] = true;

  // Captured before anything on the page can replace them, so a target that monkey-patches fetch
  // or JSON cannot interfere with (or observe) the capture.
  const nativeFetch = window.fetch;
  const NativeXHR = window.XMLHttpRequest;
  const nativeRequest = window.Request;
  const postMessage = window.postMessage.bind(window);
  const now = () =>
    window.performance && window.performance.now ? window.performance.now() : Date.now();

  let config = { active: false, scopeHosts: [], maxBodyBytes: 524288, captureResponseBodies: true };

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.__ars0n !== CONTROL) return;
    config = { ...config, ...(data.config || {}) };
  });

  function inScope(url) {
    if (!config.active) return false;
    let host;
    try {
      host = new URL(url, document.baseURI).hostname.toLowerCase();
    } catch (error) {
      return false;
    }
    return config.scopeHosts.some((scope) => host === scope || host.endsWith('.' + scope));
  }

  function absolute(url) {
    try {
      return new URL(url, document.baseURI).href;
    } catch (error) {
      return String(url);
    }
  }

  function truncate(text) {
    if (typeof text !== 'string') return { body: '', truncated: false };
    if (text.length <= config.maxBodyBytes) return { body: text, truncated: false };
    return { body: text.slice(0, config.maxBodyBytes), truncated: true };
  }

  const NON_TEXT = /^(image|video|audio|font)\//i;
  function bodyIsWorthReading(contentType) {
    if (!config.captureResponseBodies) return false;
    const type = String(contentType || '').toLowerCase();
    if (!type) return true;
    if (NON_TEXT.test(type)) return false;
    if (type.includes('octet-stream') || type.includes('application/pdf') || type.includes('zip')) return false;
    return true;
  }

  function report(record) {
    try {
      postMessage({ __ars0n: CHANNEL, record }, '*');
    } catch (error) {
      /* never let reporting break the page */
    }
  }

  function headersToObject(headers) {
    const result = {};
    if (!headers) return result;
    try {
      if (typeof headers.forEach === 'function' && typeof headers.get === 'function') {
        headers.forEach((value, key) => {
          result[String(key).toLowerCase()] = value;
        });
        return result;
      }
      if (Array.isArray(headers)) {
        headers.forEach(([key, value]) => {
          result[String(key).toLowerCase()] = value;
        });
        return result;
      }
      Object.keys(headers).forEach((key) => {
        result[key.toLowerCase()] = headers[key];
      });
    } catch (error) {
      /* exotic header container; report what we managed to read */
    }
    return result;
  }

  // Request bodies come in many shapes. Only the ones that are cheap and safe to stringify are
  // read; a stream or a large binary blob is described rather than consumed, because consuming it
  // would break the page's own request.
  async function readRequestBody(body) {
    if (body === undefined || body === null || body === '') return null;
    try {
      if (typeof body === 'string') return body;
      if (body instanceof URLSearchParams) return body.toString();
      if (typeof FormData !== 'undefined' && body instanceof FormData) {
        const out = {};
        body.forEach((value, key) => {
          out[key] = typeof value === 'string' ? value : `[file:${value && value.name ? value.name : 'blob'}]`;
        });
        return JSON.stringify(out);
      }
      if (typeof Blob !== 'undefined' && body instanceof Blob) {
        if (body.size > config.maxBodyBytes) return `[blob ${body.size} bytes]`;
        return await body.text();
      }
      if (body instanceof ArrayBuffer) {
        if (body.byteLength > config.maxBodyBytes) return `[arraybuffer ${body.byteLength} bytes]`;
        return new TextDecoder('utf-8').decode(new Uint8Array(body));
      }
      if (ArrayBuffer.isView(body)) {
        if (body.byteLength > config.maxBodyBytes) return `[binary ${body.byteLength} bytes]`;
        return new TextDecoder('utf-8').decode(new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
      }
      if (typeof ReadableStream !== 'undefined' && body instanceof ReadableStream) {
        return '[stream]';
      }
      return String(body);
    } catch (error) {
      return null;
    }
  }

  /* ------------------------------------------------------------------ fetch */

  window.fetch = function patchedFetch(input, init) {
    let url;
    let method;
    let requestHeaders;
    let bodySource;

    try {
      const isRequest = nativeRequest && input instanceof nativeRequest;
      url = absolute(isRequest ? input.url : input);
      method = String((init && init.method) || (isRequest && input.method) || 'GET').toUpperCase();
      requestHeaders = headersToObject((init && init.headers) || (isRequest && input.headers));
      bodySource = init && init.body !== undefined ? init.body : null;
    } catch (error) {
      return nativeFetch.apply(this, arguments);
    }

    if (!inScope(url)) return nativeFetch.apply(this, arguments);

    const started = now();
    const args = arguments;
    const self = this;

    // A Request object's body can only be consumed once. Cloning it is the only safe way to read
    // it without stealing the body from the request the page is about to send.
    let bodyPromise;
    if (bodySource !== null && bodySource !== undefined) {
      bodyPromise = readRequestBody(bodySource);
    } else if (nativeRequest && input instanceof nativeRequest && input.body) {
      bodyPromise = (async () => {
        try {
          return await input.clone().text();
        } catch (error) {
          return null;
        }
      })();
    } else {
      bodyPromise = Promise.resolve(null);
    }

    return nativeFetch.apply(self, args).then(
      (response) => {
        void (async () => {
          try {
            const responseHeaders = headersToObject(response.headers);
            const contentType = responseHeaders['content-type'] || '';
            let responseBody = '';
            let responseTruncated = false;

            // An opaque (no-cors) response has no readable body by design; do not try.
            if (response.type !== 'opaque' && bodyIsWorthReading(contentType)) {
              try {
                const text = await response.clone().text();
                const trimmed = truncate(text);
                responseBody = trimmed.body;
                responseTruncated = trimmed.truncated;
              } catch (error) {
                /* body already disturbed or unreadable */
              }
            }

            const requestBody = truncate((await bodyPromise) || '');
            report({
              url,
              method,
              statusCode: response.status,
              headers: requestHeaders,
              responseHeaders,
              postData: requestBody.body,
              requestBodyTruncated: requestBody.truncated,
              responseBody,
              responseBodyTruncated: responseTruncated,
              mimeType: contentType,
              resourceType: 'fetch',
              durationMs: Math.round(now() - started),
            });
          } catch (error) {
            /* never surface capture failures to the page */
          }
        })();
        return response;
      },
      async (error) => {
        try {
          const requestBody = truncate((await bodyPromise) || '');
          report({
            url,
            method,
            statusCode: 0,
            headers: requestHeaders,
            responseHeaders: {},
            postData: requestBody.body,
            requestBodyTruncated: requestBody.truncated,
            responseBody: '',
            mimeType: '',
            resourceType: 'fetch',
            error: String((error && error.message) || error || 'fetch failed'),
            durationMs: Math.round(now() - started),
          });
        } catch (reportError) {
          /* ignore */
        }
        throw error;
      }
    );
  };

  // Keep the patched function indistinguishable from the native one, so feature-detection and
  // anti-tamper checks in the page behave the same.
  try {
    Object.defineProperty(window.fetch, 'name', { value: 'fetch', configurable: true });
    window.fetch.toString = () => nativeFetch.toString();
  } catch (error) {
    /* non-fatal */
  }

  /* ------------------------------------------------------------------ XMLHttpRequest */

  const OPEN = NativeXHR.prototype.open;
  const SEND = NativeXHR.prototype.send;
  const SET_HEADER = NativeXHR.prototype.setRequestHeader;
  const CAPTURE = Symbol('ars0nCapture');
  const CAPTURE_BODY = Symbol('ars0nCaptureBody');
  const LISTENERS_BOUND = Symbol('ars0nListeners');

  NativeXHR.prototype.open = function patchedOpen(method, url) {
    try {
      this[CAPTURE] = {
        method: String(method || 'GET').toUpperCase(),
        url: absolute(url),
        headers: {},
        started: now(),
      };
    } catch (error) {
      /* fall through to native */
    }
    return OPEN.apply(this, arguments);
  };

  NativeXHR.prototype.setRequestHeader = function patchedSetRequestHeader(name, value) {
    try {
      if (this[CAPTURE]) this[CAPTURE].headers[String(name).toLowerCase()] = value;
    } catch (error) {
      /* ignore */
    }
    return SET_HEADER.apply(this, arguments);
  };

  NativeXHR.prototype.send = function patchedSend(body) {
    const meta = this[CAPTURE];

    if (!meta || !inScope(meta.url)) return SEND.apply(this, arguments);

    const xhr = this;
    meta.started = now();
    // An XHR object can legally be reused for several sends. Bind the completion listeners once so
    // they do not accumulate and report the same response repeatedly.
    const alreadyBound = xhr[LISTENERS_BOUND] === true;
    xhr[LISTENERS_BOUND] = true;
    // The listeners read `this[CAPTURE]` at fire time, so a reused object reports its current
    // request rather than the one it was first opened with.

    const finish = (errorMessage) => {
      void (async () => {
        try {
          const current = xhr[CAPTURE] || meta;
          const responseHeaders = parseRawHeaders(safeGetAllResponseHeaders(xhr));
          const contentType = responseHeaders['content-type'] || '';
          let responseBody = '';
          let responseTruncated = false;

          if (!errorMessage && bodyIsWorthReading(contentType)) {
            const raw = readXHRResponse(xhr);
            if (raw !== null) {
              const trimmed = truncate(raw);
              responseBody = trimmed.body;
              responseTruncated = trimmed.truncated;
            }
          }

          const requestBody = truncate((await readRequestBody(xhr[CAPTURE_BODY])) || '');
          report({
            url: current.url,
            method: current.method,
            statusCode: errorMessage ? 0 : xhr.status,
            headers: current.headers,
            responseHeaders,
            postData: requestBody.body,
            requestBodyTruncated: requestBody.truncated,
            responseBody,
            responseBodyTruncated: responseTruncated,
            mimeType: contentType,
            resourceType: 'xhr',
            error: errorMessage || '',
            durationMs: Math.round(now() - current.started),
          });
        } catch (error) {
          /* ignore */
        }
      })();
    };

    // Stash the body on the instance so a reused XHR reports the body of its current send.
    xhr[CAPTURE_BODY] = body;

    if (!alreadyBound) {
      xhr.addEventListener('load', () => finish(null));
      xhr.addEventListener('error', () => finish('network error'));
      xhr.addEventListener('abort', () => finish('aborted'));
      xhr.addEventListener('timeout', () => finish('timeout'));
    }

    return SEND.apply(this, arguments);
  };

  function safeGetAllResponseHeaders(xhr) {
    try {
      return xhr.getAllResponseHeaders();
    } catch (error) {
      return '';
    }
  }

  function parseRawHeaders(raw) {
    const result = {};
    String(raw || '')
      .split(/\r?\n/)
      .forEach((line) => {
        const index = line.indexOf(':');
        if (index <= 0) return;
        result[line.slice(0, index).trim().toLowerCase()] = line.slice(index + 1).trim();
      });
    return result;
  }

  // responseText throws for arraybuffer/blob response types, so check before reading.
  function readXHRResponse(xhr) {
    try {
      const type = xhr.responseType;
      if (type === '' || type === 'text') return xhr.responseText;
      if (type === 'json') return JSON.stringify(xhr.response);
      if (type === 'document' && xhr.responseXML) {
        return new XMLSerializer().serializeToString(xhr.responseXML);
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  /* ------------------------------------------------------------------ sendBeacon */

  // Analytics and logout flows commonly use sendBeacon, which webRequest reports with no body.
  if (navigator.sendBeacon) {
    const nativeBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function patchedSendBeacon(url, data) {
      const absoluteUrl = absolute(url);
      if (inScope(absoluteUrl)) {
        void (async () => {
          try {
            const requestBody = truncate((await readRequestBody(data)) || '');
            report({
              url: absoluteUrl,
              method: 'POST',
              statusCode: 0,
              headers: {},
              responseHeaders: {},
              postData: requestBody.body,
              requestBodyTruncated: requestBody.truncated,
              responseBody: '',
              mimeType: '',
              resourceType: 'beacon',
              durationMs: 0,
            });
          } catch (error) {
            /* ignore */
          }
        })();
      }
      return nativeBeacon(url, data);
    };
  }
})();
