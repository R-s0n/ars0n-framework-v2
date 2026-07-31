import React from 'react';

// Parse "METHOD /path HTTP/1.1" from the first line of a raw HTTP request.
function parseRequestLine(raw) {
  if (!raw) return { method: '', path: '' };
  const firstLine = String(raw).split('\n')[0].trim();
  const parts = firstLine.split(/\s+/);
  return { method: parts[0] || '', path: parts[1] || '' };
}

function statusVariant(status) {
  if (!status) return 'secondary';
  if (status >= 200 && status < 300) return 'success';
  if (status >= 300 && status < 400) return 'info';
  if (status >= 400 && status < 500) return 'warning';
  if (status >= 500) return 'danger';
  return 'secondary';
}

// A small, purpose-built vertical diagram of a flow's request -> response steps.
// Clicking a node selects that step (highlighted with a red border).
const AuthFlowChart = ({ steps = [], selectedStepId, onSelectStep }) => {
  if (!steps.length) {
    return (
      <div className="text-center text-white-50 py-4 fst-italic">
        No steps yet — add a step below to start building this flow.
      </div>
    );
  }

  return (
    <div className="d-flex flex-column align-items-center py-2">
      {steps.map((step, idx) => {
        const { method, path } = parseRequestLine(step.raw_request);
        const isSelected = step.id === selectedStepId;
        const variant = statusVariant(step.response_status);
        return (
          <React.Fragment key={step.id || idx}>
            <div
              role="button"
              onClick={() => onSelectStep && onSelectStep(step.id)}
              className={`rounded border p-2 bg-dark ${isSelected ? 'border-danger' : 'border-secondary'}`}
              style={{ cursor: 'pointer', width: '100%', maxWidth: 560 }}
            >
              <div className="d-flex justify-content-between align-items-center mb-1">
                <span className="text-white-50 small">
                  Step {step.step_order}{step.name ? ` · ${step.name}` : ''}
                </span>
                {step.response_status ? (
                  <span className={`badge bg-${variant}`}>{step.response_status}</span>
                ) : step.error ? (
                  <span className="badge bg-danger" title={step.error}>error</span>
                ) : (
                  <span className="badge bg-secondary">no response</span>
                )}
              </div>
              <div className="text-info text-truncate" style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                <span className="fw-bold text-warning">{method}</span> {path}
              </div>
              {step.response_time_ms != null && (
                <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                  {Math.round(step.response_time_ms)} ms
                </div>
              )}
            </div>
            {idx < steps.length - 1 && (
              <div className="text-secondary" style={{ fontSize: '1.3rem', lineHeight: 1 }}>&#8595;</div>
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
};

export default AuthFlowChart;
