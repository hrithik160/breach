/**
 * Breach Sentinel — Universal Attack Telemetry SDK
 * Include this script in ANY website:
 *   <script src="http://localhost:8000/site/breach_sentinel.js"></script>
 *
 * Automatically monitors form inputs for common attack signatures (SQLi, XSS, Path Traversal, Leaked Keys, IoT exploits)
 * or triggers explicit exploit notifications that ripple across the Breach Domino Simulator.
 */
(function(window) {
  const getDefaultBackendUrl = function() {
    if (typeof window !== 'undefined' && window.BreachSentinelConfig && window.BreachSentinelConfig.backendUrl) {
      return window.BreachSentinelConfig.backendUrl;
    }
    if (typeof window !== 'undefined' && window.location) {
      const proto = window.location.protocol;
      if (proto === 'http:' || proto === 'https:') {
        const host = window.location.hostname || 'localhost';
        const port = window.location.port;
        // If served from FastAPI on port 8000 or without explicit port, default to 8000.
        // If loaded from a different frontend dev port (e.g. 3000, 5173), default to localhost:8000.
        const targetPort = (port === '8000' || !port) ? '8000' : (host === 'localhost' || host === '127.0.0.1' ? '8000' : port);
        return `${proto}//${host}:${targetPort}`;
      }
    }
    return 'http://localhost:8000';
  };

  const ATTACK_REGEXES = {
    sqli: /('|\b)(union\s+select|or\s+1=1|drop\s+table|insert\s+into)\b|--|\/\*/i,
    path_traversal: /(\.\.\/|\.\.\\|\/etc\/passwd|\/etc\/shadow)/i,
    leaked_api_key: /(AKIA[0-9A-Z]{16}|bearer\s+[a-z0-9\._\-]{20,})/i,
    xss: /(<script|javascript:|onerror=|onload=)/i,
    printer_overflow: /(HP_RAW_SOCKET|BUFFER_OVERFLOW|CVE-2023-3519|9100\/raw|jetdirect)/i
  };

  const BreachSentinel = {
    backendUrl: getDefaultBackendUrl(),

    setBackendUrl(url) {
      if (url && typeof url === 'string') {
        this.backendUrl = url.replace(/\/+$/, '');
      }
    },

    async reportExploit(data) {
      if (!data) data = {};
      try {
        const payload = {
          vector: data.vector || 'custom_attack',
          input: data.input || data.payload || '',
          url: (typeof window !== 'undefined' && window.location) ? window.location.href : '',
          timestamp: Date.now()
        };

        const targetNode = data.target || data.target_node || data.entry_node;
        if (targetNode) {
          payload.target_node = targetNode;
        }

        const res = await fetch(`${this.backendUrl}/portal/attack`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        if (!res.ok) {
          throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }

        const resData = await res.json();
        console.warn('[BreachSentinel] Exploit reported to Breach Domino:', resData);
        return resData;
      } catch (err) {
        console.error('[BreachSentinel] Could not report to Breach Domino:', err);
        return { status: 'offline', error: err.message };
      }
    },

    autoDetect(text) {
      if (!text || typeof text !== 'string') return null;
      for (const [vector, regex] of Object.entries(ATTACK_REGEXES)) {
        if (regex.test(text)) {
          return vector;
        }
      }
      return null;
    },

    bindForm(formSelector, inputSelector, options) {
      const opts = options || {};
      const attach = () => {
        const form = document.querySelector(formSelector);
        if (!form) return;

        if (form.__breach_sentinel_bound) return;
        form.__breach_sentinel_bound = true;

        form.addEventListener('submit', (e) => {
          if (e.defaultPrevented || e.__breach_reported) return;

          const input = document.querySelector(inputSelector);
          if (!input) return;
          const val = input.value || '';
          const detected = this.autoDetect(val) || opts.defaultVector;
          if (detected) {
            e.__breach_reported = true;
            this.reportExploit({
              vector: detected,
              input: val,
              target: opts.target
            });
          }
        });
      };

      if (typeof document !== 'undefined') {
        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', attach);
        } else {
          attach();
        }
      }
    }
  };

  window.BreachSentinel = BreachSentinel;
})(typeof window !== 'undefined' ? window : this);