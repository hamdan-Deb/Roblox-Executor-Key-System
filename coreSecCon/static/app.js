document.addEventListener("DOMContentLoaded", () => {
  // Navigation Tabs
  const navBtns = document.querySelectorAll(".nav-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  navBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      navBtns.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      const tabId = btn.getAttribute("data-tab");
      document.getElementById(tabId).classList.add("active");
      if (tabId === "dashboard") refreshDashboard();
    });
  });

  let lastWebhookPayload = null;

  // --------------------------------------------------------------------------
  // Tab 1: Dashboard Refresh
  // --------------------------------------------------------------------------
  async function refreshDashboard() {
    try {
      const res = await fetch("/api/dashboard/stats");
      const data = await res.json();

      // Populate Sessions
      const sessionsBody = document.querySelector("#sessions-table tbody");
      sessionsBody.innerHTML = "";
      data.active_sessions.forEach(s => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${s.session_id}</td>
          <td>${s.hwid_hash.substring(0, 10)}...</td>
          <td><span style="color: ${getStatusColor(s.status)}">${s.status}</span></td>
          <td>${s.token || "<em>None</em>"}</td>
          <td>${s.expires_in}s</td>
        `;
        sessionsBody.appendChild(tr);
      });

      // Populate Audit Logs
      const logsBody = document.querySelector("#logs-table tbody");
      logsBody.innerHTML = "";
      data.logs.forEach(l => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${l.timestamp.split("T")[1].substring(0, 8)}</td>
          <td><span style="color: ${getSeverityColor(l.severity)}">${l.severity}</span></td>
          <td>${l.event_type}</td>
          <td>${l.description}</td>
        `;
        logsBody.appendChild(tr);
      });
    } catch (err) {
      console.error("Dashboard refresh error:", err);
    }
  }

  function getStatusColor(status) {
    if (status === "APPROVED") return "var(--accent-green)";
    if (status === "PENDING") return "var(--accent-amber)";
    return "var(--accent-red)";
  }

  function getSeverityColor(sev) {
    if (sev === "ALERT") return "var(--accent-red)";
    if (sev === "WARNING") return "var(--accent-amber)";
    return "var(--accent-cyan)";
  }

  setInterval(refreshDashboard, 5000);
  refreshDashboard();

  // --------------------------------------------------------------------------
  // Tab 2: URL Payload Explorer
  // --------------------------------------------------------------------------
  document.getElementById("btn-inspect-url").addEventListener("click", async () => {
    const url = document.getElementById("explorer-url-input").value;
    const res = await fetch("/api/explore-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    const out = document.getElementById("url-inspection-result");
    out.classList.remove("hidden");
    out.textContent = JSON.stringify(data, null, 2);
  });

  // --------------------------------------------------------------------------
  // Tab 3: Crypto Playground
  // --------------------------------------------------------------------------
  document.getElementById("btn-calculate-hash").addEventListener("click", async () => {
    const input_string = document.getElementById("hash-input").value;
    const secret_key = document.getElementById("hash-salt").value;
    const res = await fetch("/api/crypto/hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input_string, secret_key })
    });
    const data = await res.json();
    const out = document.getElementById("hash-output");
    out.classList.remove("hidden");
    out.textContent = JSON.stringify(data, null, 2);
  });

  document.getElementById("btn-generate-token").addEventListener("click", async () => {
    const res = await fetch("/api/crypto/generate-token");
    const data = await res.json();
    const out = document.getElementById("token-output");
    out.classList.remove("hidden");
    out.textContent = JSON.stringify(data, null, 2);
  });

  // --------------------------------------------------------------------------
  // Tab 4: Auth Simulator
  // --------------------------------------------------------------------------
  document.getElementById("btn-start-session").addEventListener("click", async () => {
    const hwid = document.getElementById("sim-hwid").value;
    const res = await fetch("/api/auth/session/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hwid })
    });
    const data = await res.json();
    const out = document.getElementById("session-output");
    out.classList.remove("hidden");
    out.textContent = JSON.stringify(data, null, 2);

    if (data.session_id) {
      document.getElementById("webhook-session-id").value = data.session_id;
      document.getElementById("verify-hwid-input").value = data.hwid_hash;
    }
  });

  document.getElementById("btn-verify-token").addEventListener("click", async () => {
    const token = document.getElementById("verify-token-input").value;
    const hwid_hash = document.getElementById("verify-hwid-input").value;
    const res = await fetch("/api/auth/token/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, hwid_hash })
    });
    const data = await res.json();
    const out = document.getElementById("verify-output");
    out.classList.remove("hidden");
    out.textContent = JSON.stringify(data, null, 2);
    refreshDashboard();
  });

  // --------------------------------------------------------------------------
  // Tab 5: Webhook & Replay Lab
  // --------------------------------------------------------------------------
  async function computeHMAC(secret, message) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", key, enc.encode(message));
    return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  document.getElementById("btn-fire-webhook").addEventListener("click", async () => {
    const sessionId = document.getElementById("webhook-session-id").value;
    const action = document.getElementById("webhook-action").value;
    const tamperSig = document.getElementById("tamper-signature").checked;
    const tamperTime = document.getElementById("tamper-timestamp").checked;

    const payload = JSON.stringify({ session_id: sessionId, action: action });
    const eventId = "evt_" + Math.random().toString(36).substring(2, 10);
    let timestamp = (Date.now() / 1000).toString();

    if (tamperTime) {
      timestamp = (Date.now() / 1000 - 600).toString(); // 10 minutes in the past
    }

    const signingSecret = "super_secret_signing_key_2026";
    const messageToSign = `${timestamp}.${eventId}.${payload}`;
    let signature = await computeHMAC(signingSecret, messageToSign);

    if (tamperSig) {
      signature = signature.replace("a", "f").replace("0", "1");
    }

    // Cache for replay demonstration
    lastWebhookPayload = { payload, signature, timestamp, eventId };

    const res = await fetch("/api/webhook/callback", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Timestamp": timestamp,
        "X-Event-ID": eventId
      },
      body: payload
    });

    const data = await res.json();
    const out = document.getElementById("webhook-output");
    out.classList.remove("hidden");
    out.textContent = JSON.stringify(data, null, 2);

    if (data.issued_token) {
      document.getElementById("verify-token-input").value = data.issued_token;
    }
    refreshDashboard();
  });

  document.getElementById("btn-replay-webhook").addEventListener("click", async () => {
    if (!lastWebhookPayload) {
      alert("Send a valid webhook first before testing replay attack!");
      return;
    }

    // Re-send the exact identical headers and payload
    const res = await fetch("/api/webhook/callback", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Signature": lastWebhookPayload.signature,
        "X-Timestamp": lastWebhookPayload.timestamp,
        "X-Event-ID": lastWebhookPayload.eventId
      },
      body: lastWebhookPayload.payload
    });

    const data = await res.json();
    const out = document.getElementById("webhook-output");
    out.classList.remove("hidden");
    out.textContent = "[REPLAY EXPERIMENT RESULT]\n" + JSON.stringify(data, null, 2);
    refreshDashboard();
  });
});