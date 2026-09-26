(() => {
  const formView = document.getElementById("form-view");
  const waitingView = document.getElementById("waiting-view");
  const approvedView = document.getElementById("approved-view");
  const rejectedView = document.getElementById("rejected-view");

  const enrollForm = document.getElementById("enroll-form");
  const deviceInput = document.getElementById("device_name");
  const platformSelect = document.getElementById("platform");
  const previewText = document.getElementById("preview-text");
  const formError = document.getElementById("form-error");

  const waitingDeviceName = document.getElementById("waiting-device-name");
  const approvedPin = document.getElementById("approved-pin");
  const approvedIdentity = document.getElementById("approved-identity");
  const approvedDomain = document.getElementById("approved-domain");
  const approvedVlan = document.getElementById("approved-vlan");
  const platformInstructions = document.getElementById("platform-instructions");
  const manualDownloadBtn = document.getElementById("manual-download-btn");

  const rejectTitle = document.getElementById("reject-title");
  const rejectReason = document.getElementById("reject-reason");
  const retryBtn = document.getElementById("retry-btn");

  let pollInterval = null;

  // Auto-sanitizer for device name input
  function sanitizeName(raw) {
    if (!raw) return "";
    let s = raw.toLowerCase().trim();
    s = s.replace(/[\s_.]+/g, "-");
    s = s.replace(/[^a-z0-9-]/g, "");
    s = s.replace(/-+/g, "-");
    return s.replace(/^-+|-+$/g, "");
  }

  deviceInput.addEventListener("input", () => {
    const sanitized = sanitizeName(deviceInput.value);
    previewText.textContent = sanitized || "none";
  });

  function showView(view) {
    formView.classList.add("hidden");
    waitingView.classList.add("hidden");
    approvedView.classList.add("hidden");
    rejectedView.classList.add("hidden");
    view.classList.remove("hidden");
  }

  function getPlatformGuide(platform, identity, domain) {
    switch (platform) {
      case "android":
        return `
          <strong>Android Setup Steps:</strong>
          <ol>
            <li>Tap the downloaded certificate file (or go to <em>Settings &gt; Security &gt; Install from storage &gt; Wi-Fi certificate</em>).</li>
            <li>Enter the 4-digit PIN above when prompted.</li>
            <li>In Wi-Fi settings for your network:
              <ul>
                <li><strong>EAP method:</strong> <code>TLS</code></li>
                <li><strong>CA certificate:</strong> Select your Root CA (e.g. <code>Spoutin-Root-CA</code>)</li>
                <li><strong>Domain:</strong> <code>${domain}</code></li>
                <li><strong>User certificate:</strong> Select the certificate you just imported</li>
                <li><strong>Identity:</strong> <code>${identity}</code></li>
              </ul>
            </li>
          </ol>
        `;
      case "ios":
      case "macos":
        return `
          <strong>Apple (iOS / macOS) Setup Steps:</strong>
          <ol>
            <li>Open the downloaded <code>.p12</code> file to import into Apple Keychain / Profiles.</li>
            <li>Enter the 4-digit PIN when prompted.</li>
            <li>Select your 802.1X Wi-Fi network and authenticate using the imported certificate identity: <code>${identity}</code>.</li>
          </ol>
        `;
      case "windows":
        return `
          <strong>Windows Setup Steps:</strong>
          <ol>
            <li>Double-click the downloaded <code>.p12</code> file to launch the Certificate Import Wizard.</li>
            <li>Select <em>Current User</em>, enter the 4-digit PIN, and choose automatic store placement.</li>
            <li>Connect to the Wi-Fi network and select this certificate when prompted.</li>
          </ol>
        `;
      default:
        return `
          <strong>General Setup Steps:</strong>
          <ol>
            <li>Import the <code>.p12</code> certificate bundle using the 4-digit PIN.</li>
            <li>Configure EAP-TLS with Identity <code>${identity}</code> and Server Domain <code>${domain}</code>.</li>
          </ol>
        `;
    }
  }

  enrollForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    formError.classList.add("hidden");
    const rawName = deviceInput.value;
    const sanitized = sanitizeName(rawName);

    if (!sanitized || sanitized.length < 2) {
      formError.textContent = "Please enter a valid device name (at least 2 letters/numbers).";
      formError.classList.remove("hidden");
      return;
    }

    const platform = platformSelect.value;

    try {
      const resp = await fetch("/api/request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_name: sanitized, platform: platform }),
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || "Failed to submit request.");
      }

      const data = await resp.json();
      waitingDeviceName.textContent = data.device_name;
      showView(waitingView);

      // Start instant listening via Server-Sent Events (SSE)
      startListening(data.request_id);
    } catch (err) {
      formError.textContent = err.message;
      formError.classList.remove("hidden");
    }
  });

  let activeEventSource = null;

  function handleApproved(data) {
    if (pollInterval) clearInterval(pollInterval);
    if (activeEventSource) {
      activeEventSource.close();
      activeEventSource = null;
    }

    approvedPin.textContent = data.pin || "----";
    approvedIdentity.textContent = data.radius_identity || data.device_name;
    approvedDomain.textContent = data.radius_domain || "radius.int.spoutin.org";
    approvedVlan.textContent = data.vlan_label || `VLAN ${data.vlan_id}`;

    platformInstructions.innerHTML = getPlatformGuide(
      data.platform,
      data.radius_identity || data.device_name,
      data.radius_domain || "radius.int.spoutin.org"
    );

    if (data.download_token) {
      const dlUrl = `/api/download/${data.download_token}`;
      manualDownloadBtn.href = dlUrl;
      manualDownloadBtn.setAttribute("download", `${data.radius_identity || data.device_name}.p12`);
    }

    showView(approvedView);
  }

  function handleRejected(data) {
    if (pollInterval) clearInterval(pollInterval);
    if (activeEventSource) {
      activeEventSource.close();
      activeEventSource = null;
    }
    rejectTitle.textContent = "Request Rejected";
    rejectReason.textContent = data.message || "Your enrollment request was rejected by an administrator.";
    showView(rejectedView);
  }

  function startListening(requestId) {
    if (activeEventSource) {
      activeEventSource.close();
      activeEventSource = null;
    }
    if (pollInterval) clearInterval(pollInterval);

    // 1. One-time immediate status check (also used on network reconnect)
    async function checkStatusOnce() {
      try {
        const resp = await fetch(`/api/status/${requestId}?_t=${Date.now()}`, { cache: "no-store" });
        if (resp.status === 404 || resp.status === 410) {
          if (activeEventSource) activeEventSource.close();
          if (pollInterval) clearInterval(pollInterval);
          rejectTitle.textContent = "Request Not Found";
          rejectReason.textContent = "Your enrollment request was not found or has expired.";
          showView(rejectedView);
          return;
        }
        if (resp.ok) {
          const data = await resp.json();
          if (data.status === "approved") {
            handleApproved(data);
          } else if (data.status === "rejected") {
            handleRejected(data);
          } else if (data.status === "expired") {
            if (activeEventSource) activeEventSource.close();
            if (pollInterval) clearInterval(pollInterval);
            rejectTitle.textContent = "Request Expired";
            rejectReason.textContent = "Your request expired while waiting for administrator review.";
            showView(rejectedView);
          }
        }
      } catch (err) {
        console.error("Status check error:", err);
      }
    }

    checkStatusOnce();

    // 2. Real-time instant push updates via Server-Sent Events (SSE)
    if (window.EventSource) {
      activeEventSource = new EventSource(`/api/status/${requestId}/events`);

      activeEventSource.addEventListener("approved", (e) => {
        try {
          const data = JSON.parse(e.data);
          handleApproved(data);
        } catch (err) {
          console.error("Error parsing approved SSE payload:", err);
          checkStatusOnce();
        }
      });

      activeEventSource.addEventListener("rejected", (e) => {
        try {
          const data = JSON.parse(e.data);
          handleRejected(data);
        } catch (err) {
          console.error("Error parsing rejected SSE payload:", err);
          checkStatusOnce();
        }
      });

      activeEventSource.onerror = () => {
        // Triggers when mobile screen sleeps or connection blips; re-check status once
        checkStatusOnce();
      };
    }

    // 3. Fallback low-frequency poll (every 30s) instead of 2s to reduce server load
    pollInterval = setInterval(checkStatusOnce, 30000);
  }

  retryBtn.addEventListener("click", () => {
    if (activeEventSource) {
      activeEventSource.close();
      activeEventSource = null;
    }
    if (pollInterval) clearInterval(pollInterval);
    deviceInput.value = "";
    previewText.textContent = "none";
    formError.classList.add("hidden");
    showView(formView);
  });
})();
