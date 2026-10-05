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
  const instructionPlatformSelect = document.getElementById("instruction-platform-select");
  const manualDownloadBtn = document.getElementById("manual-download-btn");

  const rejectTitle = document.getElementById("reject-title");
  const rejectReason = document.getElementById("reject-reason");
  const retryBtn = document.getElementById("retry-btn");

  let pollInterval = null;
  let currentApprovedData = null;

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
      case "windows-11":
      case "windows":
        return `
          <strong>Windows 11 Setup Steps:</strong>
          <ol>
            <li><strong>Import Certificate:</strong>
              Press <kbd>Win</kbd> + <kbd>R</kbd> (Start &gt; Run), type <code>certmgr.msc</code> and press Enter (or double-click the downloaded <code>.p12</code> file).
              <ul>
                <li>Select <strong>Current User</strong> &gt; click <strong>Next</strong>.</li>
                <li>Enter the 4-digit PIN above when prompted &gt; click <strong>Next</strong>.</li>
                <li>Select <strong>Automatically select the certificate store based on the type of certificate</strong> &gt; click <strong>Finish</strong>.</li>
              </ul>
            </li>
            <li><strong>Connect to Wi-Fi:</strong>
              Press <kbd>Win</kbd> + <kbd>A</kbd> for Quick Settings (or press <kbd>Win</kbd> + <kbd>R</kbd> and run <code>ms-settings:network-wifi</code>).
              <ul>
                <li>Select <strong>Spoutin-Secure</strong> and click <strong>Connect</strong>.</li>
                <li>When prompted for authentication, select <strong>Connect using a certificate</strong> and choose your certificate: <code>${identity}</code>.</li>
              </ul>
            </li>
          </ol>
        `;
      case "windows-10":
        return `
          <strong>Windows 10 Setup Steps:</strong>
          <ol>
            <li><strong>Import Certificate:</strong>
              Press <kbd>Win</kbd> + <kbd>R</kbd> (Start &gt; Run), type <code>certmgr.msc</code> and press Enter (or double-click the downloaded <code>.p12</code> file).
              <ul>
                <li>Select <strong>Current User</strong> &gt; click <strong>Next</strong>.</li>
                <li>Enter the 4-digit PIN above when prompted &gt; click <strong>Next</strong>.</li>
                <li>Select <strong>Automatically select the certificate store based on the type of certificate</strong> &gt; click <strong>Finish</strong>.</li>
              </ul>
            </li>
            <li><strong>Configure Wi-Fi Profile:</strong>
              Press <kbd>Win</kbd> + <kbd>R</kbd>, type <code>control.exe /name Microsoft.NetworkAndSharingCenter</code> and press Enter.
              <ul>
                <li>Click <strong>Set up a new connection or network</strong> &gt; choose <strong>Manually connect to a wireless network</strong>.</li>
                <li><strong>Network name:</strong> <code>Spoutin-Secure</code></li>
                <li><strong>Security type:</strong> <strong>WPA2-Enterprise</strong> (or <strong>WPA3-Enterprise</strong>) &gt; click <strong>Next</strong>.</li>
                <li>Click <strong>Change connection settings</strong> &gt; open the <strong>Security</strong> tab.</li>
                <li>Set authentication method: <strong>Microsoft: Smart Card or other certificate</strong>.</li>
                <li>Click <strong>Settings</strong> &gt; ensure your user certificate (<code>${identity}</code>) is selected &gt; click <strong>OK</strong>.</li>
              </ul>
            </li>
            <li><strong>Connect to Wi-Fi:</strong>
              Press <kbd>Win</kbd> + <kbd>R</kbd>, type <code>ms-settings:network-wifi</code> and connect to <strong>Spoutin-Secure</strong> (or click the Wi-Fi icon in the taskbar).
            </li>
          </ol>
        `;
      case "android":
        return `
          <strong>Android Setup Steps:</strong>
          <ol>
            <li>Tap the downloaded certificate file (or go to <em>Settings &gt; Security &gt; More security settings &gt; Install from storage &gt; Wi-Fi certificate</em>).</li>
            <li>Enter the 4-digit PIN above when prompted.</li>
            <li>In Wi-Fi settings for <strong>Spoutin-Secure</strong>:
              <ul>
                <li><strong>EAP method:</strong> <code>TLS</code></li>
                <li><strong>CA certificate:</strong> Select your Root CA (or <code>Trust on First Use</code> / <code>Spoutin-Root-CA</code>)</li>
                <li><strong>Domain:</strong> <code>${domain}</code></li>
                <li><strong>User certificate:</strong> Select the certificate you just imported (<code>${identity}</code>)</li>
                <li><strong>Identity:</strong> <code>${identity}</code></li>
              </ul>
            </li>
          </ol>
        `;
      case "ios":
        return `
          <strong>iPhone / iPad (iOS) Setup Steps:</strong>
          <ol>
            <li>Open the downloaded <code>.p12</code> file to import into Apple Profiles.</li>
            <li>Go to <em>Settings &gt; Profile Downloaded</em> (or <em>General &gt; VPN &amp; Device Management</em>) and tap <strong>Install</strong>.</li>
            <li>Enter your device passcode, then enter the 4-digit PIN when prompted.</li>
            <li>Select <strong>Spoutin-Secure</strong> in Wi-Fi settings and authenticate using identity <code>${identity}</code>.</li>
          </ol>
        `;
      case "macos":
        return `
          <strong>Mac (macOS) Setup Steps:</strong>
          <ol>
            <li>Double-click the downloaded <code>.p12</code> file to open <strong>Keychain Access</strong>.</li>
            <li>Select the <strong>login</strong> keychain and enter the 4-digit PIN when prompted.</li>
            <li>In Wi-Fi settings or menu bar, connect to <strong>Spoutin-Secure</strong>.</li>
            <li>Select your imported certificate (<code>${identity}</code>) when prompted for 802.1X authentication and click <strong>OK</strong>.</li>
          </ol>
        `;
      default:
        return `
          <strong>Linux &amp; Other Platforms:</strong>
          <ol>
            <li>Extract the certificate and private key from the <code>.p12</code> bundle using:
              <div style="margin: 0.35rem 0;"><code>openssl pkcs12 -in ${identity}.p12 -out ${identity}.pem -nodes</code></div>
            </li>
            <li>In your Wi-Fi client (e.g. NetworkManager / wpa_supplicant) for <strong>Spoutin-Secure</strong>:
              <ul>
                <li><strong>Security:</strong> WPA &amp; WPA2 Enterprise</li>
                <li><strong>Authentication:</strong> TLS</li>
                <li><strong>Identity:</strong> <code>${identity}</code></li>
                <li><strong>Domain:</strong> <code>${domain}</code></li>
                <li><strong>User Certificate:</strong> Select your extracted certificate</li>
              </ul>
            </li>
          </ol>
        `;
    }
  }

  function mapPlatformToInstructionKey(platform) {
    if (!platform) return "other";
    const p = String(platform).toLowerCase();
    if (p === "windows" || p === "windows-11" || p === "win11") {
      return "windows-11";
    }
    if (p === "windows-10" || p === "win10") {
      return "windows-10";
    }
    if (p === "android") {
      return "android";
    }
    if (p === "ios") {
      return "ios";
    }
    if (p === "macos") {
      return "macos";
    }
    return "other";
  }

  function updateInstructions() {
    if (!currentApprovedData) return;
    const selectedPlatform = instructionPlatformSelect ? instructionPlatformSelect.value : "windows-11";
    const identity = currentApprovedData.radius_identity || currentApprovedData.device_name;
    const domain = currentApprovedData.radius_domain || "radius.int.spoutin.org";
    platformInstructions.innerHTML = getPlatformGuide(selectedPlatform, identity, domain);
  }

  if (instructionPlatformSelect) {
    instructionPlatformSelect.addEventListener("change", () => {
      updateInstructions();
    });
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

    currentApprovedData = data;

    approvedPin.textContent = data.pin || "----";
    approvedIdentity.textContent = data.radius_identity || data.device_name;
    approvedDomain.textContent = data.radius_domain || "radius.int.spoutin.org";
    approvedVlan.textContent = data.vlan_label || `VLAN ${data.vlan_id}`;

    if (instructionPlatformSelect) {
      instructionPlatformSelect.value = mapPlatformToInstructionKey(data.platform);
    }
    updateInstructions();

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

  // ================= SSH PORTAL TAB & WORKFLOW =================
  const tabWifiBtn = document.getElementById("tab-wifi-btn");
  const tabSshBtn = document.getElementById("tab-ssh-btn");
  const wifiTabSection = document.getElementById("wifi-tab-section");
  const sshTabSection = document.getElementById("ssh-tab-section");

  if (tabWifiBtn && tabSshBtn) {
    tabWifiBtn.addEventListener("click", () => {
      tabWifiBtn.classList.add("active");
      tabSshBtn.classList.remove("active");
      wifiTabSection.classList.remove("hidden");
      sshTabSection.classList.add("hidden");
    });
    tabSshBtn.addEventListener("click", () => {
      tabSshBtn.classList.add("active");
      tabWifiBtn.classList.remove("active");
      sshTabSection.classList.remove("hidden");
      wifiTabSection.classList.add("hidden");
    });
  }

  const sshEnrollForm = document.getElementById("ssh-enroll-form");
  const sshFormView = document.getElementById("ssh-form-view");
  const sshWaitingView = document.getElementById("ssh-waiting-view");
  const sshApprovedView = document.getElementById("ssh-approved-view");
  const sshRejectedView = document.getElementById("ssh-rejected-view");
  const sshFormError = document.getElementById("ssh-form-error");
  const sshWaitingUsername = document.getElementById("ssh-waiting-username");
  const sshCertText = document.getElementById("ssh-cert-text");
  const copySshCertBtn = document.getElementById("copy-ssh-cert-btn");
  const downloadSshCertBtn = document.getElementById("download-ssh-cert-btn");
  const sshRetryBtn = document.getElementById("ssh-retry-btn");

  let sshPollInterval = null;

  function showSshView(view) {
    if (sshFormView) sshFormView.classList.add("hidden");
    if (sshWaitingView) sshWaitingView.classList.add("hidden");
    if (sshApprovedView) sshApprovedView.classList.add("hidden");
    if (sshRejectedView) sshRejectedView.classList.add("hidden");
    if (view) view.classList.remove("hidden");
  }

  if (sshEnrollForm) {
    sshEnrollForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      sshFormError.classList.add("hidden");
      const name = document.getElementById("ssh_name").value.trim();
      const username = document.getElementById("ssh_username").value.trim();
      const deviceName = document.getElementById("ssh_device_name").value.trim();
      const publicKey = document.getElementById("ssh_public_key").value.trim();

      if (!publicKey.startsWith("ssh-") && !publicKey.startsWith("ecdsa-")) {
        sshFormError.textContent = "Invalid public key format. Must start with ssh-ed25519, ssh-rsa, etc.";
        sshFormError.classList.remove("hidden");
        return;
      }

      try {
        const resp = await fetch("/api/ssh/request", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name, username, device_name: deviceName, public_key: publicKey }),
        });
        if (!resp.ok) {
          const err = await resp.json().catch(() => ({}));
          throw new Error(err.detail || "Submission failed");
        }
        const data = await resp.json();
        sshWaitingUsername.textContent = username;
        showSshView(sshWaitingView);
        pollSshRequest(data.request_id);
      } catch (err) {
        sshFormError.textContent = err.message;
        sshFormError.classList.remove("hidden");
      }
    });
  }

  function pollSshRequest(requestId) {
    if (sshPollInterval) clearInterval(sshPollInterval);
    sshPollInterval = setInterval(async () => {
      try {
        const resp = await fetch(`/api/ssh/status/${requestId}`);
        if (!resp.ok) return;
        const data = await resp.json();
        if (data.status === "APPROVED") {
          clearInterval(sshPollInterval);
          sshCertText.value = data.certificate || `Certificate issued for ${data.username}.\nSerial: ${data.request_id}`;
          showSshView(sshApprovedView);
        } else if (data.status === "REJECTED") {
          clearInterval(sshPollInterval);
          showSshView(sshRejectedView);
        }
      } catch (e) {
        console.error("SSH poll failed", e);
      }
    }, 2500);
  }

  if (copySshCertBtn) {
    copySshCertBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(sshCertText.value).then(() => {
        copySshCertBtn.textContent = "✅ Copied!";
        setTimeout(() => { copySshCertBtn.textContent = "📋 Copy Certificate"; }, 2000);
      });
    });
  }

  if (downloadSshCertBtn) {
    downloadSshCertBtn.addEventListener("click", () => {
      const blob = new Blob([sshCertText.value], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "id_ed25519-cert.pub";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  }

  if (sshRetryBtn) {
    sshRetryBtn.addEventListener("click", () => {
      showSshView(sshFormView);
    });
  }
})();
