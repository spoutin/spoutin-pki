(() => {
  // --- DOM Elements ---
  const adminEmailEl = document.getElementById("admin-email");
  const adminAvatarEl = document.getElementById("admin-avatar");
  const logoutBtn = document.getElementById("logout-btn");

  const statActiveEl = document.getElementById("stat-active");
  const statRevokedEl = document.getElementById("stat-revoked");
  const statPendingEl = document.getElementById("stat-pending");
  const vlanPillsEl = document.getElementById("vlan-pills");

  const tabBtnRequests = document.getElementById("tab-btn-requests");
  const tabBtnInventory = document.getElementById("tab-btn-inventory");
  const tabBtnSsh = document.getElementById("tab-btn-ssh");
  const tabRequestsView = document.getElementById("tab-requests-view");
  const tabInventoryView = document.getElementById("tab-inventory-view");
  const tabSshView = document.getElementById("tab-ssh-view");
  const pendingCounter = document.getElementById("pending-counter");

  const adminQuickSignForm = document.getElementById("admin-quick-sign-form");
  const qsResult = document.getElementById("qs-result");
  const qsCertOutput = document.getElementById("qs-cert-output");
  const qsCopyBtn = document.getElementById("qs-copy-btn");
  const qsDownloadBtn = document.getElementById("qs-download-btn");
  const sshRequestsTbody = document.getElementById("ssh-requests-tbody");
  const sshRequestsEmpty = document.getElementById("ssh-requests-empty");
  const sshInventoryTbody = document.getElementById("ssh-inventory-tbody");
  const sshInventoryEmpty = document.getElementById("ssh-inventory-empty");

  const editSshApproveModal = document.getElementById("edit-ssh-approve-modal");
  const editSshKeyIdInput = document.getElementById("edit-ssh-key-id");
  const editSshDeviceInput = document.getElementById("edit-ssh-device");
  const editSshKeyFilenameInput = document.getElementById("edit-ssh-key-filename");
  const editSshPrincipalsInput = document.getElementById("edit-ssh-principals");
  const editSshTtlInput = document.getElementById("edit-ssh-ttl");
  const editSshCancelBtn = document.getElementById("edit-ssh-cancel-btn");
  const editSshConfirmBtn = document.getElementById("edit-ssh-confirm-btn");
  let currentEditingSshRequestId = null;
  let cachedSshRequests = [];

  const qsFileUpload = document.getElementById("qs-file-upload");
  const qsKeyFilenameInput = document.getElementById("qs-key-filename");
  let currentQuickSignFilename = "id_ed25519";

  const requestsTbody = document.getElementById("requests-tbody");
  const requestsEmpty = document.getElementById("requests-empty");

  const inventorySearch = document.getElementById("inventory-search");
  const filterStatus = document.getElementById("filter-status");
  const filterVlan = document.getElementById("filter-vlan");
  const inventoryTbody = document.getElementById("inventory-tbody");
  const inventoryEmpty = document.getElementById("inventory-empty");

  // Modals
  const editApproveModal = document.getElementById("edit-approve-modal");
  const editDeviceNameInput = document.getElementById("edit-device-name");
  const editVlanSelect = document.getElementById("edit-vlan-select");
  const REVOCATION_REASON_LABELS = {
    cessationOfOperation: "Decommissioned / Retired",
    keyCompromise: "Key Compromise",
    affiliationChanged: "Device Lost or Stolen",
    superseded: "Superseded by New Cert",
    privilegeWithdrawn: "Access Withdrawn",
    unspecified: "Revoked (Unspecified)",
    certificateHold: "Certificate Hold",
    cACompromise: "CA Compromise",
  };

  function formatRevocationReason(reason) {
    if (!reason) return "Revoked";
    return REVOCATION_REASON_LABELS[reason] || reason;
  }

  function setButtonLoading(btn, text) {
    if (!btn) return;
    btn.dataset.originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="btn-spinner"></span>${escapeHtml(text)}`;
  }

  function restoreButton(btn) {
    if (!btn || !btn.dataset.originalHtml) return;
    btn.innerHTML = btn.dataset.originalHtml;
    delete btn.dataset.originalHtml;
    btn.disabled = false;
  }

  const modalCancelBtn = document.getElementById("modal-cancel-btn");
  const modalConfirmApproveBtn = document.getElementById("modal-confirm-approve-btn");
  const editApproveWarning = document.getElementById("edit-approve-warning");
  let activeModalRequestId = null;
  let currentActiveDevices = new Set();

  const revokeModal = document.getElementById("revoke-modal");
  const revokeDeviceName = document.getElementById("revoke-device-name");
  const revokeSerial = document.getElementById("revoke-serial");
  const revokeReasonSelect = document.getElementById("revoke-reason-select");
  const revokeCancelBtn = document.getElementById("revoke-cancel-btn");
  const revokeConfirmBtn = document.getElementById("revoke-confirm-btn");
  let activeRevokeSerial = null;

  // Edit VLAN Modal
  const editVlanModal = document.getElementById("edit-vlan-modal");
  const vlanModalDevice = document.getElementById("vlan-modal-device");
  const vlanModalSerial = document.getElementById("vlan-modal-serial");
  const vlanModalSelect = document.getElementById("vlan-modal-select");
  const vlanModalCancelBtn = document.getElementById("vlan-modal-cancel-btn");
  const vlanModalConfirmBtn = document.getElementById("vlan-modal-confirm-btn");
  let activeVlanSerial = null;

  // Sorting state for Inventory Table
  let currentSortCol = "issued_at";
  let currentSortDir = "desc";

  // Metric Cards
  const cardActive = document.getElementById("card-active");
  const cardRevoked = document.getElementById("card-revoked");
  const cardPending = document.getElementById("card-pending");

  const btnRefresh = document.getElementById("btn-refresh");
  const liveIndicator = document.getElementById("live-indicator");
  const liveText = document.getElementById("live-text");
  const pulseDot = document.getElementById("pulse-dot");

  let adminEventSource = null;

  const copyIconSvg = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`;

  // Helper for cache-busting fetch
  async function adminFetch(url, options = {}) {
    const separator = url.includes("?") ? "&" : "?";
    const cacheBustedUrl = `${url}${separator}_t=${Date.now()}`;
    const headers = {
      "Cache-Control": "no-cache, no-store, must-revalidate",
      "Pragma": "no-cache",
      ...(options.headers || {}),
    };
    return fetch(cacheBustedUrl, {
      ...options,
      cache: "no-store",
      headers,
    });
  }

  // --- Tab Switcher Helper ---
  function switchToTab(tabName) {
    tabBtnRequests.classList.remove("active");
    tabBtnInventory.classList.remove("active");
    if (tabBtnSsh) tabBtnSsh.classList.remove("active");
    tabRequestsView.classList.add("hidden");
    tabInventoryView.classList.add("hidden");
    if (tabSshView) tabSshView.classList.add("hidden");

    if (tabName === "requests") {
      tabBtnRequests.classList.add("active");
      tabRequestsView.classList.remove("hidden");
    } else if (tabName === "inventory") {
      tabBtnInventory.classList.add("active");
      tabInventoryView.classList.remove("hidden");
    } else if (tabName === "ssh") {
      if (tabBtnSsh) tabBtnSsh.classList.add("active");
      if (tabSshView) tabSshView.classList.remove("hidden");
      refreshSshData();
    }
  }

  // --- Server-Sent Events (SSE) Connection ---
  function connectSSE() {
    if (!window.EventSource) return;

    if (adminEventSource) {
      adminEventSource.close();
    }

    adminEventSource = new EventSource("/api/admin/events");

    adminEventSource.addEventListener("connected", () => {
      if (liveText) liveText.textContent = "Live (SSE)";
      if (pulseDot) pulseDot.style.backgroundColor = "var(--success)";
      if (liveIndicator) liveIndicator.title = "Connected to Server-Sent Events (instant push updates)";
    });

    const onServerUpdate = () => {
      // Instantly refresh all dashboard components upon push notification
      refreshAll(true);
    };

    adminEventSource.addEventListener("request_created", onServerUpdate);
    adminEventSource.addEventListener("request_approved", onServerUpdate);
    adminEventSource.addEventListener("request_rejected", onServerUpdate);
    adminEventSource.addEventListener("cert_revoked", onServerUpdate);
    adminEventSource.addEventListener("cert_vlan_updated", onServerUpdate);
    adminEventSource.addEventListener("vlan_synced", onServerUpdate);

    adminEventSource.onerror = () => {
      if (liveText) liveText.textContent = "Connecting...";
      if (pulseDot) pulseDot.style.backgroundColor = "var(--warning)";
      refreshAll(false);
    };
  }

  // --- Initial Setup ---
  async function init() {
    updateSortHeaders();
    await fetchProfile();
    await loadAdminSshConfig();
    const [, pendingList] = await Promise.all([
      refreshStats(),
      refreshRequests(),
    ]);
    await refreshInventory();

    // Smart landing page: open pending requests if any, otherwise default to inventory
    if (pendingList && pendingList.length > 0) {
      switchToTab("requests");
    } else {
      switchToTab("inventory");
    }

    connectSSE();

    // Low-frequency safety poll (every 60s) instead of aggressive polling
    setInterval(async () => {
      await refreshAll(false);
    }, 60000);
  }

  async function refreshAll(forceInventory = false) {
    try {
      await Promise.all([
        refreshStats(),
        refreshRequests(),
        (forceInventory || document.activeElement !== inventorySearch)
          ? refreshInventory()
          : Promise.resolve(),
      ]);
    } catch (e) {
      console.error("Auto-refresh cycle error", e);
    }
  }

  // --- API Calls ---
  async function fetchProfile() {
    try {
      const resp = await adminFetch("/api/admin/me");
      if (resp.status === 401 || resp.status === 403) {
        window.location.href = "/admin/login";
        return;
      }
      const data = await resp.json();
      adminEmailEl.textContent = data.email || data.name || "Admin";
      if (data.picture) adminAvatarEl.src = data.picture;
    } catch (e) {
      console.error("Profile load failed", e);
    }
  }

  async function refreshStats() {
    try {
      const resp = await adminFetch("/api/admin/stats");
      if (!resp.ok) return null;
      const stats = await resp.json();
      statActiveEl.textContent = stats.active ?? 0;
      statRevokedEl.textContent = stats.revoked ?? 0;

      vlanPillsEl.innerHTML = "";
      const vlanLabels = { 8: "SemiPrivate", 1: "LAN", 2: "DMS", 9: "IoT" };
      const byVlan = stats.by_vlan || {};
      for (const [vId, count] of Object.entries(byVlan)) {
        const span = document.createElement("span");
        span.className = "vlan-pill clickable";
        span.dataset.vlan = vId;
        span.title = `Click to filter inventory by VLAN ${vId} (${vlanLabels[vId] || "Other"})`;
        span.textContent = `VLAN ${vId} (${vlanLabels[vId] || "Other"}): ${count}`;
        vlanPillsEl.appendChild(span);
      }
      return stats;
    } catch (e) {
      console.error("Stats refresh failed", e);
      return null;
    }
  }

  async function refreshRequests() {
    try {
      const resp = await adminFetch("/api/admin/requests");
      if (!resp.ok) return [];
      const requests = await resp.json();
      statPendingEl.textContent = requests.length;
      pendingCounter.textContent = requests.length;

      requestsTbody.innerHTML = "";
      if (requests.length === 0) {
        requestsEmpty.classList.remove("hidden");
        return requests;
      }
      requestsEmpty.classList.add("hidden");

      requests.forEach((r) => {
        const tr = document.createElement("tr");
        const timeAgo = formatTimeAgo(r.created_at);
        const updateBadge = r.is_update
          ? `<span class="badge" style="background: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.3); font-size: 0.72rem; margin-left: 6px;">⚠️ Update</span>`
          : "";

        tr.innerHTML = `
          <td><strong>${escapeHtml(r.device_name)}</strong>${updateBadge}</td>
          <td><span class="badge badge-vlan">${escapeHtml(r.platform)}</span></td>
          <td><code>${escapeHtml(r.client_ip)}</code></td>
          <td>${timeAgo}</td>
          <td class="actions-cell">
            <div class="action-buttons">
              <button class="btn-sm btn-approve" data-action="quick-approve" data-id="${r.request_id}" data-name="${escapeHtml(r.device_name)}">⚡ Quick (VLAN 8)</button>
              <button class="btn-sm btn-reject" style="color: var(--text-main); border-color: var(--border);" data-action="open-modal" data-id="${r.request_id}" data-name="${escapeHtml(r.device_name)}">✏️ Edit</button>
              <button class="btn-sm btn-reject" data-action="reject" data-id="${r.request_id}">❌ Reject</button>
            </div>
          </td>
        `;
        requestsTbody.appendChild(tr);
      });
      return requests;
    } catch (e) {
      console.error("Requests load failed", e);
      return [];
    }
  }

  let cachedCerts = [];

  async function refreshInventory() {
    const search = inventorySearch.value.trim();
    const status = filterStatus.value;
    const vlan = filterVlan.value;

    const params = new URLSearchParams();
    if (search) params.append("search", search);
    if (status) params.append("status", status);
    if (vlan) params.append("vlan_id", vlan);

    try {
      const resp = await adminFetch(`/api/admin/certificates?${params.toString()}`);
      if (!resp.ok) return;
      cachedCerts = await resp.json();

      currentActiveDevices = new Set(
        cachedCerts
          .filter((c) => c.status === "ACTIVE")
          .map((c) => c.device_name.toLowerCase())
      );

      renderInventoryTable();
    } catch (e) {
      console.error("Inventory load failed", e);
    }
  }

  function renderInventoryTable() {
    inventoryTbody.innerHTML = "";
    if (!cachedCerts || cachedCerts.length === 0) {
      inventoryEmpty.classList.remove("hidden");
      return;
    }
    inventoryEmpty.classList.add("hidden");

    // Sort certificates based on selected column and direction
    const sortedCerts = [...cachedCerts].sort((a, b) => {
      let valA, valB;
      if (currentSortCol === "device_name") {
        valA = (a.device_name || "").toLowerCase();
        valB = (b.device_name || "").toLowerCase();
      } else if (currentSortCol === "platform") {
        valA = (a.platform || "").toLowerCase();
        valB = (b.platform || "").toLowerCase();
      } else if (currentSortCol === "vlan_id") {
        valA = Number(a.vlan_id) || 0;
        valB = Number(b.vlan_id) || 0;
      } else if (currentSortCol === "serial_hex") {
        valA = getHexSerial(a).toLowerCase();
        valB = getHexSerial(b).toLowerCase();
      } else if (currentSortCol === "issued_at") {
        valA = Number(a.issued_at) || 0;
        valB = Number(b.issued_at) || 0;
      } else if (currentSortCol === "expires_at") {
        valA = Number(a.expires_at) || 0;
        valB = Number(b.expires_at) || 0;
      } else if (currentSortCol === "status") {
        valA = (a.status || "").toLowerCase();
        valB = (b.status || "").toLowerCase();
      } else {
        valA = 0;
        valB = 0;
      }

      if (valA < valB) return currentSortDir === "asc" ? -1 : 1;
      if (valA > valB) return currentSortDir === "asc" ? 1 : -1;
      return 0;
    });

    sortedCerts.forEach((c) => {
      const tr = document.createElement("tr");
      const isRevoked = c.status === "REVOKED";
      const statusBadge = isRevoked
        ? `<span class="badge badge-revoked">Revoked</span>`
        : `<span class="badge badge-active">Active</span>`;

      const issuedObj = new Date(c.issued_at * 1000);
      const expiresObj = new Date(c.expires_at * 1000);
      const issuedFormatted = formatDateTime(c.issued_at);
      const expiresFormatted = formatDateTime(c.expires_at);
      const issuedTooltip = issuedObj.toLocaleString();
      const expiresTooltip = expiresObj.toLocaleString();

      const hexSerial = getHexSerial(c);
      const shortSerial = hexSerial && hexSerial.length > 16
        ? `${hexSerial.slice(0, 8)}...${hexSerial.slice(-8)}`
        : (hexSerial || "");

      const reqIdHtml = c.request_id
        ? `<span style="font-size: 0.72rem; color: var(--text-muted); font-family: monospace;">req: ${escapeHtml(c.request_id)}</span>`
        : "";

      const pinHtml = (!isRevoked && c.pin)
        ? `<button class="badge-pin" data-action="copy-pin" data-pin="${escapeHtml(c.pin)}" title="Click to copy Import PIN">PIN: <strong>${escapeHtml(c.pin)}</strong></button>`
        : "";

      const metaLine = (reqIdHtml || pinHtml)
        ? `<div style="display: flex; align-items: center; gap: 0.45rem; margin-top: 3px; flex-wrap: wrap;">${reqIdHtml}${pinHtml}</div>`
        : "";

      const serialCellHtml = `
        <span class="serial-cell">
          <code title="Hex Serial: ${escapeHtml(hexSerial)} (Matches OPNsense / OpenSSL CRL)">${escapeHtml(shortSerial)}</code>
          <button class="btn-copy" data-action="copy-serial" data-serial="${escapeHtml(hexSerial)}" title="Copy full hex serial number: ${escapeHtml(hexSerial)}">
            ${copyIconSvg}
          </button>
        </span>
      `;

      const vlanBadgeHtml = isRevoked
        ? `<span class="badge badge-vlan">${escapeHtml(c.vlan_label || "VLAN " + c.vlan_id)}</span>`
        : `<span class="badge badge-vlan clickable" data-action="open-vlan" data-serial="${escapeHtml(c.serial_number)}" data-name="${escapeHtml(c.device_name)}" data-vlan="${c.vlan_id}" title="Click to edit VLAN assignment">${escapeHtml(c.vlan_label || "VLAN " + c.vlan_id)}</span>`;

      const reasonDisplay = c.revocation_reason_label || formatRevocationReason(c.revocation_reason);
      const downloadBtnHtml = (!isRevoked && c.download_available)
        ? `<a href="/api/admin/certificates/${encodeURIComponent(c.serial_number)}/download" class="btn-sm btn-download" title="Download .p12 certificate bundle (available for 24h)">⬇️ .p12</a>`
        : "";
      const actionHtml = isRevoked
        ? `<span class="badge" style="font-size: 0.72rem; font-weight: normal; background: rgba(239, 68, 68, 0.1); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.25); white-space: nowrap;" title="Revocation Reason: ${escapeHtml(c.revocation_reason || 'Revoked')}">${escapeHtml(reasonDisplay)}</span>`
        : `<div class="action-buttons">
            ${downloadBtnHtml}
            <button class="btn-sm btn-vlan" data-action="open-vlan" data-serial="${escapeHtml(c.serial_number)}" data-name="${escapeHtml(c.device_name)}" data-vlan="${c.vlan_id}">✏️ VLAN</button>
            <button class="btn-sm btn-revoke" data-action="open-revoke" data-serial="${escapeHtml(c.serial_number)}" data-name="${escapeHtml(c.device_name)}">🚫 Revoke</button>
          </div>`;

      tr.innerHTML = `
        <td><div><strong>${escapeHtml(c.device_name)}</strong></div>${metaLine}</td>
        <td>${escapeHtml(c.platform)}</td>
        <td>${vlanBadgeHtml}</td>
        <td>${serialCellHtml}</td>
        <td title="${escapeHtml(issuedTooltip)}" class="timestamp-cell">${issuedFormatted}</td>
        <td title="${escapeHtml(expiresTooltip)}" class="timestamp-cell">${expiresFormatted}</td>
        <td>${statusBadge}</td>
        <td class="actions-cell">${actionHtml}</td>
      `;
      inventoryTbody.appendChild(tr);
    });
  }

  // --- Event Delegation for Tables ---
  requestsTbody.addEventListener("click", async (e) => {
    const btn = e.target.closest("button");
    if (!btn) return;
    const action = btn.dataset.action;
    const reqId = btn.dataset.id;
    const name = btn.dataset.name;

    if (action === "quick-approve") {
      const tr = btn.closest("tr");
      if (tr) tr.querySelectorAll("button").forEach((b) => (b.disabled = true));
      setButtonLoading(btn, "Approving...");
      try {
        const resp = await adminFetch(`/api/admin/requests/${reqId}/approve`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ approved_name: name, vlan_id: 8 }),
        });
        if (resp.ok) {
          await refreshAll(true);
        } else {
          const err = await resp.json();
          alert(`Approval failed: ${err.detail || "Server error"}`);
          restoreButton(btn);
          if (tr) tr.querySelectorAll("button").forEach((b) => (b.disabled = false));
        }
      } catch (e) {
        alert(`Network error during approval: ${e.message}`);
        restoreButton(btn);
        if (tr) tr.querySelectorAll("button").forEach((b) => (b.disabled = false));
      }
    } else if (action === "open-modal") {
      activeModalRequestId = reqId;
      editDeviceNameInput.value = name;
      editVlanSelect.value = "8";
      checkDuplicateWarning(name);
      editApproveModal.classList.remove("hidden");
    } else if (action === "reject") {
      if (!confirm(`Are you sure you want to reject request for ${name}?`)) return;
      const tr = btn.closest("tr");
      if (tr) tr.querySelectorAll("button").forEach((b) => (b.disabled = true));
      setButtonLoading(btn, "Rejecting...");
      try {
        await adminFetch(`/api/admin/requests/${reqId}/reject`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ reason: "Rejected by admin from web dashboard" }),
        });
        await refreshAll(true);
      } catch (e) {
        alert(`Network error rejecting request: ${e.message}`);
        restoreButton(btn);
        if (tr) tr.querySelectorAll("button").forEach((b) => (b.disabled = false));
      }
    }
  });

  inventoryTbody.addEventListener("click", (e) => {
    const btn = e.target.closest("button, .badge-vlan.clickable, .badge-pin");
    if (!btn) return;
    const action = btn.dataset.action;

    if (action === "copy-pin") {
      const pin = btn.dataset.pin;
      if (!pin) return;
      navigator.clipboard.writeText(pin).then(() => {
        const origHtml = btn.innerHTML;
        btn.classList.add("copied");
        btn.textContent = "✓ Copied!";
        setTimeout(() => {
          btn.innerHTML = origHtml;
          btn.classList.remove("copied");
        }, 1500);
      }).catch((err) => {
        console.error("Copy PIN failed:", err);
      });
      return;
    } else if (action === "copy-serial") {
      const serial = btn.dataset.serial;
      if (!serial) return;
      navigator.clipboard.writeText(serial).then(() => {
        btn.classList.add("copied");
        btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
        setTimeout(() => {
          btn.classList.remove("copied");
          btn.innerHTML = copyIconSvg;
        }, 1500);
      }).catch((err) => {
        console.error("Clipboard write failed:", err);
      });
    } else if (action === "open-vlan") {
      activeVlanSerial = btn.dataset.serial;
      vlanModalSerial.textContent = activeVlanSerial;
      vlanModalDevice.textContent = btn.dataset.name;
      vlanModalSelect.value = String(btn.dataset.vlan || "8");
      editVlanModal.classList.remove("hidden");
    } else if (action === "open-revoke") {
      activeRevokeSerial = btn.dataset.serial;
      revokeSerial.textContent = activeRevokeSerial;
      revokeDeviceName.textContent = btn.dataset.name;
      const defaultRadio = document.querySelector('input[name="revoke_scope"][value="USER_AND_CERT"]');
      if (defaultRadio) defaultRadio.checked = true;
      revokeModal.classList.remove("hidden");
    }
  });

  // --- Modal Event Listeners ---
  function checkDuplicateWarning(name) {
    if (!editApproveWarning) return;
    const exists = name && currentActiveDevices.has(name.toLowerCase());
    if (exists) {
      editApproveWarning.classList.remove("hidden");
    } else {
      editApproveWarning.classList.add("hidden");
    }
  }

  editDeviceNameInput.addEventListener("input", () => {
    checkDuplicateWarning(editDeviceNameInput.value.trim());
  });

  modalCancelBtn.addEventListener("click", () => {
    editApproveModal.classList.add("hidden");
    activeModalRequestId = null;
  });

  modalConfirmApproveBtn.addEventListener("click", async () => {
    if (!activeModalRequestId) return;
    const newName = editDeviceNameInput.value.trim();
    const vlanId = parseInt(editVlanSelect.value, 10);
    setButtonLoading(modalConfirmApproveBtn, "Issuing...");
    modalCancelBtn.disabled = true;

    try {
      const resp = await adminFetch(`/api/admin/requests/${activeModalRequestId}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approved_name: newName, vlan_id: vlanId }),
      });
      if (resp.ok) {
        const data = await resp.json();
        editApproveModal.classList.add("hidden");
        activeModalRequestId = null;
        await refreshAll(true);
        if (data.pin) {
          const dlNote = data.serial_number
            ? `\n\n⬇️ The .p12 bundle can be downloaded from the inventory table for the next 24 hours.`
            : "";
          alert(`✅ Approved ${newName} (VLAN ${vlanId})!\n\nImport PIN: ${data.pin}${dlNote}`);
        }
      } else {
        const err = await resp.json();
        alert(`Approval failed: ${err.detail || "Server error"}`);
      }
    } finally {
      restoreButton(modalConfirmApproveBtn);
      modalCancelBtn.disabled = false;
    }
  });

  // Edit VLAN Modal Listeners
  vlanModalCancelBtn.addEventListener("click", () => {
    editVlanModal.classList.add("hidden");
    activeVlanSerial = null;
  });

  vlanModalConfirmBtn.addEventListener("click", async () => {
    if (!activeVlanSerial) return;
    const newVlanId = parseInt(vlanModalSelect.value, 10);
    setButtonLoading(vlanModalConfirmBtn, "Saving...");
    vlanModalCancelBtn.disabled = true;

    try {
      const resp = await adminFetch(`/api/admin/certificates/${activeVlanSerial}/vlan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ vlan_id: newVlanId }),
      });
      if (resp.ok) {
        editVlanModal.classList.add("hidden");
        activeVlanSerial = null;
        await refreshAll(true);
      } else {
        const err = await resp.json();
        alert(`Failed to update VLAN: ${err.detail || "Server error"}`);
      }
    } catch (e) {
      alert(`Network error updating VLAN: ${e.message}`);
    } finally {
      restoreButton(vlanModalConfirmBtn);
      vlanModalCancelBtn.disabled = false;
    }
  });

  revokeCancelBtn.addEventListener("click", () => {
    revokeModal.classList.add("hidden");
    activeRevokeSerial = null;
  });

  revokeConfirmBtn.addEventListener("click", async () => {
    if (!activeRevokeSerial) return;
    const scopeRadio = document.querySelector('input[name="revoke_scope"]:checked');
    const scope = scopeRadio ? scopeRadio.value : "USER_AND_CERT";
    const reason = revokeReasonSelect.value;
    setButtonLoading(revokeConfirmBtn, "Revoking...");
    revokeCancelBtn.disabled = true;

    try {
      const resp = await adminFetch(`/api/admin/certificates/${activeRevokeSerial}/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: reason, scope: scope }),
      });
      if (resp.ok) {
        revokeModal.classList.add("hidden");
        activeRevokeSerial = null;
        await refreshAll(true);
      } else {
        const err = await resp.json();
        alert(`Revocation failed: ${err.detail || "Server error"}`);
      }
    } catch (e) {
      alert(`Network error revoking certificate: ${e.message}`);
    } finally {
      restoreButton(revokeConfirmBtn);
      revokeCancelBtn.disabled = false;
    }
  });

  // --- Filter Listeners ---
  let debounceTimeout;
  inventorySearch.addEventListener("input", () => {
    clearTimeout(debounceTimeout);
    debounceTimeout = setTimeout(refreshInventory, 300);
  });
  filterStatus.addEventListener("change", refreshInventory);
  filterVlan.addEventListener("change", refreshInventory);

  // --- Top Metric Cards Navigation Listeners ---
  if (cardActive) {
    cardActive.addEventListener("click", () => {
      switchToTab("inventory");
      filterStatus.value = "ACTIVE";
      filterVlan.value = "";
      refreshInventory();
      refreshStats();
    });
  }

  if (cardRevoked) {
    cardRevoked.addEventListener("click", () => {
      switchToTab("inventory");
      filterStatus.value = "REVOKED";
      filterVlan.value = "";
      refreshInventory();
      refreshStats();
    });
  }

  if (cardPending) {
    cardPending.addEventListener("click", () => {
      switchToTab("requests");
      refreshRequests();
      refreshStats();
    });
  }

  vlanPillsEl.addEventListener("click", (e) => {
    const pill = e.target.closest(".vlan-pill");
    if (!pill || !pill.dataset.vlan) return;
    switchToTab("inventory");
    filterVlan.value = pill.dataset.vlan;
    filterStatus.value = "";
    refreshInventory();
  });

  // --- Tab Switcher ---
  tabBtnRequests.addEventListener("click", () => {
    switchToTab("requests");
    refreshRequests();
    refreshStats();
  });

  tabBtnInventory.addEventListener("click", () => {
    switchToTab("inventory");
    refreshInventory();
    refreshStats();
  });

  if (tabBtnSsh) {
    tabBtnSsh.addEventListener("click", () => {
      switchToTab("ssh");
    });
  }

  async function refreshSshData() {
    await Promise.all([refreshSshRequests(), refreshSshInventory()]);
  }

  async function refreshSshRequests() {
    if (!sshRequestsTbody) return;
    try {
      const resp = await adminFetch("/api/admin/ssh/requests?status=PENDING");
      if (!resp.ok) return;
      const requests = await resp.json();
      cachedSshRequests = requests;
      sshRequestsTbody.innerHTML = "";
      if (requests.length === 0) {
        if (sshRequestsEmpty) sshRequestsEmpty.classList.remove("hidden");
        return;
      }
      if (sshRequestsEmpty) sshRequestsEmpty.classList.add("hidden");

      requests.forEach((r) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${escapeHtml(r.name)}</strong></td>
          <td><code>${escapeHtml(r.username)}</code></td>
          <td>${escapeHtml(r.device_name)}</td>
          <td><code>${escapeHtml(r.principals)}</code></td>
          <td><code style="font-size: 0.72rem;">${escapeHtml(r.key_fingerprint)}</code></td>
          <td class="actions-cell">
            <div class="action-buttons">
              <button class="btn-sm btn-approve" data-action="ssh-approve" data-id="${r.request_id}">⚡ Approve</button>
              <button class="btn-sm btn-reject" style="color: var(--text-main); border-color: var(--border);" data-action="ssh-open-modal" data-id="${r.request_id}">✏️ Edit</button>
              <button class="btn-sm btn-reject" data-action="ssh-reject" data-id="${r.request_id}">❌ Reject</button>
            </div>
          </td>
        `;
        sshRequestsTbody.appendChild(tr);
      });
    } catch (e) {
      console.error("Failed to load SSH requests", e);
    }
  }

  async function refreshSshInventory() {
    if (!sshInventoryTbody) return;
    try {
      const resp = await adminFetch("/api/admin/ssh/certificates");
      if (!resp.ok) return;
      const certs = await resp.json();
      sshInventoryTbody.innerHTML = "";
      if (certs.length === 0) {
        if (sshInventoryEmpty) sshInventoryEmpty.classList.remove("hidden");
        return;
      }
      if (sshInventoryEmpty) sshInventoryEmpty.classList.add("hidden");

      certs.forEach((c) => {
        const tr = document.createElement("tr");
        const isRevoked = c.status === "REVOKED";
        const statusBadge = isRevoked
          ? `<span class="badge badge-revoked">REVOKED</span>`
          : `<span class="badge badge-active">ACTIVE</span>`;
        const revokeBtn = isRevoked
          ? ""
          : `<button class="btn-sm btn-reject" data-action="ssh-revoke" data-serial="${c.serial_number}">Revoke</button>`;

        tr.innerHTML = `
          <td><strong>${escapeHtml(c.key_id)}</strong></td>
          <td><code>${escapeHtml(c.serial_number)}</code></td>
          <td><code>${escapeHtml(c.principals)}</code></td>
          <td><code style="font-size: 0.72rem;">${escapeHtml(c.key_fingerprint || "-")}</code></td>
          <td>${statusBadge}</td>
          <td>${revokeBtn}</td>
        `;
        sshInventoryTbody.appendChild(tr);
      });
    } catch (e) {
      console.error("Failed to load SSH inventory", e);
    }
  }

  let cachedAllowedPrincipals = ["ablack", "operator", "root"];

  async function loadAdminSshConfig() {
    try {
      const resp = await adminFetch("/api/ssh/config");
      if (!resp.ok) return;
      const data = await resp.json();
      cachedAllowedPrincipals = data.allowed_principals || ["ablack", "operator", "root"];
      renderQsPrincipals(data.default_principals || ["ablack", "root", "operator"]);
    } catch (e) {
      console.error("Failed to load SSH config in admin", e);
    }
  }

  function renderQsPrincipals(selectedList) {
    const group = document.getElementById("qs-principals-group");
    if (!group) return;
    group.innerHTML = "";
    cachedAllowedPrincipals.forEach(p => {
      const isChecked = selectedList.includes(p);
      const label = document.createElement("label");
      label.style.display = "inline-flex";
      label.style.alignItems = "center";
      label.style.gap = "0.3rem";
      label.style.background = "var(--bg)";
      label.style.border = "1px solid var(--border)";
      label.style.padding = "0.25rem 0.5rem";
      label.style.borderRadius = "6px";
      label.style.fontSize = "0.8rem";
      label.style.cursor = "pointer";
      label.innerHTML = `<input type="checkbox" name="qs_principals" value="${p}" ${isChecked ? "checked" : ""}> <code>${p}</code>`;
      group.appendChild(label);
    });
  }

  function renderEditModalPrincipals(selectedList) {
    const group = document.getElementById("edit-ssh-principals-group");
    if (!group) return;
    group.innerHTML = "";
    cachedAllowedPrincipals.forEach(p => {
      const isChecked = selectedList.includes(p);
      const label = document.createElement("label");
      label.style.display = "inline-flex";
      label.style.alignItems = "center";
      label.style.gap = "0.3rem";
      label.style.background = "var(--bg)";
      label.style.border = "1px solid var(--border)";
      label.style.padding = "0.25rem 0.5rem";
      label.style.borderRadius = "6px";
      label.style.fontSize = "0.8rem";
      label.style.cursor = "pointer";
      label.innerHTML = `<input type="checkbox" name="edit_modal_principals" value="${p}" ${isChecked ? "checked" : ""}> <code>${p}</code>`;
      group.appendChild(label);
    });
  }

  if (qsFileUpload) {
    qsFileUpload.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (!file) return;
      let baseName = file.name;
      if (baseName.endsWith(".pub")) {
        baseName = baseName.substring(0, baseName.length - 4);
      }
      if (qsKeyFilenameInput) {
        qsKeyFilenameInput.value = baseName;
      }
      const reader = new FileReader();
      reader.onload = (evt) => {
        const keyArea = document.getElementById("qs-public-key");
        if (keyArea) keyArea.value = evt.target.result.trim();
      };
      reader.readAsText(file);
    });
  }

  const qsPublicKeyArea = document.getElementById("qs-public-key");
  if (qsPublicKeyArea) {
    qsPublicKeyArea.addEventListener("input", () => {
      const text = qsPublicKeyArea.value.trim();
      let detected = null;
      if (text.startsWith("ssh-ed25519")) detected = "id_ed25519";
      else if (text.startsWith("ssh-rsa")) detected = "id_rsa";
      else if (text.startsWith("ecdsa-sha2-")) detected = "id_ecdsa";
      if (detected && qsKeyFilenameInput && (!qsKeyFilenameInput.value || qsKeyFilenameInput.value === "id_ed25519" || qsKeyFilenameInput.value === "id_rsa")) {
        qsKeyFilenameInput.value = detected;
      }
    });

    qsPublicKeyArea.addEventListener("dragover", (e) => {
      e.preventDefault();
      qsPublicKeyArea.style.borderColor = "var(--primary)";
      qsPublicKeyArea.style.background = "rgba(37, 99, 235, 0.05)";
    });
    qsPublicKeyArea.addEventListener("dragleave", () => {
      qsPublicKeyArea.style.borderColor = "var(--border)";
      qsPublicKeyArea.style.background = "var(--bg)";
    });
    qsPublicKeyArea.addEventListener("drop", (e) => {
      e.preventDefault();
      qsPublicKeyArea.style.borderColor = "var(--border)";
      qsPublicKeyArea.style.background = "var(--bg)";
      if (e.dataTransfer && e.dataTransfer.files.length > 0) {
        const file = e.dataTransfer.files[0];
        let baseName = file.name;
        if (baseName.endsWith(".pub")) {
          baseName = baseName.substring(0, baseName.length - 4);
        }
        if (qsKeyFilenameInput) qsKeyFilenameInput.value = baseName;
        const reader = new FileReader();
        reader.onload = (evt) => {
          qsPublicKeyArea.value = evt.target.result.trim();
        };
        reader.readAsText(file);
      }
    });
  }

  // Quick Sign Form submit
  if (adminQuickSignForm) {
    adminQuickSignForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const keyId = document.getElementById("qs-key-id").value.trim();
      const principals = Array.from(document.querySelectorAll('input[name="qs_principals"]:checked')).map(cb => cb.value);
      const publicKey = document.getElementById("qs-public-key").value.trim();
      const ttl = document.getElementById("qs-ttl").value.trim();
      const keyFilename = (qsKeyFilenameInput ? qsKeyFilenameInput.value.trim() : "") || "id_ed25519";
      currentQuickSignFilename = keyFilename;
      const submitBtn = document.getElementById("btn-quick-sign");

      if (principals.length === 0) {
        alert("Please select at least one authorized principal.");
        return;
      }

      submitBtn.disabled = true;
      submitBtn.textContent = "Signing with OpenBao...";
      try {
        const resp = await adminFetch("/api/admin/ssh/quick-sign", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ key_id: keyId, principals, public_key: publicKey, ttl, key_filename: keyFilename }),
        });
        if (!resp.ok) {
          const err = await resp.json().catch(() => ({}));
          throw new Error(err.detail || "Signing failed");
        }
        const data = await resp.json();
        qsCertOutput.value = data.certificate;
        qsResult.classList.remove("hidden");
        refreshSshInventory();
      } catch (err) {
        alert("Quick-sign failed: " + err.message);
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = "⚡ Sign & Issue Certificate";
      }
    });
  }

  if (qsCopyBtn) {
    qsCopyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(qsCertOutput.value).then(() => {
        qsCopyBtn.textContent = "✅ Copied!";
        setTimeout(() => { qsCopyBtn.textContent = "📋 Copy"; }, 2000);
      });
    });
  }

  if (qsDownloadBtn) {
    qsDownloadBtn.addEventListener("click", () => {
      const blob = new Blob([qsCertOutput.value], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${currentQuickSignFilename}-cert.pub`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  }

  // SSH Table Actions
  if (sshRequestsTbody) {
    sshRequestsTbody.addEventListener("click", async (e) => {
      const btn = e.target.closest("button[data-action]");
      if (!btn) return;
      const action = btn.dataset.action;
      const reqId = btn.dataset.id;
      if (action === "ssh-open-modal") {
        const req = cachedSshRequests.find(r => r.request_id === reqId);
        if (!req) return;
        currentEditingSshRequestId = reqId;
        editSshKeyIdInput.value = req.username || "";
        editSshDeviceInput.value = req.device_name || "";
        if (editSshKeyFilenameInput) {
          editSshKeyFilenameInput.value = req.key_filename || "id_ed25519";
        }
        const reqPrincipals = (req.principals || "ablack,root,operator").split(",").map(p => p.trim()).filter(Boolean);
        renderEditModalPrincipals(reqPrincipals);
        editSshTtlInput.value = req.requested_ttl || "70080h";
        editSshApproveModal.classList.remove("hidden");
        return;
      }
      if (action === "ssh-approve") {
        btn.disabled = true;
        btn.textContent = "Approving...";
        try {
          const resp = await adminFetch(`/api/admin/ssh/requests/${reqId}/approve`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({}),
          });
          if (!resp.ok) throw new Error("Approval failed");
          refreshSshData();
        } catch (err) {
          alert("Approval failed: " + err.message);
          btn.disabled = false;
        }
      } else if (action === "ssh-reject") {
        if (!confirm("Reject this SSH request?")) return;
        btn.disabled = true;
        try {
          await adminFetch(`/api/admin/ssh/requests/${reqId}/reject`, { method: "POST" });
          refreshSshData();
        } catch (err) {
          alert("Reject failed: " + err.message);
          btn.disabled = false;
        }
      }
    });
  }

  if (editSshCancelBtn) {
    editSshCancelBtn.addEventListener("click", () => {
      editSshApproveModal.classList.add("hidden");
      currentEditingSshRequestId = null;
    });
  }

  if (editSshConfirmBtn) {
    editSshConfirmBtn.addEventListener("click", async () => {
      if (!currentEditingSshRequestId) return;
      const keyId = editSshKeyIdInput.value.trim();
      const deviceName = editSshDeviceInput.value.trim();
      const keyFilename = (editSshKeyFilenameInput ? editSshKeyFilenameInput.value.trim() : "") || "id_ed25519";
      const principals = Array.from(document.querySelectorAll('input[name="edit_modal_principals"]:checked')).map(cb => cb.value);
      const ttl = editSshTtlInput.value.trim();

      if (principals.length === 0) {
        alert("Please select at least one authorized principal.");
        return;
      }

      editSshConfirmBtn.disabled = true;
      editSshConfirmBtn.textContent = "Signing with OpenBao...";
      try {
        const resp = await adminFetch(`/api/admin/ssh/requests/${currentEditingSshRequestId}/approve`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ key_id: keyId, device_name: deviceName, key_filename: keyFilename, principals, ttl }),
        });
        if (!resp.ok) {
          const err = await resp.json().catch(() => ({}));
          throw new Error(err.detail || "Approval failed");
        }
        editSshApproveModal.classList.add("hidden");
        currentEditingSshRequestId = null;
        refreshSshData();
      } catch (err) {
        alert("Approval failed: " + err.message);
      } finally {
        editSshConfirmBtn.disabled = false;
        editSshConfirmBtn.textContent = "Sign & Approve with OpenBao";
      }
    });
  }

  if (sshInventoryTbody) {
    sshInventoryTbody.addEventListener("click", async (e) => {
      const btn = e.target.closest("button[data-action='ssh-revoke']");
      if (!btn) return;
      const serial = btn.dataset.serial;
      if (!confirm(`Are you sure you want to revoke SSH certificate serial ${serial}?`)) return;
      btn.disabled = true;
      try {
        const resp = await adminFetch(`/api/admin/ssh/certificates/${serial}/revoke`, { method: "POST" });
        if (!resp.ok) throw new Error("Revocation failed");
        refreshSshInventory();
      } catch (err) {
        alert("Revoke failed: " + err.message);
        btn.disabled = false;
      }
    });
  }

  // --- Manual Refresh Button ---
  if (btnRefresh) {
    btnRefresh.addEventListener("click", async () => {
      btnRefresh.classList.add("spinning");
      btnRefresh.disabled = true;
      try {
        // Trigger background FreeRADIUS sync and reload UI in parallel
        await Promise.all([
          adminFetch("/api/admin/sync-radius", { method: "POST" }),
          refreshAll(true),
        ]);
      } finally {
        setTimeout(() => {
          btnRefresh.classList.remove("spinning");
          btnRefresh.disabled = false;
        }, 400);
      }
    });
  }

  // --- Logout ---
  logoutBtn.addEventListener("click", async () => {
    await adminFetch("/admin/auth/logout", { method: "POST" });
    window.location.href = "/admin/login";
  });

  // --- Helper Functions ---
  function escapeHtml(text) {
    if (!text) return "";
    return String(text).replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[m]);
  }

  function formatTimeAgo(epochSec) {
    const diff = Math.floor(Date.now() / 1000 - epochSec);
    if (diff < 60) return "just now";
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  function formatDateTime(epochSec) {
    if (!epochSec) return "-";
    const d = new Date(epochSec * 1000);
    const pad = (n) => String(n).padStart(2, "0");
    const year = d.getFullYear();
    const month = pad(d.getMonth() + 1);
    const day = pad(d.getDate());
    const hours = pad(d.getHours());
    const minutes = pad(d.getMinutes());
    return `${year}-${month}-${day} ${hours}:${minutes}`;
  }

  function getHexSerial(c) {
    if (c.serial_hex) return String(c.serial_hex).toUpperCase();
    if (c.serial_number) {
      try {
        return BigInt(c.serial_number).toString(16).toUpperCase();
      } catch (e) {
        return String(c.serial_number).toUpperCase();
      }
    }
    return "";
  }

  // --- Table Header Sorting ---
  const inventoryTable = document.getElementById("inventory-table");
  if (inventoryTable) {
    inventoryTable.querySelector("thead").addEventListener("click", (e) => {
      const th = e.target.closest("th.sortable");
      if (!th) return;
      const col = th.dataset.sort;
      if (!col) return;

      if (currentSortCol === col) {
        currentSortDir = currentSortDir === "asc" ? "desc" : "asc";
      } else {
        currentSortCol = col;
        currentSortDir = (col === "issued_at" || col === "expires_at") ? "desc" : "asc";
      }

      updateSortHeaders();
      renderInventoryTable();
    });
  }

  function updateSortHeaders() {
    document.querySelectorAll("#inventory-table th.sortable").forEach((th) => {
      const col = th.dataset.sort;
      const icon = th.querySelector(".sort-icon");
      th.classList.remove("sorted-asc", "sorted-desc");
      if (col === currentSortCol) {
        th.classList.add(currentSortDir === "asc" ? "sorted-asc" : "sorted-desc");
        if (icon) icon.textContent = currentSortDir === "asc" ? "▲" : "▼";
      } else {
        if (icon) icon.textContent = "";
      }
    });
  }

  init();
})();
