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
  const tabRequestsView = document.getElementById("tab-requests-view");
  const tabInventoryView = document.getElementById("tab-inventory-view");
  const pendingCounter = document.getElementById("pending-counter");

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
    if (tabName === "requests") {
      tabBtnRequests.classList.add("active");
      tabBtnInventory.classList.remove("active");
      tabRequestsView.classList.remove("hidden");
      tabInventoryView.classList.add("hidden");
    } else {
      tabBtnInventory.classList.add("active");
      tabBtnRequests.classList.remove("active");
      tabInventoryView.classList.remove("hidden");
      tabRequestsView.classList.add("hidden");
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
    await fetchProfile();
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
          <td>
            <button class="btn-sm btn-approve" data-action="quick-approve" data-id="${r.request_id}" data-name="${escapeHtml(r.device_name)}">⚡ Quick (VLAN 8)</button>
            <button class="btn-sm btn-reject" style="color: var(--text-main); border-color: var(--border);" data-action="open-modal" data-id="${r.request_id}" data-name="${escapeHtml(r.device_name)}">✏️ Edit</button>
            <button class="btn-sm btn-reject" data-action="reject" data-id="${r.request_id}">❌ Reject</button>
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
      const certs = await resp.json();

      currentActiveDevices = new Set(
        certs
          .filter((c) => c.status === "ACTIVE")
          .map((c) => c.device_name.toLowerCase())
      );

      inventoryTbody.innerHTML = "";
      if (certs.length === 0) {
        inventoryEmpty.classList.remove("hidden");
        return;
      }
      inventoryEmpty.classList.add("hidden");

      certs.forEach((c) => {
        const tr = document.createElement("tr");
        const isRevoked = c.status === "REVOKED";
        const statusBadge = isRevoked
          ? `<span class="badge badge-revoked">Revoked</span>`
          : `<span class="badge badge-active">Active</span>`;

        const issuedDate = new Date(c.issued_at * 1000).toLocaleDateString();
        const expiresDate = new Date(c.expires_at * 1000).toLocaleDateString();
        const shortSerial = c.serial_number && String(c.serial_number).length > 16
          ? `${String(c.serial_number).slice(0, 8)}...${String(c.serial_number).slice(-8)}`
          : (c.serial_number || "");

        const reqIdHtml = c.request_id
          ? `<div style="font-size: 0.72rem; color: var(--text-muted); font-family: monospace; margin-top: 2px;">req: ${escapeHtml(c.request_id)}</div>`
          : "";

        const serialCellHtml = `
          <span class="serial-cell">
            <code title="Full Serial: ${escapeHtml(c.serial_number)}">${escapeHtml(shortSerial)}</code>
            <button class="btn-copy" data-action="copy-serial" data-serial="${escapeHtml(c.serial_number)}" title="Copy full serial number">
              ${copyIconSvg}
            </button>
          </span>
        `;

        const vlanBadgeHtml = isRevoked
          ? `<span class="badge badge-vlan">${escapeHtml(c.vlan_label || "VLAN " + c.vlan_id)}</span>`
          : `<span class="badge badge-vlan clickable" data-action="open-vlan" data-serial="${escapeHtml(c.serial_number)}" data-name="${escapeHtml(c.device_name)}" data-vlan="${c.vlan_id}" title="Click to edit VLAN assignment">${escapeHtml(c.vlan_label || "VLAN " + c.vlan_id)}</span>`;

        const reasonDisplay = c.revocation_reason_label || formatRevocationReason(c.revocation_reason);
        const actionHtml = isRevoked
          ? `<span class="badge" style="font-size: 0.72rem; font-weight: normal; background: rgba(239, 68, 68, 0.1); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.25); white-space: nowrap;" title="Revocation Reason: ${escapeHtml(c.revocation_reason || 'Revoked')}">${escapeHtml(reasonDisplay)}</span>`
          : `<button class="btn-sm btn-vlan" data-action="open-vlan" data-serial="${escapeHtml(c.serial_number)}" data-name="${escapeHtml(c.device_name)}" data-vlan="${c.vlan_id}">✏️ VLAN</button>
             <button class="btn-sm btn-revoke" data-action="open-revoke" data-serial="${escapeHtml(c.serial_number)}" data-name="${escapeHtml(c.device_name)}">🚫 Revoke</button>`;

        tr.innerHTML = `
          <td><div><strong>${escapeHtml(c.device_name)}</strong></div>${reqIdHtml}</td>
          <td>${escapeHtml(c.platform)}</td>
          <td>${vlanBadgeHtml}</td>
          <td>${serialCellHtml}</td>
          <td>${issuedDate}</td>
          <td>${expiresDate}</td>
          <td>${statusBadge}</td>
          <td>${actionHtml}</td>
        `;
        inventoryTbody.appendChild(tr);
      });
    } catch (e) {
      console.error("Inventory load failed", e);
    }
  }

  // --- Event Delegation for Tables ---
  requestsTbody.addEventListener("click", async (e) => {
    const btn = e.target.closest("button");
    if (!btn) return;
    const action = btn.dataset.action;
    const reqId = btn.dataset.id;
    const name = btn.dataset.name;

    if (action === "quick-approve") {
      btn.disabled = true;
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
        }
      } finally {
        btn.disabled = false;
      }
    } else if (action === "open-modal") {
      activeModalRequestId = reqId;
      editDeviceNameInput.value = name;
      editVlanSelect.value = "8";
      checkDuplicateWarning(name);
      editApproveModal.classList.remove("hidden");
    } else if (action === "reject") {
      if (!confirm(`Are you sure you want to reject request for ${name}?`)) return;
      btn.disabled = true;
      try {
        await adminFetch(`/api/admin/requests/${reqId}/reject`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ reason: "Rejected by admin from web dashboard" }),
        });
        await refreshAll(true);
      } finally {
        btn.disabled = false;
      }
    }
  });

  inventoryTbody.addEventListener("click", (e) => {
    const btn = e.target.closest("button, .badge-vlan.clickable");
    if (!btn) return;
    const action = btn.dataset.action;

    if (action === "copy-serial") {
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
    modalConfirmApproveBtn.disabled = true;

    try {
      const resp = await adminFetch(`/api/admin/requests/${activeModalRequestId}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approved_name: newName, vlan_id: vlanId }),
      });
      if (resp.ok) {
        editApproveModal.classList.add("hidden");
        activeModalRequestId = null;
        await refreshAll(true);
      } else {
        const err = await resp.json();
        alert(`Approval failed: ${err.detail || "Server error"}`);
      }
    } finally {
      modalConfirmApproveBtn.disabled = false;
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
    vlanModalConfirmBtn.disabled = true;

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
      vlanModalConfirmBtn.disabled = false;
    }
  });

  revokeCancelBtn.addEventListener("click", () => {
    revokeModal.classList.add("hidden");
    activeRevokeSerial = null;
  });

  revokeConfirmBtn.addEventListener("click", async () => {
    if (!activeRevokeSerial) return;
    const scopeRadio = document.querySelector('input[name="revoke_scope"]:checked');
    const scope = scopeRadio ? scopeRadio.value : "CERT_ONLY";
    const reason = revokeReasonSelect.value;
    revokeConfirmBtn.disabled = true;

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
    } finally {
      revokeConfirmBtn.disabled = false;
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

  init();
})();
