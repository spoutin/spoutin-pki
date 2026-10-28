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
  const tabBtnGuests = document.getElementById("tab-btn-guests");
  const tabRequestsView = document.getElementById("tab-requests-view");
  const tabInventoryView = document.getElementById("tab-inventory-view");
  const tabSshView = document.getElementById("tab-ssh-view");
  const tabGuestsView = document.getElementById("tab-guests-view");
  const pendingCounter = document.getElementById("pending-counter");
  const guestsCounter = document.getElementById("guests-counter");

  // Guest Wi-Fi elements
  const guestsTbody = document.getElementById("guests-tbody");
  const guestsEmpty = document.getElementById("guests-empty");
  const guestsSearch = document.getElementById("guests-search");
  const filterGuestStatus = document.getElementById("filter-guest-status");
  const revokeGuestModal = document.getElementById("revoke-guest-modal");
  const modalGuestName = document.getElementById("modal-guest-name");
  const modalGuestMac = document.getElementById("modal-guest-mac");
  const modalGuestCancelBtn = document.getElementById("modal-guest-cancel-btn");
  const modalGuestConfirmBtn = document.getElementById("modal-guest-confirm-btn");
  let activeRevokeGuestMac = null;

  // Modify Guest Expiry Modal
  const modifyExpiryModal = document.getElementById("modify-expiry-modal");
  const modalGuestTitle = document.getElementById("modal-guest-title");
  const modalCloseBtn = document.getElementById("modal-close-btn");
  const modalGuestInfo = document.getElementById("modal-guest-info");
  const modalCurrentExpiry = document.getElementById("modal-current-expiry");
  const modalDatetimeInput = document.getElementById("modal-datetime-input");
  const modalPreviewSummary = document.getElementById("modal-preview-summary");
  const modalCancelBtn = document.querySelector("#modify-expiry-modal #modal-cancel-btn");
  const modalApplyBtn = document.getElementById("modal-apply-btn");
  let activeModifyGuestMac = null;
  let activeModifyInitialExpiry = null;

  let cachedGuests = [];
  let cachedSpeedProfiles = [];
  let guestCountdownInterval = null;
  const inFlightGuestActions = new Set();

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

  const editApproveCancelBtn = document.getElementById("edit-approve-cancel-btn") || document.getElementById("modal-cancel-btn");
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
    if (tabBtnGuests) tabBtnGuests.classList.remove("active");
    tabRequestsView.classList.add("hidden");
    tabInventoryView.classList.add("hidden");
    if (tabSshView) tabSshView.classList.add("hidden");
    if (tabGuestsView) tabGuestsView.classList.add("hidden");

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
    } else if (tabName === "guests") {
      if (tabBtnGuests) tabBtnGuests.classList.add("active");
      if (tabGuestsView) tabGuestsView.classList.remove("hidden");
      fetchSpeedProfiles().finally(() => refreshGuests());
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

    // Guest Wi-Fi SSE Handlers
    adminEventSource.addEventListener("guest_requested", (event) => {
      try {
        const data = JSON.parse(event.data);
        const normMac = (data.mac || "").toLowerCase().trim();
        const existingIdx = cachedGuests.findIndex((g) => (g.mac || "").toLowerCase().trim() === normMac);
        const item = {
          id: data.id,
          mac: data.mac,
          name: data.name || "",
          reason: data.reason || "",
          duration_minutes: data.duration_minutes || 1440,
          requested_at: data.requested_at || Math.floor(Date.now() / 1000),
          status: "PENDING",
          online: false,
          ip: "",
          hostname: "",
          usergroup_id: "",
          ...data,
        };
        item.status = "PENDING";
        if (existingIdx >= 0) {
          cachedGuests[existingIdx] = { ...cachedGuests[existingIdx], ...item };
        } else {
          cachedGuests.unshift(item);
        }
        renderGuestsTable();
        updateGuestBadge();
      } catch (e) {
        console.error("Error processing guest_requested event", e);
      }
    });

    adminEventSource.addEventListener("guest_authorized", (event) => {
      try {
        const data = JSON.parse(event.data);
        const normMac = (data.mac || "").toLowerCase().trim();
        const existing = cachedGuests.find((g) => (g.mac || "").toLowerCase().trim() === normMac);
        const now = Math.floor(Date.now() / 1000);
        const durationMins = data.duration_minutes || (existing ? existing.duration_minutes : 1440) || 1440;
        const expiresAt = data.expires_at || (now + durationMins * 60);

        if (existing) {
          existing.status = "ACTIVE";
          existing.approved_by = data.approved_by || existing.approved_by || "admin";
          existing.expires_at = expiresAt;
          existing.duration_minutes = durationMins;
          existing.approved_at = data.approved_at || existing.approved_at || now;
          if (data.name) existing.name = data.name;
          if (data.reason) existing.reason = data.reason;
          if (data.id) existing.id = data.id;
          if (data.usergroup_id) existing.usergroup_id = data.usergroup_id;
          existing.time_remaining_seconds = Math.max(0, expiresAt - now);
        } else {
          cachedGuests.unshift({
            id: data.id,
            mac: data.mac,
            name: data.name || "",
            reason: data.reason || "",
            status: "ACTIVE",
            approved_by: data.approved_by || "admin",
            approved_at: data.approved_at || now,
            expires_at: expiresAt,
            duration_minutes: durationMins,
            time_remaining_seconds: Math.max(0, expiresAt - now),
            online: false,
            ip: "",
            hostname: "",
            usergroup_id: data.usergroup_id || "",
          });
        }
        renderGuestsTable();
        updateGuestBadge();
      } catch (e) {
        console.error("Error processing guest_authorized event", e);
      }
    });

    adminEventSource.addEventListener("guest_denied", (event) => {
      try {
        const data = JSON.parse(event.data);
        const normMac = (data.mac || "").toLowerCase().trim();
        const existing = cachedGuests.find((g) => (g.mac || "").toLowerCase().trim() === normMac);
        if (existing) {
          existing.status = "DENIED";
          existing.revoked_by = data.denied_by || "admin";
          existing.revoked_at = Math.floor(Date.now() / 1000);
        }
        renderGuestsTable();
        updateGuestBadge();
      } catch (e) {
        console.error("Error processing guest_denied event", e);
      }
    });

    adminEventSource.addEventListener("guest_revoked", (event) => {
      try {
        const data = JSON.parse(event.data);
        const normMac = (data.mac || "").toLowerCase().trim();
        const existing = cachedGuests.find((g) => (g.mac || "").toLowerCase().trim() === normMac);
        if (existing) {
          existing.status = "REVOKED";
          existing.revoked_by = data.revoked_by || "admin";
          existing.revoked_at = Math.floor(Date.now() / 1000);
        }
        renderGuestsTable();
        updateGuestBadge();
      } catch (e) {
        console.error("Error processing guest_revoked event", e);
      }
    });

    adminEventSource.addEventListener("guest_profile_updated", (event) => {
      try {
        const data = JSON.parse(event.data);
        const mac = (data.mac || "").toLowerCase().trim();
        const usergroupId = data.usergroup_id;

        const g = cachedGuests.find((x) => (x.mac || "").toLowerCase().trim() === mac);
        if (g) {
          g.usergroup_id = usergroupId;
        }

        const selects = document.querySelectorAll(".guest-active-profile-select");
        let found = false;
        selects.forEach((sel) => {
          if ((sel.dataset.mac || "").toLowerCase().trim() === mac) {
            sel.value = usergroupId;
            sel.dataset.prevValue = usergroupId;
            found = true;
          }
        });
        if (!found) {
          renderGuestsTable();
        }
      } catch (e) {
        console.error("Error processing guest_profile_updated event", e);
      }
    });

    adminEventSource.addEventListener("guest_extended", (event) => {
      try {
        const data = JSON.parse(event.data);
        const normMac = (data.mac || "").toLowerCase().trim();
        const g = cachedGuests.find((x) => (x.mac || "").toLowerCase().trim() === normMac);
        if (g) {
          g.expires_at = data.expires_at;
          if (data.duration_minutes !== undefined) {
            g.duration_minutes = data.duration_minutes;
          }
          const now = Math.floor(Date.now() / 1000);
          g.time_remaining_seconds = Math.max(0, data.expires_at - now);
        }
        renderGuestsTable();
      } catch (e) {
        console.error("Error processing guest_extended event", e);
      }
    });

    adminEventSource.onerror = () => {
      if (liveText) liveText.textContent = "Connecting...";
      if (pulseDot) pulseDot.style.backgroundColor = "var(--warning)";
      refreshAll(false);
    };
  }

  const initSSE = connectSSE;
  window.initSSE = initSSE;

  // --- Initial Setup ---
  async function init() {
    updateSortHeaders();
    await fetchProfile();
    await loadAdminSshConfig();
    fetchSpeedProfiles();
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
      const promises = [
        refreshStats(),
        refreshRequests(),
      ];
      if (forceInventory || document.activeElement !== inventorySearch) {
        promises.push(refreshInventory());
      }
      if (tabGuestsView && !tabGuestsView.classList.contains("hidden")) {
        promises.push(refreshGuests());
      }
      await Promise.all(promises);
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
        ? `<a href="/api/admin/certificates/${encodeURIComponent(c.serial_number)}/download" class="btn-sm btn-download" title="Download standard AES-256 .p12 certificate bundle (available for 24h)">⬇️ .p12</a>
           <a href="/api/admin/certificates/${encodeURIComponent(c.serial_number)}/download?legacy=true" class="btn-sm btn-download" style="background: rgba(147, 51, 234, 0.15); color: #c084fc; border: 1px solid rgba(147, 51, 234, 0.3);" title="Download legacy 3DES .p12 certificate bundle (for older Android / Samsung Galaxy S10)">📱 Legacy</a>`
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

  if (editApproveCancelBtn) {
    editApproveCancelBtn.addEventListener("click", () => {
      editApproveModal.classList.add("hidden");
      activeModalRequestId = null;
    });
  }

  modalConfirmApproveBtn.addEventListener("click", async () => {
    if (!activeModalRequestId) return;
    const newName = editDeviceNameInput.value.trim();
    const vlanId = parseInt(editVlanSelect.value, 10);
    setButtonLoading(modalConfirmApproveBtn, "Issuing...");
    if (editApproveCancelBtn) editApproveCancelBtn.disabled = true;

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
      if (editApproveCancelBtn) editApproveCancelBtn.disabled = false;
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

  if (tabBtnGuests) {
    tabBtnGuests.addEventListener("click", () => {
      switchToTab("guests");
    });
  }

  async function fetchSpeedProfiles() {
    try {
      const resp = await adminFetch("/api/admin/guests/speed-profiles");
      if (!resp.ok) return [];
      const profiles = await resp.json();
      cachedSpeedProfiles = Array.isArray(profiles) ? profiles : [];
      return cachedSpeedProfiles;
    } catch (e) {
      console.error("Speed profiles fetch failed", e);
      return [];
    }
  }

  function formatProfileRates(group, isDefault = false) {
    if (!group) return "";
    const down = group.down_kbps;
    const up = group.up_kbps;
    const hasDown = down != null && down > 0;
    const hasUp = up != null && up > 0;

    const fmt = (kbps) => {
      if (!kbps || kbps <= 0) return "Unlimited";
      if (kbps >= 1000) {
        const mbps = kbps / 1000;
        return (Number.isInteger(mbps) ? mbps.toFixed(1) : mbps.toFixed(1)) + " Mbps";
      }
      return `${kbps} Kbps`;
    };

    if (!hasDown && !hasUp) {
      return isDefault ? "(Default - Unlimited)" : "(Unlimited)";
    }

    const rates = `${fmt(down)} / ${fmt(up)}`;
    return isDefault ? `(Default - ${rates})` : `(${rates})`;
  }

  function getDefaultProfileId() {
    if (!cachedSpeedProfiles || cachedSpeedProfiles.length === 0) return "";
    let found = cachedSpeedProfiles.find((g) => (g.name || "").toLowerCase() === "guest speed");
    if (!found) {
      found = cachedSpeedProfiles.find((g) => (g.name || "").toLowerCase() === "guest")
        || cachedSpeedProfiles.find((g) => (g.name || "").toLowerCase().includes("guest"));
    }
    if (!found) {
      found = cachedSpeedProfiles.find((g) => (g.name || "").toLowerCase() === "default")
        || cachedSpeedProfiles.find((g) => (g.name || "").toLowerCase().includes("default"));
    }
    if (!found) {
      found = cachedSpeedProfiles[0];
    }
    return found ? found.id : "";
  }

  function updateGuestBadge() {
    const pendingCount = cachedGuests.filter((g) => g.status === "PENDING").length;
    if (guestsCounter) {
      guestsCounter.textContent = pendingCount;
      if (pendingCount === 0) {
        guestsCounter.classList.add("hidden");
      } else {
        guestsCounter.classList.remove("hidden");
      }
    }
    const pendingCounter = document.getElementById("pending-guests-counter");
    if (pendingCounter) {
      pendingCounter.textContent = pendingCount;
    }
  }

  async function refreshGuests() {
    try {
      if (!cachedSpeedProfiles || cachedSpeedProfiles.length === 0) {
        await fetchSpeedProfiles();
      }
      const resp = await adminFetch("/api/admin/guests");
      if (!resp.ok) return [];
      const guests = await resp.json();
      cachedGuests = guests;
      updateGuestBadge();

      renderGuestsTable();
      startGuestCountdownTimer();
      return guests;
    } catch (e) {
      console.error("Guests refresh failed", e);
      return [];
    }
  }

  function formatCountdown(seconds) {
    if (seconds <= 0) return `<span style="color: var(--danger); font-weight: 600;">Expired</span>`;
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;

    let parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0 || days > 0) parts.push(`${hours}h`);
    parts.push(`${minutes}m`);
    parts.push(`${secs}s`);
    return parts.join(" ");
  }

  function renderGuestsTable() {
    if (!guestsTbody) return;

    // 1. Separate pending vs processed guests
    const pendingGuests = cachedGuests.filter((g) => g.status === "PENDING");
    const processedGuests = cachedGuests.filter((g) => g.status !== "PENDING");

    // Render Pending Table
    const pendingCard = document.getElementById("pending-guests-card");
    const pendingTbody = document.getElementById("pending-guests-tbody");
    const pendingCounter = document.getElementById("pending-guests-counter");

    if (pendingCard && pendingTbody) {
      if (pendingGuests.length > 0) {
        pendingCard.classList.remove("hidden");
        if (pendingCounter) pendingCounter.textContent = pendingGuests.length;
        pendingTbody.innerHTML = "";

        const defaultProfileId = getDefaultProfileId();

        pendingGuests.forEach((p) => {
          const ptr = document.createElement("tr");

          const profileSelectHtml = cachedSpeedProfiles.length > 0
            ? `<select class="filter-select guest-pending-profile-select" data-mac="${escapeHtml(p.mac)}" style="padding: 4px 8px; font-size: 0.8rem;">
                ${cachedSpeedProfiles.map((grp) => {
                  const isSel = (p.usergroup_id ? grp.id === p.usergroup_id : grp.id === defaultProfileId) ? "selected" : "";
                  const isDefault = grp.id === defaultProfileId;
                  return `<option value="${escapeHtml(grp.id)}"${isSel ? " selected" : ""}>${escapeHtml(grp.name)} ${formatProfileRates(grp, isDefault)}</option>`;
                }).join("")}
              </select>`
            : `<span style="color:var(--text-muted); font-size:0.8rem;">-</span>`;

          ptr.innerHTML = `
            <td>
              <div style="font-weight:600; color:var(--text-main);">${escapeHtml(p.name)}</div>
              <div style="font-size:0.8rem; color:var(--text-muted);">${escapeHtml(p.reason)}</div>
            </td>
            <td><code>${escapeHtml(p.mac)}</code></td>
            <td>${formatTimeAgo(p.requested_at || p.approved_at)}</td>
            <td>
              <select class="filter-select guest-duration-select" data-mac="${escapeHtml(p.mac)}" style="padding: 4px 8px; font-size: 0.8rem;">
                <option value="1440" ${p.duration_minutes === 1440 ? "selected" : ""}>1 Day (24h)</option>
                <option value="2880" ${p.duration_minutes === 2880 ? "selected" : ""}>2 Days</option>
                <option value="4320" ${p.duration_minutes === 4320 ? "selected" : ""}>3 Days</option>
                <option value="5760" ${p.duration_minutes === 5760 ? "selected" : ""}>4 Days</option>
                <option value="7200" ${p.duration_minutes === 7200 ? "selected" : ""}>5 Days</option>
                <option value="8640" ${p.duration_minutes === 8640 ? "selected" : ""}>6 Days</option>
                <option value="10080" ${p.duration_minutes === 10080 ? "selected" : ""}>7 Days</option>
              </select>
            </td>
            <td>
              ${profileSelectHtml}
            </td>
            <td>
              <div style="display:flex; gap:0.4rem;">
                <button class="btn-sm btn-approve" data-action="approve-pending-guest" data-mac="${escapeHtml(p.mac)}">✅ Approve</button>
                <button class="btn-sm btn-reject" data-action="deny-pending-guest" data-mac="${escapeHtml(p.mac)}">❌ Deny</button>
              </div>
            </td>
          `;
          pendingTbody.appendChild(ptr);
        });
      } else {
        pendingCard.classList.add("hidden");
      }
    }

    // 2. Render Processed Guests
    guestsTbody.innerHTML = "";

    const query = (guestsSearch ? guestsSearch.value.trim().toLowerCase() : "");
    const statusFilter = (filterGuestStatus ? filterGuestStatus.value : "");

    const filtered = processedGuests.filter((g) => {
      if (statusFilter && g.status !== statusFilter) return false;
      if (query) {
        const text = `${g.name || ""} ${g.reason || ""} ${g.mac || ""} ${g.ip || ""} ${g.hostname || ""}`.toLowerCase();
        if (!text.includes(query)) return false;
      }
      return true;
    });

    if (filtered.length === 0) {
      if (guestsEmpty) guestsEmpty.classList.remove("hidden");
      return;
    }
    if (guestsEmpty) guestsEmpty.classList.add("hidden");

    filtered.forEach((g) => {
      const tr = document.createElement("tr");

      // Online status indicator
      let onlineDot = `<span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#9ca3af; margin-right:6px;" title="Offline"></span>`;
      let statusBadge = `<span class="badge" style="background: rgba(107, 114, 128, 0.15); color: #6b7280;">${escapeHtml(g.status)}</span>`;

      if (g.status === "ACTIVE") {
        if (g.online) {
          onlineDot = `<span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#10b981; margin-right:6px;" title="Connected &amp; Active"></span>`;
          statusBadge = `<span class="badge badge-active">${onlineDot}Online</span>`;
        } else {
          onlineDot = `<span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#eab308; margin-right:6px;" title="Authorized (Idle)"></span>`;
          statusBadge = `<span class="badge" style="background: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.3);">${onlineDot}Idle</span>`;
        }
      } else if (g.status === "REVOKED") {
        statusBadge = `<span class="badge badge-revoked">Revoked</span>`;
      } else if (g.status === "EXPIRED") {
        statusBadge = `<span class="badge badge-expired">Expired</span>`;
      } else if (g.status === "DENIED") {
        statusBadge = `<span class="badge badge-revoked" style="background: rgba(239, 68, 68, 0.15); color: #ef4444;">Denied</span>`;
      }

      const ipInfo = g.ip ? `<code>${escapeHtml(g.ip)}</code>` : `<span style="color:var(--text-muted);">-</span>`;
      const hostInfo = g.hostname ? `<div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(g.hostname)}</div>` : "";

      let speedProfileHtml = "";
      if (g.status === "ACTIVE") {
        if (cachedSpeedProfiles.length > 0) {
          const defaultProfileId = getDefaultProfileId();
          const currentGroupId = g.usergroup_id || defaultProfileId;
          const known = cachedSpeedProfiles.some((grp) => grp.id === currentGroupId);
          let extraOption = "";
          if (currentGroupId && !known) {
            extraOption = `<option value="${escapeHtml(currentGroupId)}" selected>${escapeHtml(currentGroupId)}</option>`;
          }
          const optionsHtml = extraOption + cachedSpeedProfiles.map((grp) => {
            const isSelected = (!extraOption && grp.id === currentGroupId) ? "selected" : "";
            const isDefault = grp.id === defaultProfileId;
            return `<option value="${escapeHtml(grp.id)}"${isSelected ? " selected" : ""}>${escapeHtml(grp.name)} ${formatProfileRates(grp, isDefault)}</option>`;
          }).join("");

          speedProfileHtml = `
            <div style="display:inline-flex; align-items:center; gap:6px;">
              <select class="filter-select guest-active-profile-select" data-mac="${escapeHtml(g.mac)}" data-prev-value="${escapeHtml(currentGroupId)}" style="padding: 4px 8px; font-size: 0.8rem;">
                ${optionsHtml}
              </select>
              <span class="profile-feedback" style="display:none; font-size:0.85rem; color:var(--success);" title="Saved">✓</span>
            </div>
          `;
        } else {
          speedProfileHtml = `<span style="color:var(--text-muted); font-size:0.8rem;">-</span>`;
        }
      } else {
        // EXPIRED, REVOKED, or DENIED
        let profileName = "-";
        if (g.usergroup_id) {
          const matched = cachedSpeedProfiles.find((grp) => grp.id === g.usergroup_id);
          profileName = matched ? matched.name : g.usergroup_id;
        }
        speedProfileHtml = `<span style="color:var(--text-muted); font-size:0.85rem;">${escapeHtml(profileName)}</span>`;
      }

      const countdownHtml = (g.status === "REVOKED" || g.status === "DENIED")
        ? `<span style="color:var(--text-muted);">${g.status === "DENIED" ? "Denied" : "Revoked"}</span>`
        : `<span class="guest-countdown" data-expires="${g.expires_at}">${formatCountdown(g.time_remaining_seconds)}</span>`;

      let actionBtn = "";
      if (g.status === "ACTIVE") {
        actionBtn = `
          <div class="action-buttons">
            <button class="btn btn-sm btn-secondary btn-modify-expiry" data-mac="${escapeHtml(g.mac)}">Modify Expiry</button>
            <button class="btn-sm btn-reject" data-action="kick-guest" data-mac="${escapeHtml(g.mac)}" data-name="${escapeHtml(g.name)}">🚫 Kick &amp; Revoke</button>
          </div>
        `;
      } else {
        actionBtn = `<span style="color:var(--text-muted); font-size:0.8rem;">${g.status === "DENIED" ? "Denied" : "Completed"}</span>`;
      }

      tr.innerHTML = `
        <td>
          <div style="font-weight:600; color:var(--text-main);">${escapeHtml(g.name)}</div>
          <div style="font-size:0.8rem; color:var(--text-muted);">${escapeHtml(g.reason)}</div>
        </td>
        <td><code>${escapeHtml(g.mac)}</code></td>
        <td>${ipInfo}${hostInfo}</td>
        <td>${statusBadge}</td>
        <td>${speedProfileHtml}</td>
        <td>
          <div style="font-size:0.85rem;">@${escapeHtml(g.approved_by || "admin")}</div>
          <div style="font-size:0.75rem; color:var(--text-muted);">${formatDateTime(g.approved_at)}</div>
        </td>
        <td>${countdownHtml}</td>
        <td>${actionBtn}</td>
      `;
      guestsTbody.appendChild(tr);
    });

    updateGuestBadge();
  }

  function startGuestCountdownTimer() {
    if (guestCountdownInterval) clearInterval(guestCountdownInterval);
    guestCountdownInterval = setInterval(() => {
      const now = Math.floor(Date.now() / 1000);
      document.querySelectorAll(".guest-countdown").forEach((el) => {
        const exp = parseInt(el.dataset.expires, 10);
        if (!isNaN(exp)) {
          const rem = Math.max(0, exp - now);
          el.innerHTML = formatCountdown(rem);
        }
      });
    }, 1000);
  }

  if (guestsSearch) {
    guestsSearch.addEventListener("input", renderGuestsTable);
  }
  if (filterGuestStatus) {
    filterGuestStatus.addEventListener("change", renderGuestsTable);
  }

  // Pending Guests Actions (Approve / Deny)
  const pendingGuestsTbody = document.getElementById("pending-guests-tbody");
  if (pendingGuestsTbody) {
    pendingGuestsTbody.addEventListener("click", async (e) => {
      const approveBtn = e.target.closest("button[data-action='approve-pending-guest']");
      const denyBtn = e.target.closest("button[data-action='deny-pending-guest']");
      if (!approveBtn && !denyBtn) return;

      const btn = approveBtn || denyBtn;
      const mac = btn.dataset.mac;
      if (!mac) return;

      if (inFlightGuestActions.has(mac)) return;

      if (denyBtn && !confirm(`Deny access for ${mac}?`)) return;

      inFlightGuestActions.add(mac);
      btn.disabled = true;
      btn.style.pointerEvents = "none";
      const row = btn.closest("tr");
      if (row) {
        row.querySelectorAll("button, select").forEach((el) => {
          el.disabled = true;
          el.style.pointerEvents = "none";
        });
      }

      try {
        if (approveBtn) {
          const select = pendingGuestsTbody.querySelector(`.guest-duration-select[data-mac='${mac}']`);
          const profSelect = pendingGuestsTbody.querySelector(`.guest-pending-profile-select[data-mac='${mac}']`);
          const durationMins = select ? parseInt(select.value, 10) : 1440;
          const usergroupId = profSelect ? profSelect.value : undefined;

          setButtonLoading(approveBtn, "Approving...");
          try {
            const resp = await adminFetch(`/api/admin/guests/${mac}/approve`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                duration_minutes: durationMins,
                usergroup_id: usergroupId || undefined,
              }),
            });
            if (!resp.ok) throw new Error("Approval failed");
            await refreshGuests();
          } catch (err) {
            alert("Failed to approve guest: " + err.message);
          } finally {
            restoreButton(approveBtn);
          }
        } else if (denyBtn) {
          setButtonLoading(denyBtn, "Denying...");
          try {
            const resp = await adminFetch(`/api/admin/guests/${mac}/deny`, {
              method: "POST",
            });
            if (!resp.ok) throw new Error("Denial failed");
            await refreshGuests();
          } catch (err) {
            alert("Failed to deny guest: " + err.message);
          } finally {
            restoreButton(denyBtn);
          }
        }
      } finally {
        inFlightGuestActions.delete(mac);
        if (row) {
          row.querySelectorAll("button, select").forEach((el) => {
            el.disabled = false;
            el.style.pointerEvents = "";
          });
        }
      }
    });
  }

  // Guests Actions (Revoke / Kick / Speed Profile Change)
  if (guestsTbody) {
    guestsTbody.addEventListener("change", async (e) => {
      const select = e.target.closest(".guest-active-profile-select");
      if (!select) return;

      const mac = select.dataset.mac;
      const newGroupId = select.value;
      const prevGroupId = select.dataset.prevValue || "";

      select.disabled = true;

      try {
        const resp = await adminFetch(`/api/admin/guests/${mac}/speed-profile`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ usergroup_id: newGroupId }),
        });
        if (!resp.ok) {
          const errData = await resp.json().catch(() => ({}));
          throw new Error(errData.detail || "Update failed");
        }
        select.dataset.prevValue = newGroupId;
        const g = cachedGuests.find((x) => (x.mac || "").toLowerCase() === (mac || "").toLowerCase());
        if (g) {
          g.usergroup_id = newGroupId;
        }

        const container = select.parentElement;
        const feedback = container ? container.querySelector(".profile-feedback") : null;
        if (feedback) {
          feedback.style.display = "inline";
          setTimeout(() => {
            feedback.style.display = "none";
          }, 2000);
        }
      } catch (err) {
        alert("Failed to update speed profile: " + err.message);
        select.value = prevGroupId;
      } finally {
        select.disabled = false;
      }
    });

    guestsTbody.addEventListener("click", async (e) => {
      const modifyBtn = e.target.closest(".btn-modify-expiry");
      if (modifyBtn) {
        const mac = modifyBtn.dataset.mac;
        openModifyExpiryModal(mac);
        return;
      }

      const btn = e.target.closest("button[data-action='kick-guest']");
      if (!btn) return;
      const mac = btn.dataset.mac;
      const name = btn.dataset.name;
      activeRevokeGuestMac = mac;

      if (modalGuestName) modalGuestName.textContent = name;
      if (modalGuestMac) modalGuestMac.textContent = mac;
      if (revokeGuestModal) revokeGuestModal.classList.remove("hidden");
    });
  }

  // --- API Tokens Modal & Management ---
  const btnSyncGuests = document.getElementById("btn-sync-guests");
  const btnOpenTokens = document.getElementById("btn-open-tokens");
  const tokensModal = document.getElementById("tokens-modal");
  const tokensCloseBtn = document.getElementById("tokens-close-btn");
  const createTokenForm = document.getElementById("create-token-form");
  const newTokenNameInput = document.getElementById("new-token-name");
  const newTokenBox = document.getElementById("new-token-box");
  const newTokenValueInput = document.getElementById("new-token-value");
  const copyTokenBtn = document.getElementById("copy-token-btn");
  const tokensTbody = document.getElementById("tokens-tbody");
  const tokensEmpty = document.getElementById("tokens-empty");

  async function refreshTokens() {
    if (!tokensTbody) return;
    try {
      const resp = await adminFetch("/api/admin/tokens");
      if (!resp.ok) return;
      const tokens = await resp.json();
      tokensTbody.innerHTML = "";
      if (tokens.length === 0) {
        if (tokensEmpty) tokensEmpty.classList.remove("hidden");
        return;
      }
      if (tokensEmpty) tokensEmpty.classList.add("hidden");

      tokens.forEach((t) => {
        const tr = document.createElement("tr");
        tr.style.borderBottom = "1px solid var(--border)";
        const lastUsed = t.last_used_at ? formatTimeAgo(t.last_used_at) : "Never";
        const isRevoked = Boolean(t.revoked_at);
        const actionHtml = isRevoked
          ? `<span style="color:var(--danger); font-size:0.75rem;">Revoked</span>`
          : `<button class="btn-sm btn-reject" style="padding: 2px 6px; font-size: 0.75rem;" data-token-id="${t.id}">Revoke</button>`;

        tr.innerHTML = `
          <td style="padding: 0.5rem; font-weight: 600;">${escapeHtml(t.name)}</td>
          <td style="padding: 0.5rem;"><code>${escapeHtml(t.token_prefix)}</code></td>
          <td style="padding: 0.5rem; color: var(--text-muted);">${formatTimeAgo(t.created_at)}</td>
          <td style="padding: 0.5rem; color: var(--text-muted);">${lastUsed}</td>
          <td style="padding: 0.5rem; text-align: right;">${actionHtml}</td>
        `;
        tokensTbody.appendChild(tr);
      });
    } catch (e) {
      console.error("Failed to refresh tokens", e);
    }
  }

  if (btnOpenTokens) {
    btnOpenTokens.addEventListener("click", () => {
      if (newTokenBox) newTokenBox.classList.add("hidden");
      if (tokensModal) tokensModal.classList.remove("hidden");
      refreshTokens();
    });
  }

  if (btnSyncGuests) {
    btnSyncGuests.addEventListener("click", async () => {
      setButtonLoading(btnSyncGuests, "Syncing...");
      try {
        const resp = await adminFetch("/api/admin/guests/sync", { method: "POST" });
        if (!resp.ok) throw new Error("Sync failed");
        const data = await resp.json();
        await fetchSpeedProfiles();
        await refreshGuests();
      } catch (err) {
        alert("Failed to sync UniFi guests: " + err.message);
      } finally {
        restoreButton(btnSyncGuests);
      }
    });
  }

  if (tokensCloseBtn) {
    tokensCloseBtn.addEventListener("click", () => {
      if (tokensModal) tokensModal.classList.add("hidden");
    });
  }

  if (createTokenForm) {
    createTokenForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = newTokenNameInput.value.trim();
      if (!name) return;
      try {
        const resp = await adminFetch("/api/admin/tokens", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name }),
        });
        if (!resp.ok) throw new Error("Failed to create token");
        const data = await resp.json();
        newTokenNameInput.value = "";
        if (newTokenValueInput) newTokenValueInput.value = data.token;
        if (newTokenBox) newTokenBox.classList.remove("hidden");
        refreshTokens();
      } catch (err) {
        alert(err.message);
      }
    });
  }

  if (copyTokenBtn && newTokenValueInput) {
    copyTokenBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(newTokenValueInput.value);
      copyTokenBtn.textContent = "✅ Copied!";
      setTimeout(() => { copyTokenBtn.textContent = "📋 Copy"; }, 2000);
    });
  }

  if (tokensTbody) {
    tokensTbody.addEventListener("click", async (e) => {
      const btn = e.target.closest("button[data-token-id]");
      if (!btn) return;
      const tokenId = btn.dataset.tokenId;
      if (!confirm("Are you sure you want to revoke this API token? Any service using it will immediately be rejected.")) return;
      try {
        const resp = await adminFetch(`/api/admin/tokens/${tokenId}`, { method: "DELETE" });
        if (!resp.ok) throw new Error("Revocation failed");
        refreshTokens();
      } catch (err) {
        alert(err.message);
      }
    });
  }

  if (modalGuestCancelBtn) {
    modalGuestCancelBtn.addEventListener("click", () => {
      if (revokeGuestModal) revokeGuestModal.classList.add("hidden");
      activeRevokeGuestMac = null;
    });
  }

  if (modalGuestConfirmBtn) {
    modalGuestConfirmBtn.addEventListener("click", async () => {
      if (!activeRevokeGuestMac) return;
      setButtonLoading(modalGuestConfirmBtn, "Revoking...");
      try {
        const resp = await adminFetch(`/api/admin/guests/${activeRevokeGuestMac}/revoke`, {
          method: "POST",
        });
        if (!resp.ok) throw new Error("Revocation failed");
        if (revokeGuestModal) revokeGuestModal.classList.add("hidden");
        activeRevokeGuestMac = null;
        await refreshGuests();
      } catch (err) {
        alert("Failed to kick/revoke guest: " + err.message);
      } finally {
        restoreButton(modalGuestConfirmBtn);
      }
    });
  }

  // --- Modify Guest Expiry Modal Functions & Listeners ---
  function formatDateTimeLocalInput(epochSec) {
    if (!epochSec) return "";
    const d = new Date(epochSec * 1000);
    const pad = (n) => String(n).padStart(2, "0");
    const year = d.getFullYear();
    const month = pad(d.getMonth() + 1);
    const day = pad(d.getDate());
    const hours = pad(d.getHours());
    const minutes = pad(d.getMinutes());
    return `${year}-${month}-${day}T${hours}:${minutes}`;
  }

  function parseDateTimeLocalInput(val) {
    if (!val) return null;
    const d = new Date(val);
    const ms = d.getTime();
    if (isNaN(ms)) return null;
    return Math.floor(ms / 1000);
  }

  function formatRelativeDiff(seconds) {
    const sign = seconds > 0 ? "+" : "-";
    const abs = Math.abs(seconds);
    const days = Math.floor(abs / 86400);
    const hours = Math.floor((abs % 86400) / 3600);
    const minutes = Math.floor((abs % 3600) / 60);
    const parts = [];
    if (days > 0) parts.push(`${days} day${days !== 1 ? "s" : ""}`);
    if (hours > 0) parts.push(`${hours} hour${hours !== 1 ? "s" : ""}`);
    if (minutes > 0 || parts.length === 0) parts.push(`${minutes} min${minutes !== 1 ? "s" : ""}`);
    return `${sign}${parts.join(", ")}`;
  }

  function updateModifyExpiryPreview() {
    if (!modalPreviewSummary || !modalDatetimeInput) return;
    const targetTimestamp = parseDateTimeLocalInput(modalDatetimeInput.value);
    if (!targetTimestamp) {
      modalPreviewSummary.innerHTML = `<span class="diff-invalid">Please select a valid date and time</span>`;
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    if (targetTimestamp <= now + 60) {
      modalPreviewSummary.innerHTML = `<span class="diff-invalid">⚠️ Expiration must be at least 1 minute in the future</span>`;
      return;
    }

    const formattedTarget = formatDateTime(targetTimestamp);
    const diffSec = targetTimestamp - (activeModifyInitialExpiry || now);
    let diffHtml = "";
    if (diffSec === 0) {
      diffHtml = `<span>(no change)</span>`;
    } else if (diffSec > 0) {
      diffHtml = `<span class="diff-add">(${formatRelativeDiff(diffSec)})</span>`;
    } else {
      diffHtml = `<span class="diff-sub">(${formatRelativeDiff(diffSec)})</span>`;
    }
    modalPreviewSummary.innerHTML = `<span>New Expiry: <strong>${escapeHtml(formattedTarget)}</strong> ${diffHtml}</span>`;
  }

  function openModifyExpiryModal(mac) {
    const normMac = (mac || "").toLowerCase().trim();
    const g = cachedGuests.find((x) => (x.mac || "").toLowerCase().trim() === normMac);
    if (!g) return;

    activeModifyGuestMac = normMac;
    activeModifyInitialExpiry = g.expires_at || (Math.floor(Date.now() / 1000) + 86400);

    if (modalGuestTitle) modalGuestTitle.textContent = "Modify Guest Expiry";
    if (modalGuestInfo) modalGuestInfo.textContent = `${g.name || "Guest"} (${g.mac})`;
    if (modalCurrentExpiry) modalCurrentExpiry.textContent = formatDateTime(g.expires_at);

    if (modalDatetimeInput) {
      modalDatetimeInput.value = formatDateTimeLocalInput(activeModifyInitialExpiry);
    }
    updateModifyExpiryPreview();

    if (modifyExpiryModal) modifyExpiryModal.classList.remove("hidden");
  }

  function closeModifyExpiryModal() {
    if (modifyExpiryModal) modifyExpiryModal.classList.add("hidden");
    activeModifyGuestMac = null;
    activeModifyInitialExpiry = null;
  }

  if (modifyExpiryModal) {
    const chips = modifyExpiryModal.querySelectorAll(".btn-chip");
    chips.forEach((chip) => {
      chip.addEventListener("click", () => {
        const delta = parseInt(chip.dataset.delta, 10);
        if (isNaN(delta)) return;

        let currentTarget = parseDateTimeLocalInput(modalDatetimeInput ? modalDatetimeInput.value : "");
        if (!currentTarget) {
          currentTarget = activeModifyInitialExpiry || Math.floor(Date.now() / 1000);
        }

        let newTarget = currentTarget + delta;
        const now = Math.floor(Date.now() / 1000);
        const minAllowed = now + 61;
        if (newTarget < minAllowed) {
          newTarget = minAllowed;
        }

        if (modalDatetimeInput) {
          modalDatetimeInput.value = formatDateTimeLocalInput(newTarget);
        }
        updateModifyExpiryPreview();
      });
    });
  }

  if (modalDatetimeInput) {
    modalDatetimeInput.addEventListener("input", updateModifyExpiryPreview);
    modalDatetimeInput.addEventListener("change", updateModifyExpiryPreview);
  }

  if (modalApplyBtn) {
    modalApplyBtn.addEventListener("click", async () => {
      if (!activeModifyGuestMac) return;

      const timestamp = parseDateTimeLocalInput(modalDatetimeInput ? modalDatetimeInput.value : "");
      const now = Math.floor(Date.now() / 1000);
      if (!timestamp || timestamp <= now + 60) {
        alert("New expiration must be at least 1 minute in the future");
        return;
      }

      setButtonLoading(modalApplyBtn, "Saving...");
      try {
        const resp = await adminFetch(`/api/admin/guests/${activeModifyGuestMac}/modify-expiry`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ new_expires_at: timestamp }),
        });
        if (!resp.ok) {
          const errData = await resp.json().catch(() => ({}));
          throw new Error(errData.detail || "Failed to update expiry");
        }
        closeModifyExpiryModal();
        await refreshGuests();
      } catch (err) {
        alert("Failed to modify expiry: " + err.message);
      } finally {
        restoreButton(modalApplyBtn);
      }
    });
  }

  if (modalCloseBtn) {
    modalCloseBtn.addEventListener("click", closeModifyExpiryModal);
  }
  if (modalCancelBtn) {
    modalCancelBtn.addEventListener("click", closeModifyExpiryModal);
  }
  if (modifyExpiryModal) {
    modifyExpiryModal.addEventListener("click", (e) => {
      if (e.target === modifyExpiryModal) {
        closeModifyExpiryModal();
      }
    });
  }
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modifyExpiryModal && !modifyExpiryModal.classList.contains("hidden")) {
      closeModifyExpiryModal();
    }
  });

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
