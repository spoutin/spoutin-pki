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
  const modalCancelBtn = document.getElementById("modal-cancel-btn");
  const modalConfirmApproveBtn = document.getElementById("modal-confirm-approve-btn");
  let activeModalRequestId = null;

  const revokeModal = document.getElementById("revoke-modal");
  const revokeDeviceName = document.getElementById("revoke-device-name");
  const revokeSerial = document.getElementById("revoke-serial");
  const revokeReasonSelect = document.getElementById("revoke-reason-select");
  const revokeCancelBtn = document.getElementById("revoke-cancel-btn");
  const revokeConfirmBtn = document.getElementById("revoke-confirm-btn");
  let activeRevokeSerial = null;

  // --- Initial Setup ---
  async function init() {
    await fetchProfile();
    await refreshStats();
    await refreshRequests();
    await refreshInventory();

    // Auto-refresh requests every 5s
    setInterval(async () => {
      await refreshRequests();
      await refreshStats();
    }, 5000);
  }

  // --- API Calls ---
  async function fetchProfile() {
    try {
      const resp = await fetch("/api/admin/me");
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
      const resp = await fetch("/api/admin/stats");
      if (!resp.ok) return;
      const stats = await resp.json();
      statActiveEl.textContent = stats.active ?? 0;
      statRevokedEl.textContent = stats.revoked ?? 0;

      vlanPillsEl.innerHTML = "";
      const vlanLabels = { 8: "SemiPrivate", 1: "LAN", 2: "DMS", 9: "IoT" };
      const byVlan = stats.by_vlan || {};
      for (const [vId, count] of Object.entries(byVlan)) {
        const span = document.createElement("span");
        span.className = "vlan-pill";
        span.textContent = `VLAN ${vId} (${vlanLabels[vId] || "Other"}): ${count}`;
        vlanPillsEl.appendChild(span);
      }
    } catch (e) {
      console.error("Stats refresh failed", e);
    }
  }

  async function refreshRequests() {
    try {
      const resp = await fetch("/api/admin/requests");
      if (!resp.ok) return;
      const requests = await resp.json();
      statPendingEl.textContent = requests.length;
      pendingCounter.textContent = requests.length;

      requestsTbody.innerHTML = "";
      if (requests.length === 0) {
        requestsEmpty.classList.remove("hidden");
        return;
      }
      requestsEmpty.classList.add("hidden");

      requests.forEach((r) => {
        const tr = document.createElement("tr");
        const timeAgo = formatTimeAgo(r.created_at);

        tr.innerHTML = `
          <td><strong>${escapeHtml(r.device_name)}</strong></td>
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
    } catch (e) {
      console.error("Requests load failed", e);
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
      const resp = await fetch(`/api/admin/certificates?${params.toString()}`);
      if (!resp.ok) return;
      const certs = await resp.json();

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
        const shortSerial = c.serial_number.length > 16
          ? `${c.serial_number.slice(0, 8)}...${c.serial_number.slice(-8)}`
          : c.serial_number;

        const actionHtml = isRevoked
          ? `<span class="hint" style="color: var(--text-muted);">${escapeHtml(c.revocation_reason || "Revoked")}</span>`
          : `<button class="btn-sm btn-revoke" data-action="open-revoke" data-serial="${c.serial_number}" data-name="${escapeHtml(c.device_name)}">🚫 Revoke</button>`;

        tr.innerHTML = `
          <td><strong>${escapeHtml(c.device_name)}</strong></td>
          <td>${escapeHtml(c.platform)}</td>
          <td><span class="badge badge-vlan">${escapeHtml(c.vlan_label || "VLAN " + c.vlan_id)}</span></td>
          <td><code title="${c.serial_number}">${shortSerial}</code></td>
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
        const resp = await fetch(`/api/admin/requests/${reqId}/approve`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ approved_name: name, vlan_id: 8 }),
        });
        if (resp.ok) {
          await refreshRequests();
          await refreshStats();
          await refreshInventory();
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
      editApproveModal.classList.remove("hidden");
    } else if (action === "reject") {
      if (!confirm(`Are you sure you want to reject request for ${name}?`)) return;
      btn.disabled = true;
      try {
        await fetch(`/api/admin/requests/${reqId}/reject`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ reason: "Rejected by admin from web dashboard" }),
        });
        await refreshRequests();
        await refreshStats();
      } finally {
        btn.disabled = false;
      }
    }
  });

  inventoryTbody.addEventListener("click", (e) => {
    const btn = e.target.closest("button");
    if (!btn) return;
    if (btn.dataset.action === "open-revoke") {
      activeRevokeSerial = btn.dataset.serial;
      revokeSerial.textContent = activeRevokeSerial;
      revokeDeviceName.textContent = btn.dataset.name;
      revokeModal.classList.remove("hidden");
    }
  });

  // --- Modal Event Listeners ---
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
      const resp = await fetch(`/api/admin/requests/${activeModalRequestId}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approved_name: newName, vlan_id: vlanId }),
      });
      if (resp.ok) {
        editApproveModal.classList.add("hidden");
        activeModalRequestId = null;
        await refreshRequests();
        await refreshStats();
        await refreshInventory();
      } else {
        const err = await resp.json();
        alert(`Approval failed: ${err.detail || "Server error"}`);
      }
    } finally {
      modalConfirmApproveBtn.disabled = false;
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
      const resp = await fetch(`/api/admin/certificates/${activeRevokeSerial}/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: reason, scope: scope }),
      });
      if (resp.ok) {
        revokeModal.classList.add("hidden");
        activeRevokeSerial = null;
        await refreshInventory();
        await refreshStats();
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

  // --- Tab Switcher ---
  tabBtnRequests.addEventListener("click", () => {
    tabBtnRequests.classList.add("active");
    tabBtnInventory.classList.remove("active");
    tabRequestsView.classList.remove("hidden");
    tabInventoryView.classList.add("hidden");
  });

  tabBtnInventory.addEventListener("click", () => {
    tabBtnInventory.classList.add("active");
    tabBtnRequests.classList.remove("active");
    tabInventoryView.classList.remove("hidden");
    tabRequestsView.classList.add("hidden");
    refreshInventory();
  });

  // --- Logout ---
  logoutBtn.addEventListener("click", async () => {
    await fetch("/admin/auth/logout", { method: "POST" });
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
