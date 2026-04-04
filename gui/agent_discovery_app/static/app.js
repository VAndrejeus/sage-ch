function byId(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  const el = byId(id);
  if (el) {
    el.textContent = value ?? "";
  }
}

function csvToArray(value) {
  return value
    .split(",")
    .map(item => item.trim())
    .filter(item => item.length > 0);
}

function arrayToCsv(arr) {
  if (!Array.isArray(arr)) return "";
  return arr.join(", ");
}

function setBanner(status) {
  const banner = byId("job-banner");
  banner.classList.remove("idle", "running", "completed", "failed");

  const normalized = status || "idle";
  banner.classList.add(normalized);

  const labelMap = {
    idle: "Idle",
    running: "Running",
    completed: "Completed",
    failed: "Failed"
  };

  banner.textContent = labelMap[normalized] || normalized;
}

function setRunButtonsDisabled(disabled) {
  byId("run-agent-btn").disabled = disabled;
  byId("run-discovery-btn").disabled = disabled;
}

function activateTab(tabId) {
  document.querySelectorAll(".tab-button").forEach(button => {
    button.classList.toggle("active", button.dataset.tab === tabId);
  });

  document.querySelectorAll(".panel").forEach(panel => {
    panel.classList.toggle("active", panel.id === tabId);
  });
}

function setupTabs() {
  document.querySelectorAll(".tab-button").forEach(button => {
    button.addEventListener("click", () => {
      activateTab(button.dataset.tab);
    });
  });
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || "Request failed");
  }

  return data;
}

async function loadEnvironment() {
  try {
    const data = await fetchJson("/api/environment");
    setText("detected-os", data.host_os || "unknown");

    const select = byId("agent-type");
    select.innerHTML = "";

    const options = Array.isArray(data.agent_options) ? data.agent_options : [];

    if (options.length === 0) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No supported agent available";
      select.appendChild(option);
      select.disabled = true;
      byId("run-agent-btn").disabled = true;
      return;
    }

    options.forEach(item => {
      const option = document.createElement("option");
      option.value = item.value;
      option.textContent = item.label;
      select.appendChild(option);
    });

    select.disabled = false;
  } catch (error) {
    setText("detected-os", `Error: ${error.message}`);
  }
}

async function loadScope() {
  try {
    const data = await fetchJson("/api/scope");

    byId("authorized-networks").value = arrayToCsv(data.authorized_networks);
    byId("authorized-interfaces").value = arrayToCsv(data.authorized_interfaces);
    byId("max-hosts-per-subnet").value = data.max_hosts_per_subnet ?? 1024;
    byId("private-only").checked = Boolean(data.private_only);

    setText("scope-save-message", "");
  } catch (error) {
    setText("scope-save-message", `Failed to load scope: ${error.message}`);
  }
}

async function saveScope() {
  const messageEl = byId("scope-save-message");
  messageEl.textContent = "Saving...";

  const payload = {
    authorized_networks: csvToArray(byId("authorized-networks").value),
    authorized_interfaces: csvToArray(byId("authorized-interfaces").value),
    max_hosts_per_subnet: parseInt(byId("max-hosts-per-subnet").value, 10),
    private_only: byId("private-only").checked
  };

  try {
    const data = await fetchJson("/api/scope", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (data.success) {
      messageEl.textContent = "Scope saved.";
    } else {
      messageEl.textContent = data.error || "Save failed.";
    }
  } catch (error) {
    messageEl.textContent = `Save failed: ${error.message}`;
  }
}

function renderJobStatus(data) {
  const status = data.status || "idle";
  setBanner(status);

  setText("job-type", data.job_type || "—");
  setText("job-status-text", status);
  setText("job-started-at", data.started_at || "—");
  setText("job-finished-at", data.finished_at || "—");
  setText("job-output-path", data.output_path || "—");
  setText("job-error-message", data.error_message || "—");

  let logsText = "No logs yet.";

  if (Array.isArray(data.logs) && data.logs.length > 0) {
    logsText = data.logs.join("\n");
  } else if (typeof data.logs === "string" && data.logs.trim() !== "") {
    logsText = data.logs;
  }

  setText("job-logs", logsText);
  setRunButtonsDisabled(Boolean(data.running));
}

let lastStatus = null;

async function pollJobStatus() {
  try {
    const data = await fetchJson("/api/job-status");
    renderJobStatus(data);

    if (lastStatus === "running" && data.status !== "running") {
      await loadOutputs();  // auto refresh when job completes
    }

    lastStatus = data.status;

  } catch (error) {
    setBanner("failed");
    setText("job-error-message", error.message);
  }
}

async function runAgent() {
  try {
    const outputDir = byId("agent-output-dir").value.trim() || "outputs";
    const agentType = byId("agent-type").value;

    const data = await fetchJson("/api/run-agent", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        agent_type: agentType,
        output_dir: outputDir
      })
    });

    if (!data.success) {
      alert(data.error || "Failed to start agent job.");
      return;
    }

    activateTab("run-panel");
    await pollJobStatus();
  } catch (error) {
    alert(`Failed to start agent job: ${error.message}`);
  }
}

async function runDiscovery() {
  try {
    const outputDir = byId("discovery-output-dir").value.trim() || "outputs";

    const data = await fetchJson("/api/run-discovery", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        output_dir: outputDir
      })
    });

    if (!data.success) {
      alert(data.error || "Failed to start discovery job.");
      return;
    }

    activateTab("run-panel");
    await pollJobStatus();
  } catch (error) {
    alert(`Failed to start discovery job: ${error.message}`);
  }
}

function formatFileSize(size) {
  if (typeof size !== "number") return "Unknown size";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  return `${(size / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function renderOutputs(files) {
  const listEl = byId("outputs-list");
  const messageEl = byId("outputs-message");
  const filter = byId("output-filter").value;

  listEl.innerHTML = "";

  if (!Array.isArray(files) || files.length === 0) {
    messageEl.textContent = "No outputs found.";
    return;
  }

  let filtered = files;

  if (filter === "agent") {
    filtered = files.filter(f => f.folder.includes("agents"));
  } else if (filter === "collector") {
    filtered = files.filter(f => f.folder.includes("collector"));
  }

  if (filtered.length === 0) {
    messageEl.textContent = "No matching files.";
    return;
  }

  messageEl.textContent = `${filtered.length} file(s)`;

  filtered.forEach(file => {
    const item = document.createElement("div");
    item.className = "output-item";

    const name = document.createElement("div");
    name.className = "output-name";
    name.textContent = file.name;

    const meta = document.createElement("div");
    meta.className = "output-meta";
    meta.textContent = `${file.folder} • ${formatFileSize(file.size)}`;

    item.appendChild(name);
    item.appendChild(meta);

    listEl.appendChild(item);
  });
}

async function loadOutputs() {
  try {
    const data = await fetchJson("/api/outputs");
    renderOutputs(data.files || []);
  } catch (error) {
    byId("outputs-message").textContent = `Failed to load outputs: ${error.message}`;
    byId("outputs-list").innerHTML = "";
  }
}

function setupActions() {
  byId("save-scope-btn").addEventListener("click", saveScope);
  byId("run-agent-btn").addEventListener("click", runAgent);
  byId("run-discovery-btn").addEventListener("click", runDiscovery);
  byId("refresh-outputs-btn").addEventListener("click", loadOutputs);
  byId("output-filter").addEventListener("change", loadOutputs);
}

async function init() {
  setupTabs();
  setupActions();

  await loadEnvironment();
  await loadScope();
  await pollJobStatus();
  await loadOutputs();

  setInterval(async () => {
    await pollJobStatus();
  }, 2000);
}

window.addEventListener("DOMContentLoaded", init);