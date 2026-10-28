const PANEL_ID = "liteaudit-downloads-folder-monitor";
const ANCHOR_ID = "liteaudit-downloads-monitor";
const HISTORY_LIMIT = 50;
const POLL_INTERVAL_MS = 2000;
const RECENT_FILE_WINDOW_MS = 5000;
const INCOMPLETE_DOWNLOAD_SUFFIXES = new Set([
  ".crdownload",
  ".download",
  ".opdownload",
  ".part",
  ".partial",
  ".tmp",
]);

const PANEL_STYLES = `
  :host {
    all: initial;
    display: block;
    margin: 0 0 12px;
    color: #edf4f2;
    font: 13px/1.45 Arial, sans-serif;
  }
  * {
    box-sizing: border-box;
  }
  .controls {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px 18px;
  }
  button {
    padding: 8px 12px;
    border: 1px solid #3e665b;
    border-radius: 8px;
    background: #19332c;
    color: #a6f3d7;
    cursor: pointer;
    font: 600 12px Arial, sans-serif;
  }
  button:hover {
    border-color: #4ee6b1;
    background: #21463a;
  }
  button:disabled {
    cursor: wait;
    opacity: .65;
  }
  label {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    color: #a6f3d7;
    cursor: pointer;
  }
  input {
    accent-color: #4ee6b1;
  }
  #status, .help {
    margin: 7px 0;
    color: #8fa5a0;
    font: 12px/1.45 Arial, sans-serif;
  }
  ul {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 0 20px;
    max-height: 180px;
    margin: 0;
    padding: 0;
    overflow: auto;
    list-style: none;
  }
  li {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    min-width: 0;
    padding: 6px 0;
    border-top: 1px solid #263a36;
    color: #edf4f2;
    font: 12px/1.4 Arial, sans-serif;
  }
  .filename {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .detail {
    flex: 0 0 auto;
    color: #8fa5a0;
  }
  @media (max-width: 600px) {
    ul {
      grid-template-columns: 1fr;
      max-height: 140px;
    }
  }
`;

let panelHost;
let panelInitialized = false;
let directoryHandle;
let previousSnapshot = {};
let downloadHistory = {};
let pollTimer;
let folderMonitorEnabled = false;

function openHandleDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("liteaudit-downloads-folder", 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore("folders");
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function saveDirectoryHandle(handle) {
  const database = await openHandleDatabase();
  await new Promise((resolve, reject) => {
    const transaction = database.transaction("folders", "readwrite");
    transaction.objectStore("folders").put(handle, "downloads");
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  database.close();
}

async function loadDirectoryHandle() {
  const database = await openHandleDatabase();
  const handle = await new Promise((resolve, reject) => {
    const request = database
      .transaction("folders", "readonly")
      .objectStore("folders")
      .get("downloads");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  database.close();
  return handle;
}

function getStatusElement() {
  return panelHost?.shadowRoot?.querySelector("#status");
}

function showStatus(message) {
  const status = getStatusElement();
  if (status) {
    status.textContent = message;
  }
}

function setMonitorToggle(enabled) {
  const toggle = panelHost?.shadowRoot?.querySelector("#monitor-toggle");
  if (toggle) {
    toggle.checked = enabled;
    toggle.disabled = !directoryHandle;
  }
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) {
    return "Size unavailable";
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(1)} ${units[unitIndex]}`;
}

function displayHistory() {
  const shadow = panelHost?.shadowRoot;
  if (!shadow) {
    return;
  }
  const list = shadow.querySelector("ul");
  list.replaceChildren();

  const records = Object.values(downloadHistory).sort(
    (left, right) => right.lastModified - left.lastModified,
  );
  if (records.length === 0) {
    if (folderMonitorEnabled) {
      showStatus("Monitoring is on. No files have been detected yet.");
    }
    return;
  }

  for (const record of records.slice(0, HISTORY_LIMIT)) {
    const item = document.createElement("li");
    const filename = document.createElement("span");
    const detail = document.createElement("span");
    filename.className = "filename";
    detail.className = "detail";
    filename.textContent = record.filename;
    detail.textContent = `${record.status} · ${formatBytes(record.size)}`;
    item.append(filename, detail);
    list.append(item);
  }
}

async function persistHistory() {
  await chrome.storage.local.set({ downloadsFolderHistory: downloadHistory });
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = undefined;
  }
}

async function scanSelectedFolder() {
  if (!folderMonitorEnabled || !directoryHandle) {
    return;
  }

  try {
    const permission = await directoryHandle.queryPermission({ mode: "read" });
    if (permission !== "granted") {
      stopPolling();
      folderMonitorEnabled = false;
      setMonitorToggle(false);
      await chrome.storage.local.set({
        downloadsFolderMonitorEnabled: false,
      });
      showStatus(
        "Folder access is not currently granted. Choose or grant access to continue.",
      );
      return;
    }

    const currentEntries = {};
    for await (const [filename, handle] of directoryHandle.entries()) {
      if (handle.kind !== "file") {
        continue;
      }
      const file = await handle.getFile();
      currentEntries[filename] = {
        filename,
        size: file.size,
        lastModified: file.lastModified,
        suffix: filename.includes(".")
          ? `.${filename.split(".").pop().toLowerCase()}`
          : "",
      };
    }

    const now = Date.now();
    const previousHistory = JSON.stringify(downloadHistory);
    for (const [filename, entry] of Object.entries(currentEntries)) {
      const previous = previousSnapshot[filename];
      const isTemporary = INCOMPLETE_DOWNLOAD_SUFFIXES.has(entry.suffix);
      const changed =
        previous &&
        (previous.size !== entry.size ||
          previous.lastModified !== entry.lastModified);
      const recentlyCreated =
        !previous && now - entry.lastModified <= RECENT_FILE_WINDOW_MS;

      if (isTemporary || changed || recentlyCreated) {
        downloadHistory[filename] = {
          ...entry,
          status: isTemporary
            ? "Temporary download"
            : changed
              ? "Writing"
              : "Recently detected",
        };
      } else if (downloadHistory[filename]) {
        downloadHistory[filename].status = "No longer changing";
      }
    }

    for (const [filename, record] of Object.entries(downloadHistory)) {
      if (!currentEntries[filename]) {
        record.status = "No longer in folder";
      }
    }

    previousSnapshot = Object.fromEntries(
      Object.entries(currentEntries).map(([filename, entry]) => [
        filename,
        { size: entry.size, lastModified: entry.lastModified },
      ]),
    );
    downloadHistory = Object.fromEntries(
      Object.entries(downloadHistory)
        .sort((left, right) => right[1].lastModified - left[1].lastModified)
        .slice(0, HISTORY_LIMIT),
    );
    if (JSON.stringify(downloadHistory) !== previousHistory) {
      await persistHistory();
    }
    displayHistory();
  } catch (error) {
    stopPolling();
    folderMonitorEnabled = false;
    setMonitorToggle(false);
    await chrome.storage.local.set({ downloadsFolderMonitorEnabled: false });
    showStatus(`Could not read the selected folder: ${error.message}`);
  }
}

async function startPolling() {
  stopPolling();
  folderMonitorEnabled = true;
  await chrome.storage.local.set({ downloadsFolderMonitorEnabled: true });
  await scanSelectedFolder();
  if (folderMonitorEnabled) {
    pollTimer = setInterval(() => {
      void scanSelectedFolder();
    }, POLL_INTERVAL_MS);
  }
}

function createPanel() {
  const host = document.createElement("div");
  host.id = PANEL_ID;
  const shadow = host.attachShadow({ mode: "open" });
  shadow.innerHTML = `
    <style>${PANEL_STYLES}</style>
    <section aria-label="Downloads folder monitoring">
      <div class="controls">
        <button id="choose-folder" type="button">Choose Downloads folder</button>
        <label>
          <input id="monitor-toggle" type="checkbox" disabled>
          Monitor selected folder
        </label>
        <button id="clear-history" type="button">Clear detected files</button>
      </div>
      <p class="help">
        Select your Downloads folder and grant read access. LiteAudit checks file names,
        sizes, and change times only; it never reads file contents. Files saved there by
        any app may appear. Monitoring runs while this app page is open. Turning monitoring
        off stops folder checks; Chrome manages the underlying folder grant in this site's
        settings.
      </p>
      <p id="status" role="status" aria-live="polite">
        Choose your Downloads folder to grant access and start monitoring.
      </p>
      <ul aria-label="Detected files"></ul>
    </section>
  `;

  shadow.querySelector("#choose-folder").addEventListener("click", async () => {
    const button = shadow.querySelector("#choose-folder");
    button.disabled = true;
    try {
      if (!window.showDirectoryPicker) {
        throw new Error("This browser does not support folder access.");
      }
      directoryHandle = await window.showDirectoryPicker({
        id: "liteaudit-downloads",
        mode: "read",
        startIn: "downloads",
      });
      const permission = await directoryHandle.requestPermission({
        mode: "read",
      });
      if (permission !== "granted") {
        throw new Error("Read access was not granted.");
      }
      await saveDirectoryHandle(directoryHandle);
      setMonitorToggle(true);
      await startPolling();
      showStatus(`Monitoring “${directoryHandle.name}”.`);
    } catch (error) {
      if (error.name !== "AbortError") {
        showStatus(`Could not access the selected folder: ${error.message}`);
      }
    } finally {
      button.disabled = false;
    }
  });

  shadow
    .querySelector("#monitor-toggle")
    .addEventListener("change", async (event) => {
      const toggle = event.currentTarget;
      if (!toggle.checked) {
        folderMonitorEnabled = false;
        stopPolling();
        try {
          await chrome.storage.local.set({
            downloadsFolderMonitorEnabled: false,
          });
          showStatus(
            "Monitoring is off. Folder read access remains under your control.",
          );
        } catch (error) {
          showStatus(`Could not stop folder monitoring: ${error.message}`);
        }
        return;
      }

      if (!directoryHandle) {
        toggle.checked = false;
        showStatus("Choose your Downloads folder first to grant read access.");
        return;
      }

      try {
        const permission = await directoryHandle.requestPermission({
          mode: "read",
        });
        if (permission !== "granted") {
          toggle.checked = false;
          showStatus("Folder read access was not granted.");
          return;
        }
        await startPolling();
      } catch (error) {
        toggle.checked = false;
        showStatus(`Could not enable folder monitoring: ${error.message}`);
      }
    });

  shadow
    .querySelector("#clear-history")
    .addEventListener("click", async () => {
      downloadHistory = {};
      try {
        await persistHistory();
        displayHistory();
        showStatus(
          folderMonitorEnabled
            ? "File history cleared. Monitoring continues."
            : "File history cleared.",
        );
      } catch (error) {
        showStatus(`Could not clear file history: ${error.message}`);
      }
    });

  return host;
}

async function initializePanel() {
  try {
    const [
      savedHandle,
      {
        downloadsFolderMonitorEnabled = false,
        downloadsFolderHistory = {},
      },
    ] = await Promise.all([
      loadDirectoryHandle(),
      chrome.storage.local.get([
        "downloadsFolderMonitorEnabled",
        "downloadsFolderHistory",
      ]),
    ]);

    directoryHandle = savedHandle;
    downloadHistory = downloadsFolderHistory || {};
    if (!directoryHandle) {
      showStatus("Choose your Downloads folder to grant read access and start monitoring.");
      return;
    }

    const permission = await directoryHandle.queryPermission({ mode: "read" });
    if (permission !== "granted") {
      showStatus(
        "Folder selected. Choose the folder again to grant read access before monitoring.",
      );
      return;
    }

    setMonitorToggle(downloadsFolderMonitorEnabled);
    if (downloadsFolderMonitorEnabled) {
      await startPolling();
      showStatus(`Monitoring “${directoryHandle.name}”.`);
    } else {
      showStatus(`Folder “${directoryHandle.name}” is selected. Monitoring is off.`);
      displayHistory();
    }
  } catch (error) {
    showStatus(`Could not restore folder access: ${error.message}`);
  }
}

function mountPanel() {
  const anchor = document.getElementById(ANCHOR_ID);
  if (!anchor) {
    return;
  }
  if (!panelHost) {
    panelHost = createPanel();
  }
  if (panelHost.parentElement !== anchor) {
    anchor.append(panelHost);
  }
  if (!panelInitialized) {
    panelInitialized = true;
    void initializePanel();
  }
}

function initialize() {
  if (!document.body) {
    return;
  }
  new MutationObserver(mountPanel).observe(document.body, {
    childList: true,
    subtree: true,
  });
  mountPanel();
}

void initialize();
