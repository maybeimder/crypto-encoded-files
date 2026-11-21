"use strict";

const views = {
  login: document.getElementById("login-view"),
  register: document.getElementById("register-view"),
  main: document.getElementById("main-view"),
};
const terminalLog = document.getElementById("terminal-log");
let currentStatus = null;
let contacts = [];

// ---------- utilidades ----------

function element(tag, properties = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(properties)) {
    if (key === "onclick") node.addEventListener("click", value);
    else if (key === "className") node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of [].concat(children)) {
    // Siempre texto, nunca HTML: un nombre de archivo malicioso no puede inyectar marcado
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

const ICONS = {
  download: "M12 4v11M7 11l5 5 5-5M5 20h14",
  upload: "M12 20V9M7 13l5-5 5 5M5 4h14",
  users: "M9 11a3 3 0 100-6 3 3 0 000 6zM3 20c0-3 2.7-5 6-5s6 2 6 5M17 5.5a3 3 0 010 5.5M21 20c0-2.4-1.5-4-3.5-4.7",
  chevron: "M6 9l6 6 6-6",
  check: "M5 12l5 5 9-10",
  x: "M6 6l12 12M18 6L6 18",
  plus: "M12 5v14M5 12h14",
  copy: "M9 9h11v11H9zM5 15H4V4h11v1",
  check: "M5 12l5 5 9-10",
  minus: "M5 12h14",
  sort: "M7 4v16M3 8l4-4 4 4M17 20V4M13 16l4 4 4-4",
  sortDown: "M7 4v16M3 16l4 4 4-4M14 6h7M14 11h5M14 16h3",
  sortUp: "M7 20V4M3 8l4-4 4 4M14 18h7M14 13h5M14 8h3",
  file: "M14 3H7a1 1 0 00-1 1v16a1 1 0 001 1h10a1 1 0 001-1V7zM14 3v4h4",
  text: "M14 3H7a1 1 0 00-1 1v16a1 1 0 001 1h10a1 1 0 001-1V7zM14 3v4h4M9 12h6M9 16h6M9 8h2",
  markdown: "M3 6h18v12H3zM6.5 15v-6l2.5 3 2.5-3v6M16 9v6M14 13l2 2 2-2",
  image: "M4 5h16v14H4zM8.5 10a1.5 1.5 0 100-3 1.5 1.5 0 000 3zM4 17l5-5 4 4 3-3 4 4",
  video: "M3 6h12v12H3zM15 10l6-3v10l-6-3",
  audio: "M9 18V5l11-2v13M9 18a3 3 0 11-6 0 3 3 0 016 0zM20 16a3 3 0 11-6 0 3 3 0 016 0z",
  sheet: "M4 5h16v14H4zM4 10h16M4 15h16M10 5v14",
  slides: "M3 4h18v12H3zM12 16v4M8 20h8M7 12l3-3 2 2 4-4",
  archive: "M4 4h16v4H4zM5 8v12h14V8M10 12h4",
  code: "M8 7l-5 5 5 5M16 7l5 5-5 5M14 4l-4 16",
};

// Tipo de archivo → icono. Las imágenes se agrupan en uno solo
const FILE_TYPES = {
  pdf: ["pdf"], doc: ["doc", "docx", "odt", "rtf", "pages"], sheet: ["xls", "xlsx", "csv", "ods", "numbers"],
  slides: ["ppt", "pptx", "odp", "key"], markdown: ["md", "markdown"], text: ["txt", "log"],
  image: ["jpg", "jpeg", "png", "gif", "webp", "svg", "bmp", "avif", "heic", "tif", "tiff"],
  video: ["mp4", "mov", "mkv", "webm", "avi", "m4v", "wmv"],
  audio: ["mp3", "wav", "flac", "ogg", "m4a", "aac", "opus"],
  archive: ["zip", "tar", "gz", "tgz", "7z", "rar", "bz2", "xz"],
  code: ["js", "ts", "py", "json", "html", "css", "c", "h", "rs", "go", "sh", "java", "yml", "yaml", "toml", "sql"],
};
// Varios tipos comparten dibujo; el color (CSS, data-kind) es lo que los distingue
const KIND_ICON = { pdf: "text", doc: "text" };
function fileKind(name) {
  const extension = (name || "").split(".").pop().toLowerCase();
  return Object.keys(FILE_TYPES).find((kind) => FILE_TYPES[kind].includes(extension)) || "file";
}

const cleanLabel = (label) => label.replace(/\s*[\[(]?\s*sin verificar\s*[\])]?/i, "").trim() || label;
function badge(unverified, compact = false) {
  const node = element("span", { className: `badge ${unverified ? "warn" : "ok"}${compact ? " compact" : ""}`,
    title: unverified ? "Huella sin verificar" : "Huella verificada" }, [icon(unverified ? "x" : "check")]);
  node.append(compact && !unverified ? "" : (unverified ? "sin verificar" : "verificado"));
  return node;
}

// Copia al portapapeles y confirma con un check un instante
function copyButton(text, label) {
  const button = element("button", { type: "button", className: "icon-button copy", "aria-label": label, title: "Copiar" }, [icon("copy")]);
  button.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(text); } catch { return; }
    button.classList.add("done");
    button.replaceChildren(icon("check"));
    setTimeout(() => { button.classList.remove("done"); button.replaceChildren(icon("copy")); }, 1200);
  });
  return button;
}
function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "icon");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", ICONS[name]);
  svg.append(path);
  return svg;
}
function iconButton(name, text, properties) {
  return element("button", { type: "button", ...properties }, [icon(name), text]);
}

async function api(path, { method = "GET", json, body } = {}) {
  // La cabecera propia demuestra que la petición sale de esta interfaz y no de una página ajena
  const options = { method, headers: { "X-Cryptostore": "1" } };
  if (json !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(json);
  } else if (body !== undefined) {
    options.headers["Content-Type"] = "application/octet-stream";
    options.body = body;
  }
  const response = await fetch(path, options);
  const content = await response.json().catch(() => ({}));
  if (!response.ok) {
    const failure = new Error(typeof content.detail === "string" ? content.detail : `error ${response.status}`);
    failure.kind = content.kind || "error";
    failure.status = response.status;
    throw failure;
  }
  return content;
}

function humanSize(bytes) {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MiB`;
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1)} KiB`;
  return `${bytes} B`;
}

function shellQuote(text) {
  return /^[\w.\-/:]+$/.test(text) ? text : `"${text.replaceAll('"', '\\"')}"`;
}

// ---------- avisos (toast) ----------

function toast(message, kind = "ok") {
  const box = document.getElementById("toasts");
  const node = element("div", { className: `toast ${kind}`, role: kind === "error" ? "alert" : "status" }, [icon(kind === "error" ? "x" : "check"), element("span", {}, [message])]);
  const dismiss = () => { node.classList.add("leaving"); setTimeout(() => node.remove(), 200); };
  node.addEventListener("click", dismiss);
  box.append(node);
  while (box.children.length > 4) box.firstElementChild.remove();
  setTimeout(dismiss, kind === "error" ? 6000 : 3500);
}

// ---------- registro tipo terminal ----------

const terminalPanel = document.getElementById("terminal-panel");
// La actividad abre el registro: es la confirmación de cada acción
function reveal() { terminalPanel.open = true; }

function logCommand(...argumentsList) {
  const line = element("div", { className: "command" }, ["cryptostore " + argumentsList.map(shellQuote).join(" ")]);
  terminalLog.append(line);
  reveal();
  terminalLog.scrollTop = terminalLog.scrollHeight;
}

function logLine(text, kind = "") {
  const line = element("div", { className: kind }, [text]);
  terminalLog.append(line);
  reveal();
  terminalLog.scrollTop = terminalLog.scrollHeight;
  return line;
}

function logShell(text) {
  terminalLog.append(element("div", { className: "command" }, [text]));
  terminalLog.scrollTop = terminalLog.scrollHeight;
}

function logFailure(failure) {
  toast(failure.message, "error");
  // Sesión vencida por inactividad: de vuelta al login
  if (failure.status === 401) { refreshStatus(); return; }
  // Mismo criterio que la terminal: el rechazo criptográfico se marca aparte
  logLine(failure.kind === "rejected" ? failure.message : `error: ${failure.message}`,
          failure.kind === "rejected" ? "rejected" : "error");
}

function progressText(label, completed, total) {
  const width = 30;
  const fraction = total ? completed / total : 0;
  const filled = Math.floor(width * fraction);
  const percentage = String(Math.floor(fraction * 100)).padStart(3, " ");
  return `${label} [${"#".repeat(filled)}${"-".repeat(width - filled)}] ${percentage}% (${completed}/${total})`;
}

async function followJob(job, label) {
  const line = logLine(progressText(label, 0, 0));
  // Se consulta el progreso hasta que la tarea termina; el texto es el mismo que muestra la CLI
  while (true) {
    job = await api(`/api/jobs/${job.job_id}`);
    line.textContent = progressText(label, job.completed_steps, job.total_steps);
    if (job.status !== "running") break;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  if (job.status === "done") return job;
  const failure = new Error(job.status === "rejected" ? `RECHAZADO: ${job.message}` : job.message);
  failure.kind = job.status === "rejected" ? "rejected" : "error";
  throw failure;
}

// ---------- vistas ----------

function show(viewName) {
  for (const [name, view] of Object.entries(views)) view.hidden = name !== viewName;
  const unlocked = viewName === "main";
  document.getElementById("identity-chip").hidden = !unlocked;
  document.getElementById("lock-button").hidden = !unlocked;
  // `autofocus` no sirve en vistas que empiezan ocultas: se enfoca el primer campo al mostrarlas
  if (viewName !== "main") views[viewName].querySelector("input").focus();
}

for (const switcher of document.querySelectorAll(".auth-switch")) {
  switcher.addEventListener("click", () => show(switcher.dataset.show));
}

async function refreshStatus() {
  currentStatus = await api("/api/status");
  if (!currentStatus.logged_in) {
    document.querySelector("#register-form [name=server_url]").value = currentStatus.suggested_server_url;
    return show(views.register.hidden ? "login" : "register");
  }
  document.getElementById("identity-name").textContent = currentStatus.username;
  document.getElementById("identity-server").textContent = currentStatus.server_url;
  renderFingerprint(currentStatus.fingerprint);
  show("main");
  await refreshAll();
}

function renderFingerprint(fingerprint) {
  const container = document.getElementById("own-fingerprint");
  container.replaceChildren(...fingerprint.split(" ").map((group) => element("span", {}, [group])));
  const copy = document.getElementById("copy-own");
  copy.replaceChildren(icon("copy"), "Copiar huella");
  copy.onclick = async () => {
    try { await navigator.clipboard.writeText(fingerprint); } catch { return; }
    copy.replaceChildren(icon("check"), "Copiada");
    setTimeout(() => copy.replaceChildren(icon("copy"), "Copiar huella"), 1200);
  };
}

async function refreshAll() {
  const [files, contactList] = await Promise.all([api("/api/files"), api("/api/contacts")]);
  contacts = contactList;
  renderFiles(files);
  renderContacts(contactList);
  document.getElementById("contact-count").textContent = contactList.length || "";
}

// Filtro (todos / míos / conmigo) y orden por tamaño, solo en pantalla
let allFiles = [];
let fileFilter = "all";
let sizeOrder = "none";

function renderFiles(files) {
  allFiles = files;
  const visible = files.filter((file) => fileFilter === "all" || (fileFilter === "mine") === (file.role === "owner"));
  if (sizeOrder !== "none") {
    const direction = sizeOrder === "desc" ? -1 : 1;
    visible.sort((a, b) => direction * ((a.plaintext_size ?? 0) - (b.plaintext_size ?? 0)));
  }
  paintFiles(visible);
  document.getElementById("file-count").textContent = files.length || "";
  document.getElementById("files-empty").textContent = files.length ? "Nada con este filtro." : "Sin archivos todavía.";
}

function paintFiles(files) {
  const rows = files.map((file) => {
    const waitingForVerification = file.problem_kind === "unverified_owner";
    let title;
    if (waitingForVerification) {
      title = element("span", { className: "file-pending" }, [file.problem]);
    } else if (file.problem) {
      title = element("span", { className: "problem" }, [file.problem]);
    } else {
      title = element("span", { className: "file-name", title: file.name }, [file.name]);
    }
    const meta = element("span", { className: "file-meta" },
      [`v${file.latest_version} · ${file.owner_label} · `, element("span", { title: file.file_id }, [file.file_id.slice(0, 8)])]);
    const actions = element("div", { className: "actions" });
    // Antes de abrirlo hay que confirmar, con la huella dictada, que quien lo firma es quien dice ser
    if (waitingForVerification) {
      actions.append(iconButton("check", `Verificar a ${file.owner_claimed_name}`, { className: "button small",
        onclick: () => prepareTrust(file.owner_claimed_name) }));
    }
    // El nombre accesible incluye el archivo: "Descargar" suelto se repite en cada fila
    const label = (action) => `${action} ${file.name || file.file_id}`;
    // De izquierda a derecha: Versión, Accesos, Descargar
    if (file.role === "owner" && !file.problem) {
      const wrap = element("div", { className: "menu-wrap" });
      const trigger = iconButton("users", "Accesos", { className: "button small", "aria-haspopup": "true", "aria-expanded": "false", "aria-label": label("Accesos de") });
      trigger.append(icon("chevron"));
      trigger.addEventListener("click", () => toggleAccessMenu(file, wrap, trigger));
      wrap.append(trigger);
      actions.append(
        iconButton("upload", "Versión", { className: "button small ghost", "aria-label": label("Nueva versión de"), onclick: () => pickReplacement(file) }),
        wrap);
    }
    if (!file.problem) {
      actions.append(iconButton("download", "Descargar", { className: "button small accent", "aria-label": label("Descargar"),
        onclick: (event) => downloadFile(file, event.currentTarget) }));
    }
    const row = element("li", { className: "file" }, [
      element("span", { className: "file-type", "data-kind": file.problem ? "file" : fileKind(file.name), title: fileKind(file.name) },
        [icon(file.problem ? "file" : (KIND_ICON[fileKind(file.name)] || fileKind(file.name)))]),
      element("div", { className: "file-info" }, [title, meta]),
      element("span", { className: "file-size" }, [humanSize(file.plaintext_size)]),
      actions,
    ]);
    // Nombre largo: en reposo se corta con «…»; al pasar por encima se desplaza para leerlo entero
    const nameBox = row.querySelector(".file-name");
    if (nameBox) {
      row.addEventListener("mouseenter", () => {
        const shift = nameBox.scrollWidth - nameBox.clientWidth;
        if (shift <= 1) return;
        nameBox.style.setProperty("--shift", `-${shift + 8}px`);
        nameBox.style.setProperty("--dur", `${Math.max(2, shift / 30)}s`);
        nameBox.classList.add("scrolling");
      });
      row.addEventListener("mouseleave", () => nameBox.classList.remove("scrolling"));
    }
    return row;
  });
  document.getElementById("file-rows").replaceChildren(...rows);
  document.getElementById("files-empty").hidden = files.length > 0;
}

for (const button of document.querySelectorAll("[data-filter]")) {
  button.addEventListener("click", () => {
    fileFilter = button.dataset.filter;
    for (const other of document.querySelectorAll("[data-filter]")) other.setAttribute("aria-pressed", String(other === button));
    renderFiles(allFiles);
  });
}
const sortButton = document.getElementById("sort-size");
function paintSortButton() {
  const labels = { none: "sin orden", desc: "mayor primero", asc: "menor primero" };
  sortButton.replaceChildren(icon({ none: "sort", desc: "sortDown", asc: "sortUp" }[sizeOrder]), "Tamaño");
  sortButton.dataset.order = sizeOrder;
  sortButton.setAttribute("aria-label", `Ordenar por tamaño: ${labels[sizeOrder]}`);
}
sortButton.addEventListener("click", () => {
  sizeOrder = { none: "desc", desc: "asc", asc: "none" }[sizeOrder];
  paintSortButton();
  renderFiles(allFiles);
});
paintSortButton();

// Cada contacto es un botón: clic = ver huella. A la derecha, copiar y quitar (con confirmación en el propio botón)
function renderContacts(contactList) {
  const items = contactList.map((contact) => {
    const detail = element("div", { className: "fp-row", hidden: "" }, [
      element("span", { className: "fingerprint-inline" }, [contact.fingerprint]),
    ]);
    const name = element("button", { type: "button", className: "contact-name", "aria-expanded": "false",
      "aria-label": `Ver huella de ${contact.alias}` }, [contact.alias]);
    const toggle = () => {
      detail.hidden = !detail.hidden;
      name.setAttribute("aria-expanded", String(!detail.hidden));
    };
    const remove = element("button", { type: "button", className: "icon-button remove", title: "Quitar contacto",
      "aria-label": `Quitar a ${contact.alias} de los contactos` }, [icon("minus")]);
    let timer = 0;
    const disarm = () => {
      clearTimeout(timer);
      if (!remove.classList.contains("armed")) return;
      remove.classList.remove("armed");
      remove.replaceChildren(icon("minus"));
      remove.setAttribute("aria-label", `Quitar a ${contact.alias} de los contactos`);
    };
    remove.addEventListener("click", () => {
      if (remove.classList.contains("armed")) { disarm(); untrust(contact.alias); return; }
      remove.classList.add("armed");
      remove.replaceChildren(icon("check"), "¿Quitar?");
      remove.setAttribute("aria-label", `Confirmar: quitar a ${contact.alias}`);
      timer = setTimeout(disarm, 4000);
    });
    remove.addEventListener("blur", disarm);
    const line = element("div", { className: "line" }, [name, copyButton(contact.fingerprint, `Copiar huella de ${contact.alias}`), remove]);
    line.addEventListener("click", (event) => { if (!event.target.closest(".icon-button")) toggle(); });
    return element("li", { className: "contact" }, [line, detail]);
  });
  if (!items.length) items.push(element("li", { className: "dim" }, ["Nadie todavía."]));
  document.getElementById("contact-list").replaceChildren(...items);
}

// En la lista del servidor no hay botón de copiar: la huella se verifica por otro canal, no desde aquí
function renderUsers(users) {
  const items = users.map((user) => {
    const unverified = user.label.includes("sin verificar");
    return element("li", { className: "contact" }, [
      element("div", { className: "line" }, [
        element("span", { className: "who" }, [user.display_name, user.label === "tú" ? element("span", { className: "badge" }, ["tú"]) : badge(unverified)]),
        unverified
          ? element("button", { type: "button", className: "link", "aria-label": `Verificar a ${user.display_name}`, onclick: () => prepareTrust(user) }, ["verificar"])
          : "",
      ]),
      element("div", { className: "fp-row" }, [element("span", { className: "fingerprint-inline" }, [user.fingerprint])]),
    ]);
  });
  document.getElementById("user-list").replaceChildren(...items);
}

// El formulario de contacto solo aparece al pulsar "Registrar nuevo contacto"
function setTrustForm(visible) {
  document.getElementById("trust-form").hidden = !visible;
  document.getElementById("add-contact").setAttribute("aria-expanded", String(visible));
  if (visible) document.getElementById("trust-form").alias.focus();
}
document.getElementById("add-contact").addEventListener("click", () => setTrustForm(document.getElementById("trust-form").hidden));

function prepareTrust(name) {
  // Solo se rellena el alias: la huella la dicta la persona por un canal confiable; el servidor no la aporta
  document.getElementById("contacts-panel").open = true;
  const form = document.getElementById("trust-form");
  setTrustForm(true);
  form.alias.value = name;
  form.fingerprint.value = "";
  form.fingerprint.focus();
  logLine(`Pide su huella a ${name} y escríbela.`);
}

// ---------- confirmación con contraseña ----------

const confirmDialog = document.getElementById("confirm-dialog");
const confirmForm = document.getElementById("confirm-form");

// Devuelve la contraseña escrita, o null si se cancela; se usa justo antes de cada acción sensible
function askPassword(detail, actionLabel) {
  closeMenu();
  document.getElementById("confirm-detail").textContent = detail;
  document.getElementById("confirm-submit").textContent = actionLabel;
  confirmForm.passphrase.value = "";
  return new Promise((resolve) => {
    const finish = (value) => {
      confirmForm.removeEventListener("submit", onSubmit);
      document.getElementById("confirm-cancel").removeEventListener("click", onCancel);
      confirmDialog.removeEventListener("cancel", onCancel);
      confirmDialog.close();
      // La contraseña no se queda en el formulario después de usarla
      confirmForm.passphrase.value = "";
      resolve(value);
    };
    const onSubmit = (event) => { event.preventDefault(); finish(confirmForm.passphrase.value); };
    const onCancel = (event) => { event.preventDefault(); finish(null); };
    confirmForm.addEventListener("submit", onSubmit);
    document.getElementById("confirm-cancel").addEventListener("click", onCancel);
    confirmDialog.addEventListener("cancel", onCancel);
    confirmDialog.showModal();
    confirmForm.passphrase.focus();
  });
}

// ---------- acciones ----------

async function uploadFile(file, replaceFileId = null) {
  const commandArguments = ["upload", file.name];
  if (replaceFileId) commandArguments.push("--replace", replaceFileId);
  logCommand(...commandArguments);
  try {
    const query = new URLSearchParams({ name: file.name });
    if (replaceFileId) query.set("replace", replaceFileId);
    const job = await followJob(await api(`/api/uploads?${query}`, { method: "POST", body: file }), "Subiendo  ");
    const result = job.result;
    toast(`Subido: ${file.name}`);
    logLine(`Publicado ${result.file_id} (versión ${result.content_version}, ${result.total_blocks} bloques).`, "ok");
    if (result.renewed_recipients.length) logLine(`Acceso renovado a la nueva versión para: ${result.renewed_recipients.join(", ")}`);
    if (result.skipped_recipients.length) logLine(`Sin renovar (no están en su libreta): ${result.skipped_recipients.join(", ")}`);
    await refreshAll();
  } catch (failure) {
    logFailure(failure);
  }
}

async function downloadFile(file, button) {
  const passphrase = await askPassword(`Vas a descifrar «${file.name}» en este equipo.`, "Descargar");
  if (passphrase === null) return;
  logCommand("download", file.file_id);
  // Un segundo clic mientras se descarga lanzaría otra tarea idéntica
  if (button) button.disabled = true;
  try {
    const job = await followJob(await api(`/api/files/${file.file_id}/download`, { method: "POST", json: { passphrase } }), "Bajando   ");
    toast(`Descargado: ${job.result.name}`);
    logLine(`Verificado: ${job.result.name} (${job.result.size} bytes, versión ${job.result.content_version}).`, "ok");
    // Solo ahora, con todo verificado, el navegador recibe el archivo en claro
    const link = element("a", { href: `/api/jobs/${job.job_id}/file`, download: job.result.name });
    document.body.append(link);
    link.click();
    link.remove();
  } catch (failure) {
    logFailure(failure);
  } finally {
    if (button) button.disabled = false;
  }
}

function pickReplacement(file) {
  const picker = element("input", { type: "file" });
  picker.addEventListener("change", () => picker.files[0] && uploadFile(picker.files[0], file.file_id));
  picker.click();
}

// Menú de accesos: quién puede abrir el archivo, retirar a alguien y añadir contactos verificados
let openMenu = null;
function closeMenu() {
  if (!openMenu) return;
  openMenu.menu.remove();
  openMenu.trigger.setAttribute("aria-expanded", "false");
  openMenu = null;
}

async function toggleAccessMenu(file, wrap, trigger) {
  const wasOpen = openMenu && openMenu.trigger === trigger;
  closeMenu();
  if (wasOpen) return;
  logCommand("recipients", file.file_id);
  try {
    const result = await api(`/api/files/${file.file_id}/recipients`);
    const menu = element("div", { className: "menu", role: "group", "aria-label": `Accesos de ${file.name}` });
    openMenu = { menu, trigger };
    trigger.setAttribute("aria-expanded", "true");
    wrap.append(menu);
    renderAccessMenu(file, result, menu);
  } catch (failure) {
    logFailure(failure);
  }
}

function renderAccessMenu(file, result, menu) {
  const refresh = async () => renderAccessMenu(file, await api(`/api/files/${file.file_id}/recipients`), menu);
  const people = result.recipients.map((recipient) => element("li", { className: "person" }, [
    element("span", { className: "person-name" }, [cleanLabel(recipient.label),
      recipient.label === "tú" ? "" : badge(recipient.label.includes("sin verificar"), true)]),
    element("span", { className: "person-fp" }, [recipient.fingerprint.slice(0, 9)]),
    copyButton(recipient.fingerprint, `Copiar huella de ${cleanLabel(recipient.label)}`),
    recipient.label === "tú" ? "" : iconButton("x", "", {
      className: "icon-button danger",
      "aria-label": `Retirar acceso a ${recipient.label}`,
      onclick: async () => { await revokeAccess(file, recipient); try { await refresh(); } catch { closeMenu(); } },
    }),
  ]));
  const present = new Set(result.recipients.map((recipient) => recipient.label));
  const addable = contacts.filter((contact) => !present.has(contact.alias)).map((contact) => element("li", {}, [
    iconButton("plus", contact.alias, {
      className: "menu-item",
      "aria-label": `Compartir ${file.name} con ${contact.alias}`,
      onclick: async () => { await shareWith(file, contact.alias); try { await refresh(); } catch { closeMenu(); } },
    }),
  ]));
  if (!addable.length) addable.push(element("li", { className: "dim menu-note" }, [contacts.length ? "Ya lo ven todos tus contactos." : "Verifica un contacto para compartir."]));
  menu.replaceChildren(
    element("div", { className: "menu-head" }, [`con acceso · época ${result.acl_epoch}`]),
    element("ul", { className: "plain-list" }, people),
    element("div", { className: "menu-head" }, ["compartir con"]),
    element("ul", { className: "plain-list" }, addable),
  );
  placeMenu(menu);
}

// La terminal fija tapa el borde inferior: si el menú no cabe encima de ella, se abre hacia arriba
function placeMenu(menu) {
  menu.classList.remove("up");
  const limit = innerHeight - terminalPanel.getBoundingClientRect().height - 8;
  if (menu.getBoundingClientRect().bottom > limit) menu.classList.add("up");
}

async function shareWith(file, alias) {
  const passphrase = await askPassword(`${alias} podrá descifrar «${file.name}». Lo que descargue no se puede retirar después.`, "Compartir");
  if (passphrase === null) return;
  logCommand("share", file.file_id, alias);
  try {
    const result = await api(`/api/files/${file.file_id}/share`, { method: "POST", json: { alias, passphrase } });
    toast(`Compartido con ${alias}`);
    logLine(`Acceso dado a ${alias} sin volver a cifrar el contenido (época de permisos ${result.acl_epoch}).`, "ok");
  } catch (failure) {
    logFailure(failure);
  }
}

document.addEventListener("click", (event) => { if (openMenu && !event.target.closest(".menu-wrap")) closeMenu(); });
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && openMenu) { const { trigger } = openMenu; closeMenu(); trigger.focus(); }
});

async function revokeAccess(file, recipient) {
  const recipientArgument = recipient.label.includes("sin verificar") ? recipient.user_id : recipient.label;
  const passphrase = await askPassword(`${recipient.label} dejará de poder bajar «${file.name}». Lo que ya descargó sigue en su equipo.`, "Retirar acceso");
  if (passphrase === null) return;
  logCommand("revoke", file.file_id, recipientArgument);
  try {
    const result = await api(`/api/files/${file.file_id}/revoke`, { method: "POST", json: { recipient: recipientArgument, passphrase } });
    // El mensaje explica qué deja de pasar y qué no puede deshacerse (la copia ya descargada)
    toast(`Acceso retirado a ${recipient.label}`);
    logLine(result.message, "ok");
    logLine(`(época de permisos ${result.acl_epoch})`);
  } catch (failure) {
    logFailure(failure);
  }
}

async function untrust(alias) {
  logCommand("untrust", alias);
  try {
    renderContacts(contacts = await api(`/api/contacts/${encodeURIComponent(alias)}`, { method: "DELETE" }));
    toast(`${alias} eliminado de contactos`);
    logLine(`'${alias}' eliminado de la libreta.`, "ok");
  } catch (failure) {
    logFailure(failure);
  }
}

// ---------- formularios y eventos ----------

function announceLogin(status) {
  // La misma carpeta sirve desde la terminal: así se apunta a ella
  logShell(`export CRYPTOSTORE_HOME=${shellQuote(status.home_directory)}`);
}

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const error = form.querySelector(".form-error");
  try {
    const status = await api("/api/login", { method: "POST", json: { username: form.username.value, passphrase: form.passphrase.value } });
    error.textContent = "";
    announceLogin(status);
    logLine(`Sesión iniciada como ${status.username}.`, "ok");
    await refreshStatus();
  } catch (failure) {
    // El registro aún no está a la vista: el error se muestra en el propio formulario
    error.textContent = failure.message;
  } finally {
    form.passphrase.value = "";
  }
});

document.getElementById("register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const error = form.querySelector(".form-error");
  if (form.passphrase.value !== form.passphrase_again.value) {
    error.textContent = "las contraseñas no coinciden";
    return;
  }
  try {
    const status = await api("/api/register", { method: "POST", json: {
      username: form.username.value, server_url: form.server_url.value, passphrase: form.passphrase.value } });
    error.textContent = "";
    announceLogin(status);
    logCommand("init", "--name", status.username, "--server", status.server_url);
    logLine("Cuenta creada. Dicta tu huella a tus contactos.", "ok");
    form.reset();
    show("login");
    await refreshStatus();
  } catch (failure) {
    error.textContent = failure.message;
  } finally {
    form.passphrase.value = "";
    form.passphrase_again.value = "";
  }
});

document.getElementById("trust-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  logCommand("trust", form.alias.value, "--fingerprint", form.fingerprint.value);
  try {
    await api("/api/contacts", { method: "POST", json: { alias: form.alias.value, fingerprint: form.fingerprint.value } });
    toast(`${form.alias.value} añadido a contactos`);
    logLine(`'${form.alias.value}' verificado y fijado.`, "ok");
    form.reset();
    setTrustForm(false);
    await refreshAll();
  } catch (failure) {
    logFailure(failure);
  }
});

document.getElementById("lock-button").addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST" });
    // El siguiente usuario de esta pestaña no debe ver el historial del anterior
    terminalLog.replaceChildren();
    await refreshStatus();
  } catch (failure) {
    logFailure(failure);
  }
});

// La zona de subida es un botón real (alcanzable con teclado) que abre el selector oculto
document.getElementById("drop-zone").addEventListener("click", () => document.getElementById("file-input").click());

document.getElementById("file-input").addEventListener("change", (event) => {
  if (event.target.files[0]) uploadFile(event.target.files[0]);
  event.target.value = "";
});

// Soltar fuera de la zona haría que el navegador abriera el archivo y se perdiera la sesión
for (const name of ["dragover", "drop"]) window.addEventListener(name, (event) => event.preventDefault());

const dropZone = document.getElementById("drop-zone");
dropZone.addEventListener("dragover", (event) => { event.preventDefault(); dropZone.classList.add("active"); });
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("active"));
dropZone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropZone.classList.remove("active");
  if (event.dataTransfer.files[0]) uploadFile(event.dataTransfer.files[0]);
});

document.getElementById("clear-log").addEventListener("click", (event) => { event.preventDefault(); event.stopPropagation(); terminalLog.replaceChildren(); });

refreshStatus().catch(logFailure);


// ---------- visuales: texto codificado en cambio constante ----------

const GLYPHS = "0123456789abcdef#$%&*+=<>/\\|~░▒";
const calm = matchMedia("(prefers-reduced-motion: reduce)").matches;
const randomGlyph = () => GLYPHS[Math.floor(Math.random() * GLYPHS.length)];

// Descifra un texto letra a letra desde ruido; el texto final es siempre el real
function decode(node, finalText, duration = 700) {
  if (calm) { node.textContent = finalText; return; }
  const start = performance.now();
  const step = (now) => {
    const progress = Math.min(1, (now - start) / duration);
    const settled = Math.floor(progress * finalText.length);
    node.textContent = finalText.split("").map((ch, i) => (i < settled || ch === " " ? ch : randomGlyph())).join("");
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

const wordmark = document.getElementById("wordmark-text");
decode(wordmark, "$tore", 900);
wordmark.parentElement.addEventListener("mouseenter", () => decode(wordmark, "$tore", 500));

const dropLabel = document.getElementById("drop-label");
dropZone.addEventListener("mouseenter", () => decode(dropLabel, "Suelta un archivo", 450));
dropZone.addEventListener("dragenter", () => decode(dropLabel, "Suéltalo ya", 350));

// Flujo de bytes dentro de la zona de subida
const glyphBox = document.getElementById("drop-glyphs");
function glyphFrame() {
  const columns = Math.max(24, Math.floor(dropZone.clientWidth / 7));
  const rows = Math.max(6, Math.floor(dropZone.clientHeight / 16));
  const lines = [];
  for (let r = 0; r < rows; r++) {
    let line = "";
    for (let c = 0; c < columns; c++) line += Math.random() < 0.55 ? randomGlyph() : " ";
    lines.push(line);
  }
  glyphBox.textContent = lines.join("\n");
}

// Campo de píxeles/glifos al fondo: celdas que se encienden y se apagan
const field = document.getElementById("field");
const paint = field.getContext("2d");
const CELL = 18;
let cells = [], cols = 0, rowsCount = 0;
function sizeField() {
  const ratio = Math.min(devicePixelRatio || 1, 2);
  field.width = innerWidth * ratio; field.height = innerHeight * ratio;
  paint.setTransform(ratio, 0, 0, ratio, 0, 0);
  cols = Math.ceil(innerWidth / CELL); rowsCount = Math.ceil(innerHeight / CELL);
  cells = Array.from({ length: cols * rowsCount }, () => ({ ch: randomGlyph(), a: 0 }));
  paint.font = `12px ${getComputedStyle(document.body).fontFamily}`;
  paint.textBaseline = "top";
}
function fieldFrame() {
  paint.clearRect(0, 0, innerWidth, innerHeight);
  for (let n = 0; n < cells.length / 40; n++) {
    const cell = cells[Math.floor(Math.random() * cells.length)];
    cell.ch = randomGlyph(); cell.a = 0.25 + Math.random() * 0.6;
  }
  for (let i = 0; i < cells.length; i++) {
    const cell = cells[i];
    if (cell.a < 0.02) continue;
    paint.fillStyle = `rgba(61,255,122,${cell.a * 0.5})`;
    paint.fillText(cell.ch, (i % cols) * CELL + 3, Math.floor(i / cols) * CELL + 2);
    cell.a *= 0.86;
  }
}
sizeField();
addEventListener("resize", sizeField);
if (calm) {
  glyphFrame();
} else {
  setInterval(() => { if (!document.hidden) { fieldFrame(); } }, 90);
  setInterval(() => { if (!document.hidden) glyphFrame(); }, 140);
}
