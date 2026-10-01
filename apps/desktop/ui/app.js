// Tokenmaxxing popover UI. Vanilla JS on purpose: no build step, nothing to audit but this file.
// All data comes from the Rust side (`get_status` + the `status` event); this file only renders.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const main = document.getElementById("main");
const autostart = document.getElementById("autostart");
const version = document.getElementById("version");
const btnDashboard = document.getElementById("btn-dashboard");
const btnHide = document.getElementById("btn-hide");
const btnQuit = document.getElementById("btn-quit");

let status = null;
let busy = false;
let pairError = null;
let keyErrors = {};
let openKeyForms = new Set();

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v === true ? "" : v);
  }
  for (const child of [].concat(children)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function formatTokens(n) {
  if (!Number.isFinite(n) || n < 0) return "0";
  if (n < 1000) return String(Math.round(n));
  const units = [[1e12, "T"], [1e9, "B"], [1e6, "M"], [1e3, "K"]];
  for (const [v, s] of units) {
    if (n >= v) {
      const x = n / v;
      const d = x >= 100 ? 0 : x >= 10 ? 1 : 2;
      return x.toFixed(d).replace(/\.?0+$/, "") + s;
    }
  }
  return String(n);
}

function timeAgo(iso, now = Date.now()) {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (s < 45) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

function timeUntil(iso, now = Date.now()) {
  const s = Math.max(0, Math.round((Date.parse(iso) - now) / 1000));
  if (s < 60) return `${s}s`;
  return `${Math.round(s / 60)}m`;
}

async function call(command, args) {
  busy = true;
  render();
  try {
    const result = await invoke(command, args);
    if (result && typeof result === "object" && "providers" in result) status = result;
    return result;
  } finally {
    busy = false;
    render();
  }
}

// ---- views -------------------------------------------------------------------------------------

function pairingView() {
  const server = el("input", { type: "url", id: "server", value: status.server, placeholder: "https://api.tokenmaxxing.dev", spellcheck: "false" });
  const code = el("input", { type: "text", id: "code", class: "code", placeholder: "TMX-XXXX-XXXX", autocomplete: "off", spellcheck: "false", maxlength: "13" });
  const submit = async () => {
    pairError = null;
    try {
      await call("pair", { code: code.value.trim(), server: server.value.trim(), name: null });
    } catch (e) {
      pairError = String(e);
      render();
    }
  };
  code.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submit();
  });
  setTimeout(() => code.focus(), 0);
  return el("div", { class: "card" }, [
    el("div", { class: "card-head" }, [el("h2", { text: "Link this device" })]),
    el("div", { class: "card-body" }, [
      el("p", { class: "hint", text: "Sign in on the web dashboard, generate a pairing code, and enter it here. Your provider logins never leave this machine." }),
      el("label", { class: "field" }, ["Server", server]),
      el("label", { class: "field" }, ["Pairing code", code]),
      pairError ? el("div", { class: "error", text: pairError }) : null,
      el("div", { style: "display:flex; gap:8px; justify-content:flex-end" }, [
        el("button", { class: "btn", type: "button", onclick: () => invoke("open_web", { path: "/dashboard" }).catch(() => {}), text: "Get a code ↗" }),
        el("button", { class: "btn primary", type: "button", disabled: busy, onclick: submit, text: busy ? "Pairing…" : "Pair" }),
      ]),
    ]),
  ]);
}

function providerRow(p) {
  const now = Date.now();
  let dot = "off";
  let detail = "";
  let detailClass = "detail";
  let unverified = "";
  let detailTail = "";
  if (p.syncing) {
    dot = "busy";
    detail = "Proving with the notary…";
  } else if (p.optIn && p.homeLogin === "ambiguous") {
    // Several stored logins: nothing says which account wrote the logs.
    dot = "off";
    detail = `${p.homeDir} · several stored logins, not synced until only one is left`;
  } else if (p.optIn && p.homeLogin === "missing") {
    // A Claude home without its own login: its logs cannot be attributed to any account.
    dot = "off";
    detail = `${p.homeDir} · no login of its own, not synced`;
  } else if (p.optIn && !p.enabled) {
    dot = "off";
    detail = `${p.homeDir} · separate Claude login, off until you link it`;
  } else if (!p.enabled) {
    dot = "off";
    detail = "Paused";
  } else if (p.takesApiKey && !p.hasKey) {
    dot = "off";
    detail = "Add an API key to start";
  } else if (!p.credential.available) {
    dot = "warn";
    detail = p.credential.detail || "Not logged in";
  } else if (p.lastError) {
    dot = "bad";
    detail = p.lastError;
    detailClass = "detail err";
  } else if (p.lastSuccessAt) {
    dot = "ok";
    detail = p.lastCreditedTokens != null ? `+${formatTokens(p.lastCreditedTokens)} verified` : "synced";
    // Claimed tokens above the calibrated envelope: shown, never hidden, but never ranked.
    if (p.lastUnverifiedTokens > 0) unverified = ` (+${formatTokens(p.lastUnverifiedTokens)} unverified)`;
    detailTail = ` · ${timeAgo(p.lastSuccessAt, now)}${p.label ? ` · ${p.label}` : ""}`;
  } else {
    dot = "ok";
    detail = `${p.credential.source} · waiting for first proof`;
  }
  if (p.backoffUntil && Date.parse(p.backoffUntil) > now && !p.syncing) {
    detailTail += ` · retry in ${timeUntil(p.backoffUntil, now)}`;
  }

  const linkable = !p.optIn || p.enabled || p.credential.available;
  const toggle = el("label", { class: "switch", title: p.optIn && !p.enabled ? "Link this Claude login" : p.enabled ? "Pause syncing" : "Resume syncing" }, [
    el("input", {
      type: "checkbox",
      checked: p.enabled,
      disabled: !linkable,
      onchange: (e) => {
        // Linking an account to a profile cannot be undone on the server; ask once.
        if (p.optIn && e.target.checked && p.syncs === 0 && !confirm(`Link the Claude account logged in at ${p.homeDir} to your profile? Linking is permanent.`)) {
          e.target.checked = false;
          return;
        }
        call("set_enabled", { provider: p.id, enabled: e.target.checked }).catch((err) => alert(String(err)));
      },
    }),
    el("span"),
  ]);

  const rows = [
    el("div", { class: "row" }, [
      el("span", { class: `dot ${dot}` }),
      el("div", { class: "info" }, [
        el("div", { class: "title" }, [el("b", { text: p.name }), el("span", { class: "tier", text: p.takesApiKey && !p.hasKey ? "" : "" })]),
        el("div", { class: detailClass, title: detail + unverified + detailTail }, [
          detail,
          unverified ? el("span", { class: "dim", text: unverified }) : null,
          detailTail,
        ]),
      ]),
      p.boardTokens != null ? el("span", { class: "tokens", title: `${p.boardTokens} verified tokens on the board`, text: formatTokens(p.boardTokens) }) : null,
      p.takesApiKey
        ? el("button", {
            class: "btn sm",
            type: "button",
            text: p.hasKey ? "Key" : "Add key",
            onclick: () => {
              if (openKeyForms.has(p.id)) openKeyForms.delete(p.id);
              else openKeyForms.add(p.id);
              render();
            },
          })
        : null,
      toggle,
    ]),
  ];

  if (p.takesApiKey && openKeyForms.has(p.id)) {
    const input = el("input", { type: "password", placeholder: p.hasKey ? "Replace stored key" : `${p.name} API key`, autocomplete: "off" });
    const save = async () => {
      keyErrors = { ...keyErrors, [p.id]: null };
      try {
        await call("set_key", { provider: p.id, key: input.value });
        openKeyForms.delete(p.id);
        if (input.value.trim()) invoke("sync_now", { provider: p.id }).catch(() => {});
      } catch (e) {
        keyErrors = { ...keyErrors, [p.id]: String(e) };
      }
      render();
    };
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") save();
    });
    setTimeout(() => input.focus(), 0);
    rows.push(
      el("div", { class: "keyform" }, [
        input,
        el("button", { class: "btn sm primary", type: "button", text: "Save", onclick: save }),
        p.hasKey ? el("button", { class: "btn sm danger", type: "button", text: "Remove", onclick: () => { input.value = ""; save(); } }) : null,
      ]),
    );
    if (keyErrors[p.id]) rows.push(el("div", { class: "error", style: "padding: 0 14px 10px 32px", text: keyErrors[p.id] }));
    rows.push(el("div", { class: "hint", style: "padding: 0 14px 10px 32px", text: "Stored with owner-only permissions on this machine and only used inside the encrypted proof session." }));
  }
  return rows;
}

function pairedView() {
  const now = Date.now();
  const syncing = Boolean(status.syncing);
  const nextLabel = syncing ? "Syncing…" : status.nextRoundAt ? `Next sync in ${timeUntil(status.nextRoundAt, now)}` : "Waiting…";
  const lastLabel = status.lastRoundAt ? `Last round ${timeAgo(status.lastRoundAt, now)}` : "No round yet";

  const hero = el("div", { class: "card" }, [
    el("div", { class: "hero" }, [
      el("div", { class: "who" }, [
        el("div", { class: "name", text: status.device.displayName || `@${status.device.username}` }),
        el("div", { class: "sub", text: `@${status.device.username} · ${lastLabel} · ${nextLabel}` }),
      ]),
      el("div", { class: "total" }, [
        el("div", { class: "n", text: status.totalTokens != null ? formatTokens(status.totalTokens) : "—" }),
        el("div", { class: "l", text: "tokens on the board" }),
      ]),
    ]),
    el("div", { class: "row", style: "justify-content:flex-end; gap:8px" }, [
      el("button", { class: "btn", type: "button", text: "Dashboard ↗", onclick: () => invoke("open_web", { path: "/dashboard" }).catch((e) => alert(String(e))) }),
      el("button", { class: "btn primary", type: "button", disabled: syncing, text: syncing ? "Syncing…" : "Sync now", onclick: () => invoke("sync_now", { provider: null }).catch((e) => alert(String(e))) }),
    ]),
  ]);

  const providers = el("div", { class: "card" }, [
    el("div", { class: "card-head" }, [el("h2", { text: "Providers" }), el("span", { class: "dim", text: `every ${Math.round(status.intervalSeconds / 60)} min` })]),
    ...status.providers.flatMap(providerRow),
  ]);

  const unlink = el("div", { style: "display:flex; justify-content:space-between; align-items:center; padding: 0 2px" }, [
    el("span", { class: "dim", text: `Device ${status.device.deviceId.slice(0, 10)}… · ${status.server}` }),
    el("button", {
      class: "link",
      type: "button",
      text: "Unlink device",
      onclick: async () => {
        if (!confirm("Unlink this device? It stops syncing until paired again; nothing on the board is removed.")) return;
        await call("unpair").catch((e) => alert(String(e)));
      },
    }),
  ]);

  return [hero, providers, unlink];
}

function render() {
  if (!status) return;
  main.replaceChildren(...[].concat(status.paired ? pairedView() : pairingView()));
  autostart.checked = status.autostart;
  version.textContent = `v${status.version}`;
  btnDashboard.hidden = !status.paired;
}

// ---- wiring ------------------------------------------------------------------------------------

autostart.addEventListener("change", (e) => call("set_autostart", { enabled: e.target.checked }).catch((err) => alert(String(err))));
btnDashboard.addEventListener("click", () => invoke("open_web", { path: "/dashboard" }).catch((e) => alert(String(e))));
btnHide.addEventListener("click", () => invoke("hide_window"));
btnQuit.addEventListener("click", () => invoke("quit"));
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") invoke("hide_window");
});
// Right-click and text selection are noise in a tray popover.
document.addEventListener("contextmenu", (e) => e.preventDefault());

listen("status", (event) => {
  status = event.payload;
  render();
});

invoke("get_status")
  .then((s) => {
    status = s;
    render();
  })
  .catch((e) => {
    main.replaceChildren(el("div", { class: "error", text: `Cannot load status: ${e}` }));
  });

// Keep relative times fresh while visible.
setInterval(() => {
  if (status && document.visibilityState === "visible") render();
}, 15_000);
