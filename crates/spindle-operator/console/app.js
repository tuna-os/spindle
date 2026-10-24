// Spindle Operator console (#458): operational state, changes, investigations, access, rooms and audit.
//
// Reads only /_spindle/operator/v1. Holds no credential: the session is an
// HttpOnly cookie the script cannot see, and the CSRF token it sends on
// writes comes from GET /session. Every piece of server data reaches the
// page through textContent, never as markup.
"use strict";

const API = "/_spindle/operator/v1";
const STALE_PROBE_MS = 5 * 60 * 1000;

const state = {
  session: null,
  view: null,
  viewError: null,
};

// ---- small DOM helpers --------------------------------------------------

function h(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

// `append`, skipping the null and false a section returns when it has
// nothing to say: `Element.append(null)` would print the word "null".
function put(parent, ...nodes) {
  parent.append(...nodes.flat().filter((node) => node !== null && node !== undefined && node !== false));
}

function badge(text, tone) {
  return h("span", { class: `badge ${tone || "info"}` }, text);
}

function panel(tone, ...children) {
  return h("div", { class: `panel ${tone}` }, ...children);
}

function table(caption, headers, rows, empty) {
  if (rows.length === 0) {
    return h("p", { class: "muted" }, empty || "Nothing to show.");
  }
  return h(
    "div",
    { class: "table-wrap", role: "region", "aria-label": caption, tabindex: "0" },
    h(
      "table",
      {},
      h("caption", {}, caption),
      h("thead", {}, h("tr", {}, headers.map((head) => h("th", { scope: "col", class: head.num ? "num" : null }, head.label || head)))),
      h("tbody", {}, rows.map((cells) => h("tr", {}, cells.map((cell, index) =>
        index === 0 ? h("th", { scope: "row" }, cell) : h("td", { class: headers[index].num ? "num" : null }, cell))))),
    ),
  );
}

function facts(pairs) {
  return h("dl", { class: "facts" }, pairs.flatMap(([term, value]) => [h("dt", {}, term), h("dd", {}, value ?? "—")]));
}

function when(ms) {
  if (!ms) return "—";
  const date = new Date(ms);
  const text = date.toLocaleString();
  const ago = Date.now() - ms;
  let relative;
  if (ago < 60_000) relative = "just now";
  else if (ago < 3_600_000) relative = `${Math.round(ago / 60_000)} min ago`;
  else if (ago < 86_400_000) relative = `${Math.round(ago / 3_600_000)} h ago`;
  else relative = `${Math.round(ago / 86_400_000)} days ago`;
  return h("time", { datetime: date.toISOString(), title: text }, `${text} (${relative})`);
}

function announce(message) {
  const announcer = document.getElementById("announcer");
  announcer.textContent = "";
  // A fresh text node in a later task is what screen readers announce.
  setTimeout(() => { announcer.textContent = message; }, 50);
}

// ---- API ----------------------------------------------------------------

class ApiFailure extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function api(path, options = {}) {
  let response;
  try {
    response = await fetch(API + path, {
      credentials: "same-origin",
      headers: { Accept: "application/json", ...(options.headers || {}) },
      ...options,
    });
  } catch {
    throw new ApiFailure(0, "operator_unreachable", "The operator service could not be reached. Check that it is running and that this network can reach it.");
  }
  let body = null;
  try { body = await response.json(); } catch { /* an empty or non-JSON body */ }
  if (!response.ok) {
    const error = body && body.error ? body.error : {};
    throw new ApiFailure(response.status, error.code || "http_" + response.status, error.message || `The operator answered ${response.status}.`);
  }
  return body;
}

async function write(path, body, headers = {}) {
  const key = (crypto.randomUUID && crypto.randomUUID()) || String(Date.now()) + Math.random();
  return api(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": state.session.csrf_token,
      "Idempotency-Key": key,
      ...headers,
    },
    body: JSON.stringify(body || {}),
  });
}

function hasRole(role) {
  const roles = (state.session && state.session.principal && state.session.principal.roles) || [];
  return roles.includes(role);
}

function failurePanel(error, what) {
  const lines = [h("p", {}, h("strong", {}, `${what} could not be loaded.`), " ", error.message)];
  const advice = {
    homeserver_unreachable: "The homeserver is down or unreachable from the operator. The Now page shows the last probe of each connection.",
    homeserver_refused: "The homeserver refused the admin credential this connection names. Check that the credential is current and carries admin rights.",
    homeserver_error: "The homeserver answered with an error. Its logs will say more.",
    no_credential: "Give the connection a credential reference (for example env:SPINDLE_ADMIN_TOKEN) to browse it here.",
    credential_unavailable: "The operator could not read the secret the connection refers to. Check the operator's environment or mounted secret.",
    operator_unreachable: "Nothing on this page can be trusted until the operator answers again.",
    forbidden: "Your roles do not allow this.",
  }[error.code];
  if (advice) lines.push(h("p", {}, advice));
  return panel(error.code === "forbidden" ? "warn" : "bad", ...lines);
}

// ---- global state banner ------------------------------------------------

function findingValue(view, prefix) {
  for (const deployment of view.deployments || []) {
    const findings = (deployment.latest_assessment && deployment.latest_assessment.findings) || [];
    const found = findings.find((finding) => finding.code === prefix || finding.code.startsWith(prefix + "."));
    if (found) return { deployment: deployment.deployment.name, finding: found };
  }
  return null;
}

function renderGlobalState() {
  const region = document.getElementById("global-state");
  region.replaceChildren();
  if (state.viewError) {
    region.append(h("p", {}, badge("Unknown", "bad"), " ", state.viewError.message));
    return;
  }
  const view = state.view;
  if (!view) {
    region.append(h("p", {}, "Loading deployment state…"));
    return;
  }
  const authority = findingValue(view, "authority");
  const writes = findingValue(view, "writes");
  const active = (view.deployments || []).filter((d) => d.active_operation);
  const attention = view.needs_attention || [];
  const unreachable = (view.connections || []).filter((c) => c.last_probe && !c.last_probe.reachable);
  region.append(
    h("p", {}, h("strong", {}, "Authority: "), authority ? `${authority.finding.summary} (${authority.deployment})` : "not reported by any assessment yet"),
    h("p", {}, h("strong", {}, "Writes: "), writes ? `${writes.finding.summary} (${writes.deployment})` : "not reported by any assessment yet"),
    h("p", {}, h("strong", {}, "Active change: "), active.length ? active.map((d) => `${d.active_operation.action} on ${d.deployment.name} (${d.active_operation.state.replaceAll("_", " ")})`).join("; ") : "none"),
    h("p", {}, h("strong", {}, "Needs a person: "), attention.length ? badge(String(attention.length), "warn") : "nothing"),
    h("p", {}, h("strong", {}, "Homeservers: "), unreachable.length ? badge(`${unreachable.length} unreachable`, "bad") : "no failed probe"),
  );
}

async function refreshView() {
  try {
    state.view = await api("/view");
    state.viewError = null;
  } catch (error) {
    state.viewError = error;
  }
  renderGlobalState();
}

// ---- pages --------------------------------------------------------------

function pageHeading(text) {
  const heading = h("h1", { tabindex: "-1" }, text);
  return heading;
}

function deploymentName(view, id) {
  const found = ((view && view.deployments) || []).find((d) => d.deployment.id === id);
  return found ? found.deployment.name : id;
}

function nextSafeAction(view) {
  const attention = view.needs_attention || [];
  if (attention.length) {
    const op = attention[0];
    const why = {
      awaiting_approval: "is waiting for an approver who did not request it",
      attention_required: "was interrupted mid-change; someone must check whether the change happened, then resume it as applied or not applied",
      failed: "failed; read its evidence before resuming or rolling it back",
      paused: "is paused; resume it or roll it back",
    }[op.state] || `is ${op.state}`;
    return panel("warn", h("p", {}, h("strong", {}, "Next safe action: "), `Operation ${op.id} on ${deploymentName(view, op.deployment)} ${why}.`), op.reason ? h("p", {}, `Reason recorded: ${op.reason}`) : null);
  }
  const blockers = [];
  for (const deployment of view.deployments || []) {
    for (const finding of (deployment.latest_assessment && deployment.latest_assessment.findings) || []) {
      if (finding.severity === "blocker") blockers.push(`${deployment.deployment.name}: ${finding.summary}`);
    }
  }
  if (blockers.length) {
    return panel("bad", h("p", {}, h("strong", {}, "Next safe action: "), "Resolve the blocking findings before starting any change."), h("ul", {}, blockers.map((text) => h("li", {}, text))));
  }
  const connections = view.connections || [];
  const down = connections.filter((c) => c.last_probe && !c.last_probe.reachable);
  if (down.length) {
    return panel("bad", h("p", {}, h("strong", {}, "Next safe action: "), `Investigate ${down.map((c) => c.name).join(", ")}: the last probe could not reach it. Start no change that depends on it.`));
  }
  const stale = connections.filter((c) => !c.last_probe || Date.now() - c.last_probe.at > STALE_PROBE_MS);
  if (stale.length) {
    return panel("info", h("p", {}, h("strong", {}, "Next safe action: "), `Probe ${stale.map((c) => c.name).join(", ")}: there is no recent probe, so this page cannot say whether it is up.`));
  }
  if (connections.length === 0) {
    return panel("info", h("p", {}, h("strong", {}, "Next safe action: "), "Add a connection for each homeserver so this page can watch it."));
  }
  return panel("ok", h("p", {}, h("strong", {}, "Next safe action: "), "Nothing needs doing. Every connection answered its last probe and no operation is waiting."));
}

async function probe(connection, button) {
  button.disabled = true;
  button.textContent = "Probing…";
  try {
    const result = await write(`/connections/${encodeURIComponent(connection.id)}:probe`, {});
    announce(`${connection.name} ${result.last_probe && result.last_probe.reachable ? "answered" : "did not answer"} the probe.`);
  } catch (error) {
    announce(`Probe of ${connection.name} failed: ${error.message}`);
  }
  await refreshView();
  await render();
}

function pageNow(main) {
  put(main, pageHeading("Now"));
  if (state.viewError) {
    put(main, failurePanel(state.viewError, "The deployment view"));
    return;
  }
  const view = state.view;
  put(main, nextSafeAction(view));

  put(main, h("h2", {}, "Needs a person"));
  put(main, table(
    "Operations that need a person",
    ["Operation", "Deployment", "State", "Reason"],
    (view.needs_attention || []).map((op) => [h("a", { class: "mono", href: `#/changes/${encodeURIComponent(op.id)}` }, op.id), deploymentName(view, op.deployment), badge(op.state.replaceAll("_", " "), op.state === "failed" ? "bad" : "warn"), op.reason || "—"]),
    "No operation is waiting for a person.",
  ));

  put(main, h("h2", {}, "Deployments"));
  put(main, table(
    "Deployments",
    ["Deployment", "Driver", "Active change", "Latest assessment"],
    (view.deployments || []).map((d) => {
      const assessment = d.latest_assessment;
      let summary = "never assessed";
      if (assessment) {
        const blockers = assessment.findings.filter((f) => f.severity === "blocker").length;
        const warnings = assessment.findings.filter((f) => f.severity === "warning").length;
        summary = h("span", {}, blockers ? badge(`${blockers} blocking`, "bad") : badge("no blockers", "ok"), " ", warnings ? `${warnings} warnings, ` : "", "assessed ", when(assessment.created_at));
      }
      return [d.deployment.name, d.deployment.driver, d.active_operation ? h("a", { href: `#/changes/${encodeURIComponent(d.active_operation.id)}` }, `${d.active_operation.action} (${d.active_operation.state.replaceAll("_", " ")})`) : "none", summary];
    }),
    "No deployment is registered yet.",
  ));

  put(main, h("h2", {}, "Homeserver connections"));
  const canProbe = hasRole("operator");
  put(main, table(
    "Homeserver connections and their last probe",
    ["Connection", "Address", "Last probe", "Result", { label: "Latency", num: true }, "Action"],
    (view.connections || []).map((c) => {
      const p = c.last_probe;
      const result = !p ? badge("never probed", "info") : p.reachable ? badge(`reachable (${p.status})`, "ok") : badge(p.detail || `unreachable (${p.status ?? "no answer"})`, "bad");
      const button = canProbe ? h("button", { type: "button" }, "Probe now") : h("span", { class: "muted" }, "operator role needed");
      if (canProbe) button.addEventListener("click", () => probe(c, button));
      return [c.name, h("span", { class: "mono" }, c.base_url), p ? when(p.at) : "—", result, p ? `${p.latency_ms} ms` : "—", button];
    }),
    "No connection is registered yet.",
  ));
}

function connectionsWithCredential() {
  return ((state.view && state.view.connections) || []).filter((c) => c.credential);
}

function connectionPicker(current, onChange) {
  const options = connectionsWithCredential();
  if (options.length <= 1) return null;
  const select = h("select", { id: "connection" }, options.map((c) => h("option", { value: c.id, selected: c.id === current }, c.name)));
  select.addEventListener("change", () => onChange(select.value));
  return h("label", { for: "connection" }, "Homeserver", select);
}

function needsConnection(main) {
  if (state.viewError) {
    put(main, failurePanel(state.viewError, "The list of connections"));
    return true;
  }
  if (connectionsWithCredential().length === 0) {
    put(main, panel("info", h("p", {}, "No connection has an admin credential, so there is nothing to browse. Add a connection whose credential is a reference to a homeserver admin token, for example env:SPINDLE_ADMIN_TOKEN. The token stays in the operator; this page never sees it.")));
    return true;
  }
  return false;
}

function searchForm(label, params, extra, go) {
  const input = h("input", { id: "search", type: "search", value: params.get("q") || "", autocomplete: "off" });
  const form = h("form", { class: "search", role: "search" },
    h("label", { for: "search" }, label, input),
    extra,
    h("button", { type: "submit" }, "Search"));
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    go(input.value.trim());
  });
  return form;
}

function pager(next, params, base) {
  if (next === null || next === undefined) return null;
  const query = new URLSearchParams(params);
  query.set("from", String(next));
  return h("p", { class: "pager" }, h("a", { href: `${base}?${query}` }, "Next page"));
}

function personFlags(person) {
  const flags = [];
  if (person.admin) flags.push(badge("admin", "info"));
  if (person.deactivated) flags.push(badge("deactivated", "bad"));
  if (person.locked) flags.push(badge("locked", "warn"));
  if (person.suspended) flags.push(badge("suspended", "warn"));
  if (person.erased) flags.push(badge("erased", "bad"));
  if (flags.length === 0) flags.push(badge("active", "ok"));
  return h("span", {}, flags.flatMap((flag, i) => (i ? [" ", flag] : [flag])));
}

function unavailableNotice(unavailable) {
  if (!unavailable || unavailable.length === 0) return null;
  return panel("warn", h("p", {}, h("strong", {}, "Part of this page could not be loaded.")), h("ul", {}, unavailable.map((u) => h("li", {}, `${u.part.replaceAll("_", " ")}: ${u.message}`))));
}

async function pagePeople(main, route) {
  put(main, pageHeading("People & access"));
  if (needsConnection(main)) return;
  const connection = route.parts[0] || connectionsWithCredential()[0].id;
  if (route.parts[1]) return pagePerson(main, connection, route.parts[1]);
  const params = route.params;
  const base = `#/people/${encodeURIComponent(connection)}`;
  put(main, searchForm("User ID or display name", params, connectionPicker(connection, (id) => { location.hash = `#/people/${encodeURIComponent(id)}`; }), (q) => {
    location.hash = q ? `${base}?q=${encodeURIComponent(q)}` : base;
  }));
  const status = h("p", { class: "muted" }, "Loading people…");
  put(main, status);
  const query = new URLSearchParams();
  if (params.get("q")) query.set("search", params.get("q"));
  if (params.get("from")) query.set("from", params.get("from"));
  try {
    const result = await api(`/connections/${encodeURIComponent(connection)}/people?${query}`);
    status.textContent = `${result.total ?? result.people.length} accounts${params.get("q") ? ` match “${params.get("q")}”` : ""}.`;
    put(main, table(
      "Accounts",
      ["Account", "Display name", "Status", "Last seen"],
      result.people.map((p) => [
        h("a", { href: `${base}/${encodeURIComponent(p.name)}`, class: "mono" }, p.name),
        p.displayname || "—",
        personFlags(p),
        p.last_seen_ts ? when(p.last_seen_ts) : "not recorded",
      ]),
      "No account matches.",
    ));
    put(main, pager(result.next, Object.fromEntries(params), base));
    announce(status.textContent);
  } catch (error) {
    status.remove();
    put(main, failurePanel(error, "People"));
  }
}

async function pagePerson(main, connection, userId) {
  main.querySelector("h1").textContent = userId;
  put(main, h("p", {}, h("a", { href: `#/people/${encodeURIComponent(connection)}` }, "Back to people")));
  try {
    const result = await api(`/connections/${encodeURIComponent(connection)}/people/${encodeURIComponent(userId)}`);
    const p = result.person;
    const restricted = Boolean(result.restricted);
    put(main, unavailableNotice(result.unavailable));
    put(main, h("h2", {}, "Account"));
    put(main, facts([
      ["User ID", h("span", { class: "mono" }, p.name)],
      ["Display name", p.displayname || "—"],
      ["Status", personFlags(p)],
      ["Created", p.creation_ts ? when(p.creation_ts) : "not recorded"],
      ["Email addresses", restricted ? "shown to the operator role only" : (p.threepids || []).filter((t) => t.medium === "email").map((t) => t.address).join(", ") || "none"],
      ["Linked identities", restricted ? "shown to the operator role only" : (p.external_ids || []).map((e) => `${e.auth_provider}: ${e.external_id}`).join(", ") || "none"],
    ]));
    put(main, h("h2", {}, "Devices"));
    put(main, result.devices === null ? h("p", { class: "muted" }, "Devices could not be loaded.") : table(
      "Devices",
      ["Device", "Name", "Last seen", "Last address"],
      result.devices.map((d) => [h("span", { class: "mono" }, d.device_id), d.display_name || "—", d.last_seen_ts ? when(d.last_seen_ts) : "not recorded", restricted ? "operator role only" : d.last_seen_ip || "not recorded"]),
      "This account has no devices.",
    ));
    put(main, h("h2", {}, "Rooms"));
    if (result.joined_rooms === null) {
      put(main, h("p", { class: "muted" }, "Rooms could not be loaded."));
    } else if (result.joined_rooms.length === 0) {
      put(main, h("p", { class: "muted" }, "Not joined to any room."));
    } else {
      put(main, h("ul", {}, result.joined_rooms.map((room) => h("li", {}, h("a", { class: "mono", href: `#/rooms/${encodeURIComponent(connection)}/${encodeURIComponent(room)}` }, room)))));
    }
    put(main, panel("info", h("p", {}, "Changes to this account (lock, deactivate, sign out devices) are not offered here yet. They will run as operations with a plan, approval and audit record.")));
    announce(`Loaded ${p.name}.`);
  } catch (error) {
    put(main, failurePanel(error, "This account"));
  }
}

async function pageRooms(main, route) {
  put(main, pageHeading("Rooms & safety"));
  if (needsConnection(main)) return;
  const connection = route.parts[0] || connectionsWithCredential()[0].id;
  if (route.parts[1]) return pageRoom(main, connection, route.parts[1]);
  const params = route.params;
  const base = `#/rooms/${encodeURIComponent(connection)}`;
  const order = h("select", { id: "order" },
    [["name", "Name"], ["joined_members", "Members"], ["joined_local_members", "Local members"], ["state_events", "State size"]]
      .map(([value, label]) => h("option", { value, selected: (params.get("order") || "name") === value }, label)));
  put(main, searchForm("Name, alias or room ID", params, [
    connectionPicker(connection, (id) => { location.hash = `#/rooms/${encodeURIComponent(id)}`; }),
    h("label", { for: "order" }, "Order by", order),
  ], (q) => {
    const query = new URLSearchParams();
    if (q) query.set("q", q);
    query.set("order", order.value);
    location.hash = `${base}?${query}`;
  }));

  const reports = h("section", { "aria-labelledby": "reports-heading" }, h("h2", { id: "reports-heading" }, "Recent reports"), h("p", { class: "muted" }, "Loading reports…"));
  const roomsSection = h("section", { "aria-labelledby": "rooms-heading" }, h("h2", { id: "rooms-heading" }, "Rooms"), h("p", { class: "muted" }, "Loading rooms…"));
  put(main, reports, roomsSection);

  const query = new URLSearchParams();
  if (params.get("q")) query.set("search", params.get("q"));
  if (params.get("from")) query.set("from", params.get("from"));
  if (params.get("order")) query.set("order_by", params.get("order"));
  const [roomsResult, reportsResult] = await Promise.allSettled([
    api(`/connections/${encodeURIComponent(connection)}/rooms?${query}`),
    api(`/connections/${encodeURIComponent(connection)}/reports?limit=10`),
  ]);
  reports.lastChild.remove();
  if (reportsResult.status === "fulfilled") {
    put(reports, reportTable(reportsResult.value.reports, connection, "Most recent reports"));
  } else {
    put(reports, failurePanel(reportsResult.reason, "Reports"));
  }
  roomsSection.lastChild.remove();
  if (roomsResult.status === "fulfilled") {
    const result = roomsResult.value;
    put(roomsSection, h("p", { class: "muted" }, `${result.total ?? result.rooms.length} rooms${params.get("q") ? ` match “${params.get("q")}”` : ""}.`));
    put(roomsSection, table(
      "Rooms on this page",
      ["Room", { label: "Members", num: true }, { label: "Local", num: true }, "Encryption", "Directory", "Version"],
      result.rooms.map((r) => [
        h("span", {}, h("a", { href: `${base}/${encodeURIComponent(r.room_id)}` }, r.name || r.canonical_alias || r.room_id), r.name || r.canonical_alias ? h("span", { class: "mono muted" }, " ", r.room_id) : null),
        String(r.joined_members ?? "—"),
        String(r.joined_local_members ?? "—"),
        r.encryption ? badge("encrypted", "ok") : badge("not encrypted", "warn"),
        r.public ? "published" : "not published",
        r.version || "—",
      ]),
      "No room matches.",
    ));
    put(roomsSection, pager(result.next, Object.fromEntries(params), base));
    announce(`${result.rooms.length} rooms shown.`);
  } else {
    put(roomsSection, failurePanel(roomsResult.reason, "Rooms"));
  }
}

function reportTable(reports, connection, caption) {
  return table(
    caption,
    ["Report", "Filed", "Room", "Reported user", "Reason", { label: "Score", num: true }],
    reports.map((r) => [
      `#${r.id}`,
      when(r.received_ts),
      r.room_id ? h("a", { href: `#/rooms/${encodeURIComponent(connection)}/${encodeURIComponent(r.room_id)}` }, r.name || r.room_id) : "—",
      r.sender ? h("a", { class: "mono", href: `#/people/${encodeURIComponent(connection)}/${encodeURIComponent(r.sender)}` }, r.sender) : "—",
      r.reason || "no reason given",
      r.score === null || r.score === undefined ? "—" : String(r.score),
    ]),
    "No reports.",
  );
}

async function pageRoom(main, connection, roomId) {
  main.querySelector("h1").textContent = roomId;
  put(main, h("p", {}, h("a", { href: `#/rooms/${encodeURIComponent(connection)}` }, "Back to rooms")));
  try {
    const result = await api(`/connections/${encodeURIComponent(connection)}/rooms/${encodeURIComponent(roomId)}`);
    const r = result.room;
    if (r.name) main.querySelector("h1").textContent = r.name;
    put(main, unavailableNotice(result.unavailable));
    const blocked = result.block && result.block.block;
    put(main, blocked
      ? panel("bad", h("p", {}, h("strong", {}, "Blocked. "), `Local users cannot join this room. Blocked by ${result.block.user_id || "an administrator"}.`))
      : result.block ? panel("ok", h("p", {}, "Not blocked.")) : null);
    put(main, h("h2", {}, "Room"));
    put(main, facts([
      ["Room ID", h("span", { class: "mono" }, r.room_id)],
      ["Alias", r.canonical_alias || "none"],
      ["Topic", r.topic || "none"],
      ["Members", `${r.joined_members} joined, ${r.joined_local_members} local, on ${r.joined_local_devices ?? "?"} local devices`],
      ["Encryption", r.encryption ? `${r.encryption}` : "not encrypted"],
      ["Who may join", r.join_rules || "not set"],
      ["History visible to", r.history_visibility || "not set"],
      ["Guests", r.guest_access || "not set"],
      ["Room directory", r.public ? "published" : "not published"],
      ["Federates", r.federatable ? "yes" : "no (local only)"],
      ["Version", r.version || "—"],
      ["Creator", r.creator ? h("a", { class: "mono", href: `#/people/${encodeURIComponent(connection)}/${encodeURIComponent(r.creator)}` }, r.creator) : "—"],
      ["State entries", String(r.state_events ?? "—")],
    ]));
    put(main, h("h2", {}, "Reports about this room"));
    put(main, result.reports === null ? h("p", { class: "muted" }, "Reports could not be loaded.") : reportTable(result.reports, connection, "Reports about this room"));
    put(main, h("h2", {}, "Deletion tasks"));
    put(main, result.tasks === null ? h("p", { class: "muted" }, "Tasks could not be loaded.") : table(
      "Deletion and purge tasks",
      ["Task", "Action", "Status", "When", "Error"],
      result.tasks.map((t) => [h("span", { class: "mono" }, t.id), t.action.replaceAll("_", " "), badge(t.status, t.status === "failed" ? "bad" : t.status === "complete" ? "ok" : "info"), when(t.timestamp_ms), t.error || "—"]),
      "No deletion has been requested for this room.",
    ));
    put(main, h("h2", {}, "Members"));
    if (result.members === null) {
      put(main, h("p", { class: "muted" }, "Members could not be loaded."));
    } else {
      const shown = result.members.members;
      put(main, h("details", {},
        h("summary", {}, `${result.members.total} joined members${shown.length < result.members.total ? ` (first ${shown.length} shown)` : ""}`),
        h("ul", {}, shown.map((m) => h("li", {}, h("a", { class: "mono", href: `#/people/${encodeURIComponent(connection)}/${encodeURIComponent(m)}` }, m))))));
    }
    put(main, panel("info", h("p", {}, "Blocking, deleting and quarantining are not offered here yet. They will run as operations with a plan, approval and audit record.")));
    announce(`Loaded room ${r.name || r.room_id}.`);
  } catch (error) {
    put(main, failurePanel(error, "This room"));
  }
}

function operationTone(value) {
  if (value === "succeeded" || value === "rolled_back" || value === "completed" || value === "compensated") return "ok";
  if (value === "failed") return "bad";
  if (value === "awaiting_approval" || value === "attention_required" || value === "paused") return "warn";
  return "info";
}

function operationBadge(value) {
  return badge(value.replaceAll("_", " "), operationTone(value));
}

function terminalOperation(operation) {
  return ["succeeded", "cancelled", "rolled_back"].includes(operation.state);
}

function operationTable(operations, caption, empty) {
  return table(
    caption,
    ["Operation", "Deployment", "Action", "State", "Requested by", "Updated"],
    operations.map((operation) => [
      h("a", { class: "mono", href: `#/changes/${encodeURIComponent(operation.id)}` }, operation.id),
      deploymentName(state.view, operation.deployment),
      operation.action,
      operationBadge(operation.state),
      h("span", { class: "mono" }, operation.requested_by),
      when(operation.updated_at),
    ]),
    empty,
  );
}

async function pageChanges(main, route) {
  put(main, pageHeading("Changes"));
  if (route.parts[0]) return pageOperation(main, route.parts[0]);
  put(main, h("p", {}, "Every change is a planned operation. Open one to inspect its risk, scope, approvals, progress, evidence and recovery path."));
  const loading = h("p", { class: "muted" }, "Loading operations…");
  put(main, loading);
  try {
    const result = await api("/operations");
    loading.remove();
    const current = result.items.filter((operation) => !terminalOperation(operation));
    const history = result.items.filter(terminalOperation);
    put(main, h("h2", {}, "Active and needs action"));
    put(main, operationTable(current, "Active operations and operations that need a person", "No operation is active or waiting for a person."));
    put(main, h("h2", {}, "Completed"));
    put(main, operationTable(history, "Completed operations", "No operation has completed yet."));
    announce(`${result.items.length} operations loaded.`);
  } catch (error) {
    loading.remove();
    put(main, failurePanel(error, "Operations"));
  }
}

function recoveryAdvice(operation) {
  const boundary = operation.steps.find((step) => step.state === "completed" && step.mutation && !step.compensable);
  const advice = {
    running: "This operation is running. Pause before investigating a surprising result; cancel stops future steps without undoing completed ones.",
    awaiting_approval: "An independent approver must compare the plan and evidence with the requested scope, then type the required confirmation.",
    paused: boundary ? `This operation is paused after the irreversible step “${boundary.name}”. Recovery must move forward in a new operation.` : "This operation is paused. Resume after checking the open step, or roll back completed compensable steps.",
    attention_required: "The engine cannot tell whether the interrupted mutation happened. Verify the target, then resume and record “applied” or “not applied”.",
    failed: boundary ? `The operation failed after the irreversible step “${boundary.name}”. Inspect the failure evidence and recover with a new forward operation.` : "Inspect the failed step and its evidence. After correcting the cause, resume it or roll back completed changes.",
    rolling_back: "Rollback is in progress. Completed compensations are recorded below.",
    succeeded: "The plan completed. If the result must change, create a new forward operation; do not rewrite this history.",
    cancelled: "The operation was cancelled. Completed steps were not undone.",
    rolled_back: "Every compensable completed step was undone in reverse order.",
  }[operation.state];
  return panel(operation.state === "failed" ? "bad" : ["awaiting_approval", "attention_required", "paused"].includes(operation.state) ? "warn" : "info",
    h("p", {}, h("strong", {}, "Recovery action: "), advice || "Review the operation state before acting."));
}

async function runOperationAction(operation, verb, body, button, errors) {
  button.disabled = true;
  errors.replaceChildren();
  try {
    await write(
      `/operations/${encodeURIComponent(operation.id)}:${verb}`,
      body,
      { "If-Match": `"${operation.version}"` },
    );
    announce(`${operation.id}: ${verb.replaceAll("_", " ")} accepted.`);
    await refreshView();
    await render();
  } catch (error) {
    button.disabled = false;
    put(errors, failurePanel(error, `The ${verb.replaceAll("_", " ")} action`));
    announce(`${operation.id}: ${verb.replaceAll("_", " ")} failed. ${error.message}`);
  }
}

function actionButton(operation, verb, label, errors, body = {}) {
  const button = h("button", { type: "button" }, label);
  button.addEventListener("click", () => runOperationAction(operation, verb, body, button, errors));
  return button;
}

function operationControls(operation) {
  const section = h("section", { "aria-labelledby": "operation-actions-heading" });
  put(section, h("h2", { id: "operation-actions-heading" }, "Safe actions"));
  const errors = h("div", { "aria-live": "assertive" });
  if (!hasRole("operator") && !hasRole("approver")) {
    put(section, h("p", { class: "muted" }, "An operator or approver role is needed to act."));
    return section;
  }
  const actions = h("div", { class: "actions" });
  if (hasRole("operator")) {
    if (["running", "awaiting_approval"].includes(operation.state)) {
      put(actions, actionButton(operation, "pause", "Pause before next step", errors));
    }
    if (["paused", "failed"].includes(operation.state)) {
      put(actions, actionButton(operation, "resume", "Resume from open step", errors));
    }
    if (operation.state === "attention_required") {
      put(
        section,
        panel("warn",
          h("p", {}, h("strong", {}, "Verify the interrupted change before choosing."), " These two actions become part of the immutable audit trail."),
          h("div", { class: "actions" },
            actionButton(operation, "resume", "Change was applied", errors, { resolution: "applied" }),
            actionButton(operation, "resume", "Change was not applied", errors, { resolution: "not_applied" }),
          )),
      );
    }
    const rollbackBoundary = operation.steps.some((step) => step.state === "completed" && step.mutation && !step.compensable);
    if (["paused", "failed", "attention_required", "awaiting_approval"].includes(operation.state) && !rollbackBoundary) {
      put(actions, actionButton(operation, "rollback", "Roll back completed changes", errors));
    }
    if (!terminalOperation(operation) && operation.state !== "rolling_back") {
      put(actions, actionButton(operation, "cancel", "Cancel without undo", errors));
    }
  }
  put(section, actions);

  if (operation.state === "awaiting_approval") {
    const step = operation.steps.find((candidate) => candidate.state === "pending");
    const principal = state.session.principal;
    if (!hasRole("approver")) {
      put(section, h("p", { class: "muted" }, "An independent approver role is needed for the waiting step."));
    } else if (operation.requested_by === principal.subject) {
      put(section, h("p", { class: "muted" }, "You requested this operation, so you cannot approve it."));
    } else if (step) {
      const typed = Boolean(state.view && state.view.policy && state.view.policy.typed_confirmation);
      const expected = `${operation.id}/${step.name}`;
      const input = typed ? h("input", { id: "approval-confirmation", required: true, autocomplete: "off", "aria-describedby": "approval-help" }) : null;
      const confirmation = typed
        ? [
          h("label", { for: "approval-confirmation" }, "Typed confirmation", input),
          h("p", { id: "approval-help", class: "muted" }, "Type ", h("code", {}, expected), " after reviewing the plan and evidence."),
        ]
        : [h("p", { class: "muted" }, "Review the plan and evidence before recording approval.")];
      const form = h("form", { class: "confirm" },
        confirmation,
        h("button", { type: "submit" }, `Approve “${step.name}”`));
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const button = form.querySelector("button");
        button.disabled = true;
        errors.replaceChildren();
        try {
          const body = { step: step.index };
          if (typed) body.confirmation = input.value;
          await write(
            `/operations/${encodeURIComponent(operation.id)}/approvals`,
            body,
            { "If-Match": `"${operation.version}"` },
          );
          announce(`${operation.id}: approval recorded.`);
          await refreshView();
          await render();
        } catch (error) {
          button.disabled = false;
          put(errors, failurePanel(error, "The approval"));
          announce(`${operation.id}: approval failed. ${error.message}`);
        }
      });
      put(section, form);
    }
  }
  put(section, errors);
  return section;
}

function evidenceDetails(artifact) {
  return h("details", {},
    h("summary", {}, artifact.name || artifact.id),
    facts([
      ["Artifact", h("span", { class: "mono" }, artifact.id)],
      ["Step", String(artifact.step)],
      ["SHA-256", h("span", { class: "mono" }, artifact.sha256)],
      ["Created", when(artifact.created_at)],
      ["Expires", when(artifact.expires_at)],
    ]),
    h("pre", { class: "evidence" }, JSON.stringify(artifact.content, null, 2)));
}

async function renderOperationEvidence(section, operation) {
  const ids = [...new Set(operation.steps.flatMap((step) => step.artifacts || []))];
  if (ids.length === 0) {
    put(section, h("p", { class: "muted" }, "No evidence artifact was recorded."));
    return;
  }
  const results = await Promise.allSettled(ids.map((id) => api(`/artifacts/${encodeURIComponent(id)}`)));
  for (let index = 0; index < results.length; index += 1) {
    const result = results[index];
    if (result.status === "fulfilled") put(section, evidenceDetails(result.value));
    else put(section, panel("warn", h("p", {}, h("strong", {}, `${ids[index]} is unavailable. `), result.reason.message)));
  }
}

async function pageOperation(main, id) {
  main.querySelector("h1").textContent = id;
  put(main, h("p", {}, h("a", { href: "#/changes" }, "Back to changes")));
  try {
    const operation = await api(`/operations/${encodeURIComponent(id)}`);
    main.querySelector("h1").textContent = `${operation.action} on ${deploymentName(state.view, operation.deployment)}`;
    const mutations = operation.steps.filter((step) => step.mutation);
    const highRisk = operation.steps.filter((step) => step.risk === "high");
    put(main, recoveryAdvice(operation));
    put(main, h("h2", {}, "Scope and risk"));
    put(main, facts([
      ["Operation", h("span", { class: "mono" }, operation.id)],
      ["State", operationBadge(operation.state)],
      ["Deployment", deploymentName(state.view, operation.deployment)],
      ["Action", operation.action],
      ["Requested by", h("span", { class: "mono" }, operation.requested_by)],
      ["Created", when(operation.created_at)],
      ["Updated", when(operation.updated_at)],
      ["Scope", `${operation.steps.length} planned steps; ${mutations.length} mutate the deployment`],
      ["Risk", highRisk.length ? `${highRisk.length} high-risk step${highRisk.length === 1 ? "" : "s"}` : "all steps low risk"],
      ["Parameters", h("pre", { class: "inline-json" }, JSON.stringify(operation.params, null, 2))],
      ["Reason", operation.reason || "none recorded"],
    ]));
    put(main, h("h2", {}, "Plan and progress"));
    put(main, table(
      "Planned operation steps",
      [{ label: "#", num: true }, "Step", "Risk", "Scope", "Recovery", "State", { label: "Attempts", num: true }, "Result"],
      operation.steps.map((step) => [
        String(step.index + 1),
        step.name,
        badge(step.risk, step.risk === "high" ? "warn" : "info"),
        step.mutation ? "changes deployment" : "read only",
        step.compensable ? "can roll back" : step.mutation ? "forward recovery only" : "not needed",
        operationBadge(step.state),
        String(step.attempts),
        step.error || (step.finished_at ? when(step.finished_at) : "—"),
      ]),
      "The driver returned no steps.",
    ));
    put(main, h("h2", {}, "Approvals"));
    put(main, table(
      "Recorded approvals",
      [{ label: "Step", num: true }, "Approver", "When"],
      operation.approvals.map((approval) => [String(approval.step + 1), h("span", { class: "mono" }, approval.approver), when(approval.at)]),
      "No approval has been recorded.",
    ));
    const evidenceLoading = h("p", { class: "muted" }, "Loading evidence…");
    const evidence = h("section", { "aria-labelledby": "evidence-heading" },
      h("h2", { id: "evidence-heading" }, "Evidence"),
      evidenceLoading);
    put(main, evidence);
    put(main, operationControls(operation));
    put(main, h("p", {}, h("a", { href: `#/audit?operation=${encodeURIComponent(operation.id)}` }, "View the immutable audit trail for this operation")));
    await renderOperationEvidence(evidence, operation);
    evidenceLoading.remove();
    announce(`Loaded operation ${operation.id}.`);
  } catch (error) {
    put(main, failurePanel(error, "This operation"));
  }
}

async function pageInvestigate(main) {
  put(main, pageHeading("Investigate"));
  put(main, h("p", {}, "Correlate homeserver reachability, deployment findings and operations without shell access. Data remains useful when one target is unavailable."));
  if (state.viewError) {
    put(main, failurePanel(state.viewError, "The deployment view"));
    return;
  }
  const connections = state.view.connections || [];
  const canProbe = hasRole("operator");
  put(main, h("h2", {}, "Reachability"));
  put(main, table(
    "Homeserver reachability probes",
    ["Connection", "Address", "Observed", "Result", { label: "Latency", num: true }, "Investigate"],
    connections.map((connection) => {
      const probeResult = connection.last_probe;
      const result = !probeResult ? badge("not observed", "warn") : probeResult.reachable ? badge(`reachable (${probeResult.status})`, "ok") : badge(probeResult.detail || "unreachable", "bad");
      const actions = [];
      if (connection.credential) {
        actions.push(h("a", { href: `#/rooms/${encodeURIComponent(connection.id)}` }, "Rooms"), " · ", h("a", { href: `#/people/${encodeURIComponent(connection.id)}` }, "People"));
      }
      if (canProbe) {
        const button = h("button", { type: "button", class: "link" }, "Probe now");
        button.addEventListener("click", () => probe(connection, button));
        if (actions.length) actions.push(" · ");
        actions.push(button);
      }
      return [connection.name, h("span", { class: "mono" }, connection.base_url), probeResult ? when(probeResult.at) : "never", result, probeResult ? `${probeResult.latency_ms} ms` : "—", actions.length ? h("span", {}, actions) : "—"];
    }),
    "No homeserver connection is registered.",
  ));

  put(main, h("h2", {}, "Deployment findings"));
  const loading = h("p", { class: "muted" }, "Loading assessments…");
  put(main, loading);
  try {
    const result = await api("/assessments");
    loading.remove();
    const assessments = [...result.items].sort((left, right) => right.created_at - left.created_at);
    const rows = assessments.flatMap((assessment) => {
      if (assessment.findings.length === 0) {
        return [[when(assessment.created_at), deploymentName(state.view, assessment.deployment), badge("no findings", "ok"), "—", "Assessment completed without a finding."]];
      }
      return assessment.findings.map((finding) => [
        when(assessment.created_at),
        deploymentName(state.view, assessment.deployment),
        badge(finding.severity, finding.severity === "blocker" ? "bad" : finding.severity === "warning" ? "warn" : "info"),
        h("span", { class: "mono" }, finding.code),
        finding.summary,
      ]);
    });
    put(main, table(
      "Assessment findings, newest assessment first",
      ["Observed", "Deployment", "Severity", "Code", "Finding"],
      rows,
      "No deployment assessment has been recorded.",
    ));
    const blocked = (state.view.needs_attention || []).filter((operation) => ["failed", "attention_required"].includes(operation.state));
    put(main, h("h2", {}, "Interrupted and failed changes"));
    put(main, table(
      "Changes that need investigation",
      ["Operation", "Deployment", "State", "Reason"],
      blocked.map((operation) => [
        h("a", { class: "mono", href: `#/changes/${encodeURIComponent(operation.id)}` }, operation.id),
        deploymentName(state.view, operation.deployment),
        operationBadge(operation.state),
        operation.reason || "Inspect its step evidence.",
      ]),
      "No failed or interrupted change needs investigation.",
    ));
    announce(`${assessments.length} assessments loaded.`);
  } catch (error) {
    loading.remove();
    put(main, failurePanel(error, "Assessments"));
  }
}

function auditActor(event) {
  return event.actor && event.actor.kind === "principal"
    ? h("span", { class: "mono" }, event.actor.subject)
    : "operator engine";
}

function auditSummary(event) {
  const change = event.change || {};
  const type = (change.type || "unknown_event").replaceAll("_", " ");
  if (change.type === "operation_created") return `Created ${change.operation.action} operation`;
  if (change.type === "operation_state") return `Operation became ${String(change.state).replaceAll("_", " ")}`;
  if (change.type === "step_started") return `Started step ${change.step + 1}`;
  if (change.type === "step_completed") return `Completed step ${change.step + 1}`;
  if (change.type === "step_failed") return `Step ${change.step + 1} failed`;
  if (change.type === "step_observed") return `Observed step ${change.step + 1} as ${change.applied ? "applied" : "not applied"}`;
  if (change.type === "approval_recorded") return `Approved step ${change.approval.step + 1}`;
  return type.charAt(0).toUpperCase() + type.slice(1);
}

async function pageAudit(main, route) {
  put(main, pageHeading("Audit"));
  put(main, h("p", {}, "Immutable operator history connects each request, actor, operation, step and outcome. Session secrets and idempotency bookkeeping are omitted by the API."));
  const operation = route.params.get("operation") || "";
  const input = h("input", { id: "audit-operation", value: operation, autocomplete: "off", placeholder: "op_…" });
  const form = h("form", { class: "search" },
    h("label", { for: "audit-operation" }, "Operation ID", input),
    h("button", { type: "submit" }, "Filter"));
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const query = new URLSearchParams();
    if (input.value.trim()) query.set("operation", input.value.trim());
    location.hash = `#/audit${query.size ? `?${query}` : ""}`;
  });
  put(main, form);
  const loading = h("p", { class: "muted" }, "Loading audit events…");
  put(main, loading);
  const query = new URLSearchParams({ limit: "200" });
  if (operation) query.set("operation", operation);
  if (route.params.get("after")) query.set("after", route.params.get("after"));
  try {
    const result = await api(`/audit?${query}`);
    loading.remove();
    put(main, table(
      operation ? `Audit events for ${operation}` : "Operator audit events",
      [{ label: "Sequence", num: true }, "When", "Actor", "Operation", "Event", "Request and details"],
      result.events.map((event) => [
        String(event.seq),
        when(event.at),
        auditActor(event),
        event.operation ? h("a", { class: "mono", href: `#/changes/${encodeURIComponent(event.operation)}` }, event.operation) : "—",
        auditSummary(event),
        h("details", {},
          h("summary", {}, event.request ? `Request ${event.request}` : "Event details"),
          h("pre", { class: "evidence" }, JSON.stringify(event.change, null, 2))),
      ]),
      operation ? "No audit event matches this operation." : "No audit event has been recorded.",
    ));
    if (result.events.length === 200) {
      const next = new URLSearchParams();
      if (operation) next.set("operation", operation);
      next.set("after", String(result.next));
      put(main, h("p", { class: "pager" }, h("a", { href: `#/audit?${next}` }, "Next 200 events")));
    }
    announce(`${result.events.length} audit events loaded.`);
  } catch (error) {
    loading.remove();
    put(main, failurePanel(error, "Audit history"));
  }
}

// ---- session and routing --------------------------------------------------



function renderWho() {
  const who = document.getElementById("who");
  who.replaceChildren();
  if (!state.session) return;
  const principal = state.session.principal;
  const button = h("button", { type: "button", class: "link" }, "Sign out");
  button.addEventListener("click", async () => {
    try { await write("/session/logout"); } catch { /* the session may already be gone */ }
    location.reload();
  });
  who.append(
    h("span", {}, "Signed in as ", h("strong", {}, principal.name || principal.subject)),
    h("span", {}, "Roles: ", principal.roles.join(", ")),
    button,
  );
}

function signIn(main, reason) {
  main.replaceChildren(
    pageHeading("Sign in"),
    reason ? panel("warn", h("p", {}, reason)) : null,
    h("p", {}, "The console uses your organisation's sign-in. You need the viewer, operator or approver role."),
    h("p", {}, h("a", { href: `${API}/session/login?return_to=${encodeURIComponent("/console/")}` }, "Sign in")),
  );
  document.getElementById("global-state").replaceChildren(h("p", {}, "Sign in to see the deployment state."));
  main.querySelector("h1").focus();
}

function parseRoute() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, query] = raw.split("?");
  const segments = (path || "now").split("/").filter(Boolean).map(decodeURIComponent);
  return { page: segments[0] || "now", parts: segments.slice(1), params: new URLSearchParams(query || "") };
}

const PAGES = {
  now: { title: "Now", render: pageNow },
  changes: { title: "Changes", render: pageChanges },
  investigate: { title: "Investigate", render: pageInvestigate },
  people: { title: "People & access", render: pagePeople },
  rooms: { title: "Rooms & safety", render: pageRooms },
  audit: { title: "Audit", render: pageAudit },
};

// `moveFocus` is false for the first page a person opens, so the skip link
// stays the first tab stop; on every later navigation focus moves to the new
// page's heading, so a screen reader announces where they are.
async function render(moveFocus = true) {
  const main = document.getElementById("main");
  const route = parseRoute();
  const page = PAGES[route.page] || PAGES.now;
  for (const link of document.querySelectorAll(".nav a")) {
    if (link.dataset.page === route.page) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  document.title = `${page.title} · Spindle Operator`;
  main.replaceChildren();
  const loading = page.render(main, route);
  const heading = main.querySelector("h1");
  if (heading && moveFocus) heading.focus();
  await loading;
}

async function start() {
  const main = document.getElementById("main");
  // The skip link's `#main` would otherwise be read as a route.
  document.querySelector(".skip-link").addEventListener("click", (event) => {
    event.preventDefault();
    main.focus();
  });
  try {
    state.session = await api("/session");
  } catch (error) {
    if (error.status === 401) return signIn(main);
    if (error.status === 403) return signIn(main, "Your account has no role on this operator. Ask an administrator to grant one.");
    main.replaceChildren(pageHeading("Operator unavailable"), failurePanel(error, "Your session"));
    return;
  }
  renderWho();
  await refreshView();
  window.addEventListener("hashchange", async () => {
    // Only `#/…` is a route; any other fragment is an in-page link.
    if (location.hash && !location.hash.startsWith("#/")) return;
    await refreshView();
    await render();
  });
  await render(false);
  // Keep the global state current without moving focus or re-rendering
  // the page the person is reading.
  setInterval(refreshView, 30_000);
}

document.addEventListener("DOMContentLoaded", start);
