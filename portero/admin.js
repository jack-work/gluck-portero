"use strict";

const $ = (id) => document.getElementById(id);
let grantable = [];

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c) node.append(c);
  return node;
}

function when(epoch) {
  return epoch ? new Date(epoch * 1000).toLocaleString() : "";
}

function say(message, isError) {
  const s = $("status");
  s.textContent = message;
  s.className = isError ? "err" : "";
}

async function call(method, path, body) {
  const init = { method, credentials: "same-origin", redirect: "manual", headers: { Accept: "application/json" } };
  if (method !== "GET") {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body || {});
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch (e) {
    throw new Error("network error: " + e.message);
  }
  if (res.type === "opaqueredirect" || res.status === 401) {
    throw new Error("your session has expired: reload the page to sign in again");
  }
  let data = {};
  try { data = await res.json(); } catch (e) { data = {}; }
  if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
  return data;
}

async function act(button, label, method, path, body, done) {
  button.disabled = true;
  try {
    const data = await call(method, path, body);
    say(done(data));
    await load();
  } catch (e) {
    say(label + ": " + e.message, true);
    button.disabled = false;
  }
}

function suggest(email) {
  const local = (email.split("@")[0] || "").toLowerCase().replace(/[^a-z0-9_-]/g, "");
  return /^[a-z]/.test(local) ? local.slice(0, 32) : "";
}

function pendingRow(r) {
  const user = el("input", { type: "text", placeholder: "username", size: "16", value: suggest(r.email) });
  const name = el("input", { type: "text", placeholder: "display name (optional)", size: "22" });
  const boxes = grantable.map((g) => el("input", { type: "checkbox", value: g, id: `g-${r.id}-${g}` }));
  const approve = el("button", { text: "Approve" });
  const reject = el("button", { class: "quiet", text: "Reject" });
  approve.addEventListener("click", () => act(approve, "approve", "POST", `/intake/${r.id}/approve`, {
    username: user.value.trim(),
    display_name: name.value.trim(),
    site_access_groups: boxes.filter((b) => b.checked).map((b) => b.value),
  }, (d) => `approved ${d.username}` + (d.mailed ? ", invite mailed" : `, mail FAILED: ${d.mail_error}`)));
  reject.addEventListener("click", () => {
    if (confirm(`Reject ${r.email}?`)) act(reject, "reject", "POST", `/intake/${r.id}/reject`, {}, () => `rejected #${r.id}`);
  });
  const groups = boxes.map((b, i) => el("label", { for: b.id }, b, " " + grantable[i]));
  return el("div", { class: "row" },
    el("div", { class: "head" },
      el("span", { class: "email", text: r.email }),
      el("span", { class: "meta", text: `#${r.id} · ${when(r.received_at)}` })),
    r.note ? el("div", { class: "note", text: r.note }) : null,
    el("div", { class: "fields" }, user, name, ...groups, approve, reject));
}

function inviteRow(r) {
  const resend = el("button", { class: "quiet", text: "Resend" });
  const remove = el("button", { class: "danger", text: "Delete account" });
  const retire = el("button", { class: "quiet", text: "Retire" });
  resend.addEventListener("click", () => act(resend, "resend", "POST", `/intake/${r.id}/send`, {},
    (d) => d.mailed ? `invite mailed again to ${r.email}` : `mail FAILED: ${d.mail_error}`));
  remove.addEventListener("click", () => {
    if (confirm(`Delete the account ${r.username}? This cannot be undone.`)) {
      act(remove, "delete", "DELETE", `/invites/${encodeURIComponent(r.username)}`, null, () => `deleted ${r.username}; retire the row next`);
    }
  });
  retire.addEventListener("click", () => act(retire, "retire", "POST", `/intake/${r.id}/retire`, {}, () => `retired #${r.id}`));
  return el("div", { class: "row" },
    el("div", { class: "head" },
      el("span", { class: "email", text: r.username }),
      el("span", { text: r.email }),
      el("span", { class: "meta", text: `#${r.id} · by ${r.decided_by || "?"} · sent ${r.send_count}× · last ${when(r.sent_at)} · link expires ${when(r.expires_at)}` })),
    el("div", { class: "fields" }, resend, remove, retire));
}

function decidedRow(r) {
  return el("div", { class: "row" },
    el("div", { class: "head" },
      el("span", { class: "email", text: r.email }),
      el("span", { text: r.state + (r.username ? ` (${r.username})` : "") }),
      el("span", { class: "meta", text: `#${r.id} · by ${r.decided_by || "?"} · ${when(r.decided_at)}` })));
}

function fill(id, rows, render) {
  const box = $(id);
  box.replaceChildren(...(rows.length ? rows.map(render) : [el("p", { class: "empty", text: "none" })]));
  $(id + "-count").textContent = `(${rows.length})`;
}

async function load() {
  const data = await call("GET", "/intake?state=all");
  const rows = data.rows.slice().sort((a, b) => a.id - b.id);
  fill("pending", rows.filter((r) => r.state === "pending"), pendingRow);
  fill("invites", rows.filter((r) => r.state === "approved"), inviteRow);
  fill("decided", rows.filter((r) => r.state === "rejected" || r.state === "retired").reverse(), decidedRow);
  if (data.ingest === "error") say(`the spool could not be read (${data.ingest_errno}); new signups are waiting`, true);
}

async function start() {
  try {
    const cfg = await call("GET", "/admin/config");
    grantable = cfg.grantable;
    $("who").textContent = `signed in as ${cfg.user}`;
    await load();
  } catch (e) {
    say(e.message, true);
  }
}

start();
