#!/usr/bin/env node
// Public triage job, shadow mode (product loop work package 5, D-2026-10-22-09).
//
// Runs inside the workflow that the community kit renders from
// github/workflows/triage.yml. It reads the new item from GITHUB_EVENT_PATH,
// asks one Gateway route for a typed decision with a short-lived GitHub OIDC
// token, validates the answer, renders the reply it WOULD post and keeps a
// decision record. It posts nothing: the workflow holds no write permission
// and no secret.
//
// The model has no tools and fills no text: it answers with values from fixed
// lists, and this script maps each value to fixed text (replies/*.md). Item
// text goes only to the Gateway route. The decision record, the job summary
// and every log line carry typed values and SHA-256 hashes, never the title or
// body.
//
// Environment: GITHUB_EVENT_NAME, GITHUB_EVENT_PATH, GITHUB_REPOSITORY,
// GITHUB_RUN_ID, GITHUB_STEP_SUMMARY, GITHUB_OUTPUT, RUNNER_TEMP and
// ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN come from the runner; TRIAGE_ENDPOINT
// comes from the workflow and has no default, so a missing value fails.
// TRIAGE_STRICT=1, set only in the Preview probe, turns every answer other
// than HTTP 200 into a red job, so the probe cannot stay green while proving
// nothing.
//
// Every item that was read leaves a decision record, whatever happened, with
// an outcome: decided; deferred (HTTP 429, HTTP 402 when the spend cap is
// reached, and HTTP 503 when the route is not configured or its call budget
// is unavailable: green with a notice, because shadow mode must not alarm);
// or failed (anything else, red, with the HTTP status and error code but no
// text). Step outputs: file and artifact, set whenever a record was written.

import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA = "kombify.public-triage.shadow-decision.v1";
const AUDIENCE = "urn:kombify:ai:public-triage";
const MAX_TITLE = 256;
const MAX_BODY_BYTES = 16 * 1024;
const MAX_REQUEST_BYTES = 32 * 1024;

const TEMPLATES = ["idea_received", "acknowledge", "needs_info", "redirect", "none"];
const PRODUCTS = {
  stackkits: "StackKits",
  techstack: "Techstack",
  cloud: "kombify Cloud",
  companion: "kombify Companion",
  workbench: "kombify Workbench",
  speechkit: "SpeechKit",
  paperwork: "Paperwork",
  platform: "kombify",
  unknown: "kombify",
};
const LABELS = ["triage/needs", "needs-info", "security"];
const FLAGS = ["prompt_injection", "pii", "security_report", "spam"];
const MISSING = {
  version: "the version you use",
  steps: "the steps to reproduce it",
  expected_actual: "what you expected and what happened instead",
  logs: "the relevant log lines (with secrets removed)",
  environment: "your environment (operating system and how you run it)",
};
const MISSING_FALLBACK = "the version you use, the steps to reproduce it and what you expected";
const HUMAN_CONTACT = "[kombify.io/support](https://kombify.io/support) or [info@kombify.io](mailto:info@kombify.io)";
const REPLY_FILES = { idea_received: "idea-received.md", acknowledge: "acknowledge.md", needs_info: "needs-info.md", redirect: "redirect.md" };

class Refusal extends Error {}
/** A failure after the item was read: it still leaves a record, with the HTTP status (or null) and an error code. */
class Failure extends Refusal {
  constructor(message, status, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// A 503 with one of these codes is the route being closed or out of budget, which shadow mode only notes;
// any other 503 is an infrastructure fault and fails the job.
const DEFERRED_503 = ["public_triage_unconfigured", "public_triage_budget_unavailable"];
const CODE = /^[a-z][a-z0-9_]{0,63}$/;

const sha256 = (text) => createHash("sha256").update(text, "utf8").digest("hex");
const subset = (value, allowed) => Array.isArray(value) && value.every((item) => allowed.includes(item));
const annotate = (level, title, message) => process.stdout.write(`::${level} title=${title}::${message}\n`);

// ---------- the item ----------

function readItem(eventName, payload, repository) {
  const kind = { issues: "issue", discussion: "discussion" }[eventName];
  if (!kind) throw new Refusal(`event ${eventName} is not handled`);
  const raw = kind === "issue" ? payload.issue : payload.discussion;
  const wantedAction = kind === "issue" ? "opened" : "created";
  if (payload.action !== wantedAction || !raw) return { skip: `action ${payload.action} is not ${wantedAction}` };
  if (payload.repository?.full_name?.toLowerCase() !== repository.toLowerCase()) throw new Refusal("the event belongs to another repository");
  if (payload.sender?.type === "Bot") return { skip: "opened by a bot account (for example the projection of a roadmap issue)" };
  const number = raw.number;
  if (!Number.isInteger(number) || number < 1) throw new Refusal("the item has no number");
  const htmlUrl = `https://github.com/${repository}/${kind === "issue" ? "issues" : "discussions"}/${number}`;
  if (String(raw.html_url).toLowerCase() !== htmlUrl.toLowerCase()) throw new Refusal("the item URL does not match its repository and number");
  const login = String(raw.user?.login ?? "");
  const labels = (raw.labels ?? []).map((label) => String(label?.name ?? "").toLowerCase());
  const bug = kind === "issue" && (String(raw.type?.name ?? "").toLowerCase() === "bug" || labels.includes("bug"));
  const slug = String(raw.category?.slug ?? "");
  const category = kind === "issue" ? (bug ? "bug" : "other") : ["ideas", "q-a", "announcements"].includes(slug) ? slug : "other";
  return {
    kind,
    number,
    category,
    nodeId: String(raw.node_id ?? ""),
    htmlUrl,
    author: /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(login) ? login : "there",
    title: String(raw.title ?? ""),
    body: String(raw.body ?? ""),
  };
}

function clipTitle(title) {
  let clipped = title.slice(0, MAX_TITLE);
  const last = clipped.charCodeAt(clipped.length - 1);
  if (clipped.length < title.length && last >= 0xd800 && last <= 0xdbff) clipped = clipped.slice(0, -1);
  return clipped;
}

function clipBody(body, limit) {
  const bytes = Buffer.from(body, "utf8");
  if (bytes.length <= limit) return body;
  let end = limit;
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) end -= 1; // never cut a UTF-8 sequence
  return bytes.subarray(0, end).toString("utf8");
}

/** The typed request: title at most 256 characters, body at most 16 KiB, the whole JSON at most 32 KiB. */
function buildRequest(item) {
  let limit = MAX_BODY_BYTES;
  for (;;) {
    const request = { kind: item.kind, category: item.category, title: clipTitle(item.title), body: clipBody(item.body, limit) };
    const json = JSON.stringify(request);
    if (Buffer.byteLength(json) <= MAX_REQUEST_BYTES) return { json, clipped: request.body !== item.body || request.title !== item.title };
    if (limit === 0) throw new Refusal("the request does not fit the size limit");
    limit = Math.floor(limit * 0.75); // escaping can inflate the body past the limit
  }
}

// ---------- the Gateway call ----------

function endpointUrl() {
  const raw = process.env.TRIAGE_ENDPOINT;
  if (!raw) throw new Refusal("TRIAGE_ENDPOINT is not set; the workflow must name the route");
  const url = new URL(raw);
  const local = ["localhost", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) throw new Refusal("TRIAGE_ENDPOINT must be an https URL");
  return url;
}

async function requestToken() {
  const base = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const bearer = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!base || !bearer) throw new Failure("no OIDC request credential: the workflow needs permissions id-token: write", null, "oidc_unavailable");
  const url = new URL(base);
  url.searchParams.set("audience", AUDIENCE);
  let response;
  let token = null;
  try {
    response = await fetch(url, { headers: { Authorization: `Bearer ${bearer}`, Accept: "application/json" }, signal: AbortSignal.timeout(20_000) });
    token = response.ok ? (await response.json())?.value : null;
  } catch (error) {
    throw new Failure("the OIDC token request failed before an answer arrived", null, "oidc_token_failed");
  }
  if (typeof token !== "string" || token.length < 20) throw new Failure(`the OIDC token request failed (HTTP ${response.status})`, null, "oidc_token_failed");
  process.stdout.write(`::add-mask::${token}\n`);
  return token;
}

/**
 * The error code of a Gateway or AI Platform answer: the x-kombify-error-code header, else the Gateway's
 * `reason`, else `error.code` or `error.reason` of an AI Platform error object, else a string `error`.
 * Only a lower-case token is returned, never text.
 */
function errorCode(headers, body) {
  const object = body && typeof body === "object" && !Array.isArray(body) ? body : {};
  const nested = object.error && typeof object.error === "object" ? object.error : {};
  for (const candidate of [headers.get("x-kombify-error-code"), object.reason, nested.code, nested.reason, object.error_code, object.error]) {
    if (typeof candidate === "string" && CODE.test(candidate)) return candidate;
  }
  return null;
}

async function decide(token, json) {
  const url = endpointUrl();
  let response;
  let text;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", Accept: "application/json", "User-Agent": "kombify-public-triage/1" },
      body: json,
      signal: AbortSignal.timeout(60_000),
      redirect: "error",
    });
    text = await response.text();
  } catch (error) {
    throw new Failure("the Gateway call failed before an answer arrived", null, "transport_error");
  }
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (error) {
    body = null; // a non-JSON answer is judged by its status below
  }
  return { status: response.status, retryAfter: response.headers.get("retry-after"), code: errorCode(response.headers, body), body };
}

/** decided, deferred or failed for an HTTP answer. */
function classify(status, code) {
  if (status === 200) return "decided";
  if (status === 429 || status === 402) return "deferred";
  if (status === 503 && DEFERRED_503.includes(code)) return "deferred";
  return "failed";
}

/** The typed answer, or a Failure that names the field and never echoes the answer. */
function validateDecision(body) {
  const bad = (field) => new Failure(`the typed response is invalid at ${field}`, 200, "typed_response_invalid");
  if (!body || typeof body !== "object" || Array.isArray(body)) throw bad("body");
  if (!TEMPLATES.includes(body.template)) throw bad("template");
  if (!Object.hasOwn(PRODUCTS, body.product)) throw bad("product");
  if (!subset(body.labels, LABELS)) throw bad("labels");
  if (!subset(body.missing, Object.keys(MISSING))) throw bad("missing");
  if (typeof body.link_bead !== "boolean") throw bad("link_bead");
  if (typeof body.confidence !== "number" || !(body.confidence >= 0 && body.confidence <= 1)) throw bad("confidence");
  if (!subset(body.flags, FLAGS)) throw bad("flags");
  // model and usage are copied only as plain tokens and numbers, so no free text can pass through them.
  const model = typeof body.model === "string" && /^[A-Za-z0-9._:/-]{1,100}$/.test(body.model) ? body.model : null;
  const usage = {};
  for (const [name, value] of Object.entries(body.usage && typeof body.usage === "object" ? body.usage : {})) {
    if (/^[a-z][a-z0-9_]{0,39}$/.test(name) && typeof value === "number" && Number.isFinite(value)) usage[name] = value;
  }
  return {
    decision: {
      template: body.template,
      product: body.product,
      labels: [...new Set(body.labels)],
      missing: [...new Set(body.missing)],
      link_bead: body.link_bead,
      confidence: body.confidence,
      flags: [...new Set(body.flags)],
    },
    model,
    usage,
  };
}

// ---------- the reply it would post ----------

function joinPhrases(phrases) {
  return phrases.length < 2 ? phrases.join("") : `${phrases.slice(0, -1).join(", ")} and ${phrases.at(-1)}`;
}

function fill(text, values, owner) {
  const out = text.replace(/\{\{([a-z_]+)\}\}/g, (_, name) => {
    if (!Object.hasOwn(values, name)) throw new Refusal(`${owner} uses the slot ${name}, which the job does not fill`);
    return values[name];
  });
  if (/\{\{|\}\}/.test(out)) throw new Refusal(`${owner} has unresolved template syntax`);
  return out;
}

function renderReply(decision, item) {
  const file = REPLY_FILES[decision.template];
  if (!file) return null;
  const read = (name) => fs.readFileSync(path.join(HERE, "replies", name), "utf8").replace(/\r\n/g, "\n").replace(/\s+$/, "");
  const values = {
    author: item.author,
    product: PRODUCTS[decision.product],
    missing_information: decision.missing.length ? joinPhrases(decision.missing.map((name) => MISSING[name])) : MISSING_FALLBACK,
    human_contact: HUMAN_CONTACT,
  };
  return `${fill(read(file), values, file)}\n\n${fill(read("footer.md"), values, "footer.md")}\n`;
}

// ---------- the decision record and the summary ----------

const cell = (value) => String(value).replace(/\|/g, "/").replace(/[\r\n]+/g, " ").slice(0, 300);
const list = (items) => (items.length ? items.join(", ") : "none");

function outcomeText(record) {
  const detail = record.deferred ?? record.failure;
  if (!detail) return record.outcome;
  const code = detail.code ? ` ${detail.code}` : "";
  const retry = detail.retry_after_seconds ? `, retry after ${detail.retry_after_seconds} s` : "";
  return `${record.outcome} (${detail.status ? `HTTP ${detail.status}` : "no HTTP answer"}${code}${retry})`;
}

function summaryTable(record) {
  const decision = record.decision;
  const rows = [
    ["Item", `${record.kind} #${record.number}`],
    ["URL", record.html_url],
    ["Author", record.author],
    ["Outcome", outcomeText(record)],
    ["Template", decision?.template ?? "none"],
    ["Product", decision?.product ?? "none"],
    ["Labels", list(decision?.labels ?? [])],
    ["Missing", list(decision?.missing ?? [])],
    ["Link bead", decision ? (decision.link_bead ? "yes" : "no") : "no"],
    ["Confidence", decision?.confidence ?? "none"],
    ["Flags", list(decision?.flags ?? [])],
    ["Model", record.model ?? "none"],
    ["Usage", Object.keys(record.usage ?? {}).length ? Object.entries(record.usage).map(([name, value]) => `${name}=${value}`).join(", ") : "none"],
    ["Reply SHA-256", record.reply_sha256 ?? "none"],
    ["Title SHA-256", record.title_sha256],
    ["Body SHA-256", record.body_sha256],
    ["Run", `${record.run_id} (attempt ${record.run_attempt})`],
  ];
  return ["## Public triage, shadow mode", "", "| Field | Value |", "| --- | --- |", ...rows.map(([name, value]) => `| ${name} | ${cell(value)} |`), "",
    "Nothing was posted: the job holds no write permission. The reply it would post carries only the author login and fixed text.", ""].join("\n");
}

function append(variable, text) {
  if (process.env[variable]) fs.appendFileSync(process.env[variable], text);
}

// ---------- main ----------

/** The decision of one item as a record; throws a Failure after the item was read. */
async function decideItem(item, base, request) {
  const answer = await decide(await requestToken(), request.json);
  const kind = classify(answer.status, answer.code);
  if (kind === "decided") {
    const typed = validateDecision(answer.body);
    const reply = renderReply(typed.decision, item);
    return { ...base, outcome: "decided", decision: typed.decision, reply_template: reply ? typed.decision.template : null,
      reply_sha256: reply ? sha256(reply) : null, model: typed.model, usage: typed.usage, deferred: null, failure: null };
  }
  const empty = { ...base, decision: null, reply_template: null, reply_sha256: null, model: null, usage: {} };
  if (kind === "deferred") {
    const seconds = /^\d{1,6}$/.test(answer.retryAfter ?? "") ? Number(answer.retryAfter) : null;
    return { ...empty, outcome: "deferred", deferred: { status: answer.status, code: answer.code, retry_after_seconds: seconds }, failure: null };
  }
  return { ...empty, outcome: "failed", deferred: null, failure: { status: answer.status, code: answer.code } };
}

async function main() {
  if (Number(process.versions.node.split(".")[0]) < 18) throw new Refusal("Node 18 or newer is required");
  const repository = process.env.GITHUB_REPOSITORY;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!repository || !eventPath) throw new Refusal("GITHUB_REPOSITORY and GITHUB_EVENT_PATH are required");
  const item = readItem(process.env.GITHUB_EVENT_NAME, JSON.parse(fs.readFileSync(eventPath, "utf8")), repository);
  if (item.skip) {
    annotate("notice", "public triage skipped", item.skip);
    append("GITHUB_STEP_SUMMARY", `## Public triage, shadow mode\n\nSkipped: ${item.skip}.\n`);
    return 0;
  }

  const request = buildRequest(item);
  const base = {
    schema: SCHEMA,
    mode: "shadow",
    decided_at: new Date().toISOString(),
    repository,
    kind: item.kind,
    number: item.number,
    node_id: item.nodeId,
    html_url: item.htmlUrl,
    author: item.author,
    title_sha256: sha256(item.title),
    body_sha256: sha256(item.body),
    input_clipped: request.clipped,
    run_id: String(process.env.GITHUB_RUN_ID ?? "0"),
    run_attempt: Number(process.env.GITHUB_RUN_ATTEMPT ?? 1),
  };

  let record;
  let message = null;
  try {
    record = await decideItem(item, base, request);
  } catch (error) {
    // Whatever went wrong, the item keeps a record, so the intake can count it; the message never carries item text.
    const known = error instanceof Failure;
    const code = String(error?.cause?.code ?? error?.code ?? "");
    message = error instanceof Refusal ? error.message : `unexpected ${error?.name ?? "error"}${/^[A-Z0-9_]{1,40}$/.test(code) ? ` (${code})` : ""}`;
    record = { ...base, outcome: "failed", decision: null, reply_template: null, reply_sha256: null, model: null, usage: {}, deferred: null,
      failure: { status: known ? error.status : null, code: known ? error.code : "job_error" } };
  }
  const strict = process.env.TRIAGE_STRICT === "1";
  if (record.outcome === "deferred") {
    const detail = record.deferred;
    const text = `HTTP ${detail.status}${detail.code ? ` ${detail.code}` : ""}${detail.retry_after_seconds ? `, retry after ${detail.retry_after_seconds} s` : ""}`;
    if (strict) message = `strict mode: the Gateway did not decide (${text})`;
    else annotate("notice", "public triage deferred", `${text}; shadow mode, the item waits for a rerun`);
  } else if (record.outcome === "failed" && !message) {
    message = `the Gateway answered HTTP ${record.failure.status}${record.failure.code ? ` ${record.failure.code}` : ""}`;
  }

  const dir = path.join(process.env.RUNNER_TEMP || os.tmpdir(), "public-triage");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, "shadow-decision.json");
  fs.writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`);
  append("GITHUB_OUTPUT", `file=${file}\nartifact=public-triage-${record.kind}-${record.number}-${record.run_id}\n`);
  append("GITHUB_STEP_SUMMARY", summaryTable(record));
  process.stdout.write(`public triage ${record.outcome}: ${record.kind} #${record.number} template=${record.decision?.template ?? "none"} reply_sha256=${record.reply_sha256 ?? "none"}\n`);
  if (message) annotate("error", "public triage failed", message);
  return message ? 1 : 0;
}

main().then((code) => { process.exitCode = code; }, (error) => {
  // Only this job's own messages are printed; an unexpected error shows its type and system code, never request or response text.
  const code = String(error?.cause?.code ?? error?.code ?? "");
  const message = error instanceof Refusal ? error.message : `unexpected ${error?.name ?? "error"}${/^[A-Z0-9_]{1,40}$/.test(code) ? ` (${code})` : ""}`;
  annotate("error", "public triage failed", message);
  process.exitCode = 1;
});
