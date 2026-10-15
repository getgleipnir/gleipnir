/**
 * Zendesk Support read-back checks (mirrors `gleipnir.outcomes.zendesk`).
 *
 * - Tickets: https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/
 *   (`GET /api/v2/tickets/{id}` -> `{ticket: {...}}`; `status` new/open/pending/hold/solved/closed;
 *   `priority` urgent/high/normal/low; `assignee_id`, `group_id`, `requester_id`, `tags`, `subject`,
 *   `type`, `custom_fields: [{id, value}]`)
 * - Ticket comments: https://developer.zendesk.com/api-reference/ticketing/tickets/ticket_comments/
 *   (`GET /api/v2/tickets/{id}/comments?sort_order=desc` -> `{comments: [{id, body, html_body,
 *   plain_body, public, author_id}]}`)
 *
 * `client` is a function `path => JSON`, e.g. `jsonGet("https://acme.zendesk.com", {headers})`.
 */

import type { Call } from "../recorder.js";
import {
  ABSENT,
  Check,
  ConfigError,
  NotFound,
  SKIP,
  checkFn,
  firstOf,
  getPath,
  includesAll,
  normText,
  optArg,
  resolve,
  resolveFields,
  resolveId,
  resp,
  sameSet,
  valuesEqual,
  type Fields,
  type JsonFetch,
  type OutcomeCheckFn,
  type RetryOptions,
  type Spec,
} from "./core.js";

export const DOCS = "https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/";

function fetcher(client: unknown): JsonFetch {
  if (typeof client !== "function") throw new ConfigError("Zendesk client must be a path => JSON function (see jsonGet)");
  return client as JsonFetch;
}

export async function getTicket(client: unknown, id: string): Promise<unknown> {
  const body = await fetcher(client)(`/api/v2/tickets/${encodeURIComponent(id)}.json`);
  const t = getPath(body, "ticket");
  if (t === ABSENT || !t) throw new NotFound(`ticket ${id}`);
  return t;
}

export async function getComments(client: unknown, id: string): Promise<unknown[]> {
  const body = await fetcher(client)(`/api/v2/tickets/${encodeURIComponent(id)}/comments.json?sort_order=desc`);
  const items = getPath(body, "comments");
  if (!Array.isArray(items)) throw new ConfigError("unexpected comments payload (no 'comments' list)");
  return items;
}

interface TicketFieldOptions {
  status?: Spec;
  priority?: Spec;
  assigneeId?: Spec;
  groupId?: Spec;
  tags?: Spec;
  tagsExact?: boolean;
  fields?: Fields;
  customFields?: Record<string, unknown>;
}

function compareTicket(c: Check, t: unknown, call: Call, response: unknown, o: Required<Omit<TicketFieldOptions, "customFields" | "fields">> & TicketFieldOptions): void {
  c.note("id", getPath(t, "id"));
  c.field("status", resolve(o.status, call, response), getPath(t, "status"));
  c.field("priority", resolve(o.priority, call, response), getPath(t, "priority"));
  c.field("assignee_id", resolve(o.assigneeId, call, response), getPath(t, "assignee_id"));
  c.field("group_id", resolve(o.groupId, call, response), getPath(t, "group_id"));
  c.field("tags", resolve(o.tags, call, response), getPath(t, "tags"), o.tagsExact ? sameSet : includesAll);
  for (const [k, v] of Object.entries(resolveFields(o.fields, call, response))) c.field(k, v, getPath(t, k));
  if (o.customFields) {
    const have = new Map<string, unknown>();
    const cf = getPath(t, "custom_fields");
    if (Array.isArray(cf)) for (const f of cf) {
      const fid = getPath(f, "id");
      if (fid !== ABSENT) have.set(String(fid), getPath(f, "value"));
    }
    for (const [fid, value] of Object.entries(o.customFields)) {
      const v = typeof value === "function" ? (value as (c: Call, r: unknown) => unknown)(call, response) : value;
      if (v !== SKIP) c.field(`custom_fields.${fid}`, v, have.has(fid) ? have.get(fid) : ABSENT);
    }
  }
}

async function checkComment(c: Check, client: unknown, id: string, body: unknown, pub: unknown, author: unknown): Promise<void> {
  const want = normText(body);
  if (!want) throw new ConfigError("comment body to look for is empty");
  for (const cm of await getComments(client, id)) {
    const text = ["plain_body", "body", "html_body"].map((k) => normText(getPath(cm, k))).join(" ");
    if (!text.includes(want)) continue;
    if (pub !== SKIP && !valuesEqual(pub, getPath(cm, "public"))) continue;
    if (author !== SKIP && !valuesEqual(author, getPath(cm, "author_id"))) continue;
    c.require("comment", true, { present: true, id: getPath(cm, "id"), public: getPath(cm, "public"), author_id: getPath(cm, "author_id") });
    return;
  }
  c.fail("comment", { present: false });
}

export interface TicketUpdatedOptions extends RetryOptions, TicketFieldOptions {
  ticketId?: Spec;
  /** Comment text to find among the latest comments (e.g. `"reply"` for the tool's `reply` arg). */
  comment?: Spec;
  commentPublic?: Spec;
  commentAuthorId?: Spec;
}

export function ticketUpdated(client: unknown, opts: TicketUpdatedOptions = {}): OutcomeCheckFn {
  const o = {
    ticketId: firstOf(optArg("ticket_id"), resp("ticket.id"), resp("id")), status: optArg("status"),
    priority: optArg("priority"), assigneeId: optArg("assignee_id"), groupId: optArg("group_id"), tags: optArg("tags"),
    tagsExact: false, comment: null, commentPublic: null, commentAuthorId: null, ...opts,
  };
  return checkFn("zendesk.ticket_updated", async (call, response) => {
    const id = resolveId(o.ticketId, call, response, "ticket id");
    const t = await getTicket(client, id);
    const c = new Check("zendesk.ticket_updated");
    compareTicket(c, t, call, response, o);
    const body = resolve(o.comment, call, response);
    if (body !== SKIP) {
      await checkComment(c, client, id, body, resolve(o.commentPublic, call, response), resolve(o.commentAuthorId, call, response));
    }
    return c.outcome();
  }, opts);
}

export interface TicketCreatedOptions extends RetryOptions, TicketFieldOptions {
  ticketId?: Spec;
  subject?: Spec;
  requesterId?: Spec;
  type?: Spec;
  comment?: Spec;
}

export function ticketCreated(client: unknown, opts: TicketCreatedOptions = {}): OutcomeCheckFn {
  const o = {
    ticketId: firstOf(resp("ticket.id"), resp("id")), subject: optArg("subject"), requesterId: optArg("requester_id"),
    type: optArg("type"), status: optArg("status"), priority: optArg("priority"), assigneeId: optArg("assignee_id"),
    groupId: optArg("group_id"), tags: optArg("tags"), tagsExact: false,
    comment: firstOf(optArg("comment"), optArg("description"), optArg("body")), ...opts,
  };
  return checkFn("zendesk.ticket_created", async (call, response) => {
    const id = resolveId(o.ticketId, call, response, "ticket id");
    const t = await getTicket(client, id);
    const c = new Check("zendesk.ticket_created");
    c.field("subject", resolve(o.subject, call, response), getPath(t, "subject"));
    c.field("requester_id", resolve(o.requesterId, call, response), getPath(t, "requester_id"));
    c.field("type", resolve(o.type, call, response), getPath(t, "type"));
    compareTicket(c, t, call, response, o);
    let body = resolve(o.comment, call, response);
    if (body && typeof body === "object") {
      const b = body as Record<string, unknown>;
      body = b["body"] ?? b["html_body"] ?? SKIP;
    }
    if (body !== SKIP) {
      const want = normText(body);
      if (want && normText(getPath(t, "description")).includes(want)) c.require("comment", true, { present: true, in: "description" });
      else await checkComment(c, client, id, body, SKIP, SKIP);
    }
    return c.outcome();
  }, opts);
}
