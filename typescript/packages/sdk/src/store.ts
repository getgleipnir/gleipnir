/** Record storage. The default store is an append-only JSON Lines file per chain. */

import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, writeSync } from "node:fs";
import { join } from "node:path";
import { parseJsonl, pyDumps } from "@getgleipnir/verify";

export type Rec = Record<string, unknown>;

export interface Store {
  append(record: Rec): void;
  readAll(): Rec[];
}

/** One line per record, sorted keys, no spaces, UTF-8 (as the Python SDK's JsonlStore writes). */
export function recordLine(record: Rec): string {
  return pyDumps(record, { ensureAscii: false, sortKeys: true, separators: [",", ":"] }) + "\n";
}

/**
 * Like the Python store, non-ASCII text is written raw (UTF-8), except U+0085, U+2028 and
 * U+2029: Python's `str.splitlines()` (used by both readers) treats them as line breaks, so a
 * raw one would split a record in two. They are written as \u escapes, which parse to the same
 * record (so the same hash).
 */
function safeLine(record: Rec): string {
  return recordLine(record).replace(/[\u2028\u2029\u0085\u000b\u000c\u001c\u001d\u001e]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}

export class JsonlStore implements Store {
  readonly path: string;
  constructor(readonly directory: string, readonly fsync = true) {
    mkdirSync(directory, { recursive: true });
    this.path = join(directory, "records.jsonl");
  }

  append(record: Rec): void {
    const fd = openSync(this.path, "a");
    try {
      writeSync(fd, safeLine(record));
      if (this.fsync) fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }

  readAll(): Rec[] {
    if (!existsSync(this.path)) return [];
    return parseJsonl(readFileSync(this.path, "utf8")) as Rec[];
  }
}

/** In-memory store for tests. */
export class MemoryStore implements Store {
  private readonly lines: string[] = [];
  append(record: Rec): void {
    this.lines.push(safeLine(record));
  }
  readAll(): Rec[] {
    return parseJsonl(this.lines.join("")) as Rec[];
  }
}
