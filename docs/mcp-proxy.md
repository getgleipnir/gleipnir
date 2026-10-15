# gleipnir-mcp: verifiable records of what your agent did, with one config change

`gleipnir-mcp` sits between an MCP client (Claude Desktop, Cursor, Claude Code or any other client that launches stdio servers) and a local MCP server. It starts the real server as a subprocess, passes every message through unchanged, and writes a signed, hash-chained record of each `tools/call`: the tool name, the arguments, the result (`content` / `structuredContent`) or the error, start and end time, which server handled it, and which client sent it.

You don't change any code. In the client config you swap `command: npx ...` for `command: gleipnir-mcp ... -- npx ...`.

```
client  <--stdio-->  gleipnir-mcp  <--stdio-->  real MCP server
                          |
                          +--> ~/.gleipnir/chains/mcp-<server>/records.jsonl   (signed, chained)
```

## Install

```bash
uv tool install gleipnir-sdk        # or: pipx install gleipnir-sdk
gleipnir-mcp --help
```

Pre-release: until the package is on PyPI, install from a checkout with `uv tool install ./python/gleipnir`.

## Quickstart: Claude Desktop

1. **Generate the entry.** Put `gleipnir-mcp --print-config claude-desktop --` in front of the command you already use:

   ```bash
   gleipnir-mcp --print-config claude-desktop -- npx -y @modelcontextprotocol/server-filesystem ~/Desktop
   ```

   This prints an `mcpServers` entry with absolute paths. Claude Desktop does not use your shell's `PATH` to find `gleipnir-mcp`, so you need the absolute path.

2. **Paste it into the config.** Open Claude menu → Settings… → Developer → Edit Config. The file is `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS and `%APPDATA%\Claude\claude_desktop_config.json` on Windows. Merge the printed server into `mcpServers`, replacing the old entry for the same server. Config format: [MCP docs, "Connect to local MCP servers"][mcp-local].

3. **Restart Claude Desktop completely** (quit, then reopen) and use the tools as usual. Then run `gleipnir report --open`.

The proxy's own messages (where it records, problems) go to stderr. Claude Desktop writes them to `mcp-server-<name>.log` in `~/Library/Logs/Claude` (macOS) or `%APPDATA%\Claude\logs` (Windows) [mcp-local].

## Quickstart: Cursor

1. **Generate the entry:**

   ```bash
   gleipnir-mcp --print-config cursor -- npx -y @modelcontextprotocol/server-github
   ```

2. **Paste it** into `.cursor/mcp.json` in your project, or into `~/.cursor/mcp.json` for every project, under `mcpServers`. The printed entry has `"type": "stdio"`, `command` and `args`; add `env` if your server needs it. Format: [Cursor docs, Model Context Protocol][cursor-mcp].

3. **Restart Cursor** (or reload the server in Settings → MCP), use the tools, then run `gleipnir report --open`.

## Quickstart: Claude Code

1. **Remove the old entry** if the server is already configured: `claude mcp remove <name>`.

2. **Add it through the proxy.** `--print-config claude-code` prints the full command:

   ```bash
   gleipnir-mcp --print-config claude-code -- npx -y @modelcontextprotocol/server-github
   # prints: claude mcp add --transport stdio server-github -- /abs/path/gleipnir-mcp --home ... -- npx -y ...
   ```

   Run what it prints. Options such as `--scope project|user` and `--env KEY=value` go before the server name. Everything after the first `--` is the command Claude Code launches [claude-code-mcp]. For a shared project `.mcp.json`, use the same `command`/`args` as the Claude Desktop entry.

3. **Use it.** Start `claude`, check with `/mcp` that the server is connected, then run `gleipnir report --open`.

## See what your agent did

```bash
gleipnir report --open                 # HTML page: every tool call, args, result/error, integrity check
gleipnir --home ~/.gleipnir --chain mcp-server-github pack -o review.zip   # hand-off pack for someone else
unzip review.zip bundle.zip && gleipnir-verify bundle.zip --expect-key k_ed25519_... --require-full
```

`gleipnir report` reads every chain in `--home`, verifies each one, and writes `gleipnir-report.html`. Without `--home` it uses `./.gleipnir` if that exists, otherwise `$GLEIPNIR_HOME` or `~/.gleipnir` (where the proxy writes). The other `gleipnir` commands default to `./.gleipnir`, so pass `--home ~/.gleipnir` to them. The pack contains `summary.html`, `actions.csv`, `bundle.zip` and `VERIFY.md` with the exact verify command.

## Options

```
gleipnir-mcp [--home DIR] [--system NAME] [--chain NAME] [--anchor local|rekor|none]
             [--redact field,...] -- <server command...>
gleipnir mcp-proxy [same options] -- <server command...>
```

| Option | Meaning |
|---|---|
| `--home` | Where keys and records live. Default `$GLEIPNIR_HOME` or `~/.gleipnir`. |
| `--system` | System name on each record. Default: the server's own `serverInfo.name` from `initialize`. |
| `--chain` | Chain name. Default `mcp-<server>`, derived from the command. If another proxy is already writing that chain (two clients running the same server), the second one uses `mcp-<server>-2`, because a chain has one writer. |
| `--anchor` | `local` (default; a local log, fine for trying it out), `rekor` (segment hashes go to Sigstore Rekor plus an RFC 3161 timestamp, so they are independent of you; needs network), `none`. |
| `--redact` | Comma-separated field names, e.g. `--redact token,password,card_number`. Wherever one of these keys appears in the arguments, the result, the `content[].text` of the result when that text is a JSON object or array (tools often return JSON as text), or the `data` of a JSON-RPC error, the proxy replaces its value with an HMAC before anything is hashed or stored. For JSON text, the record stores the redacted JSON re-serialized; the client still receives the original. Free text that is not JSON is stored as is, because there are no field names to match in it: a secret written into a plain sentence or a log line is not redacted. |
| `--print-config` | `claude-desktop`, `cursor` or `claude-code`: print the snippet instead of running. `--name` sets the server name in it. |

What ends up on each record: `tool.name`, `tool.system`, `args`, `response` (`{status: ok, body: <the JSON-RPC result>}`, or `{status: error, error}` for a JSON-RPC error, an `isError: true` result, a client cancellation, or a call still pending at shutdown), `t.start`/`t.end` (when the proxy saw the request and the response), `agent` = the client's `clientInfo` name and version, and `context.session`, `context.tool_call_id` (the JSON-RPC id) and `context.run_id` (one per proxy process).

## How it behaves

- **Transparent.** Bytes are copied in both directions as they arrive. They are not parsed, buffered or re-encoded on the way through. A copy goes to a background thread that splits it into newline-delimited JSON-RPC messages ([MCP stdio transport][mcp-stdio]), including batches, and pairs each `tools/call` with its response. Notifications, pings, progress messages, server-to-client requests and every other method pass through without being recorded.
- **Never breaks the session.** If recording fails (unwritable home, full disk, a bug), the proxy logs to stderr and keeps forwarding. If the recorder falls far behind, chunks are forwarded but not observed, and a signed note in the chain says so. The same applies to single messages over 64 MiB and to any line the recorder cannot parse or process (invalid JSON, nesting too deep for the parser, and so on). Each of these is forwarded unchanged, and a signed note records its direction, size and the error, saying that tool calls in it may be missing. After 20 such notes, the total goes into one note at shutdown.
- **Reused request ids.** A client should not reuse the id of a request that is still in flight. If one does, the proxy keeps every call: calls with the same id are queued and paired with responses first in, first out. The chain gets a signed note when the collision happens, and another note for each affected action saying its pairing is ambiguous. No call is overwritten or lost. A call that never gets a response is recorded as an error at shutdown.
- **Shutdown.** When the client closes stdin, the server's stdin is closed and the server gets 5 seconds to exit. On SIGTERM/SIGINT/SIGHUP the server is terminated. In both cases calls still waiting for a response are recorded as errors, the open segment is sealed and anchored, and the proxy exits with the server's exit code.
- **Overhead.** One extra pipe hop and a memory copy per chunk. Signing and the disk write (fsync) happen off the forwarding path.

## What it proves, and what it doesn't

A valid bundle shows that the records of tool calls **made through the proxy** were not edited, removed, reordered or inserted after they were written. They were signed with your key, and with `--anchor rekor` they existed no later than the anchor time. It shows what the client asked for and what the server answered.

It does not show:

- **Calls that didn't go through the proxy.** Examples: other servers, remote (HTTP) MCP servers, built-in client tools, a config that bypasses the proxy.
- **That the action really happened in the external system.** A successful result is the server's claim. Outcome checks (reading the system of record back) are not automatic in the proxy. Use the SDK's `verify_outcome`, or reconcile `actions.csv` against the system's own logs.
- **That the records are true at the moment they were signed.** Whoever controls the machine running the proxy controls the signing key in `~/.gleipnir/keys`. For records a third party can rely on, keep the key out of reach of the agent and anchor with `rekor`. See the [threat model](threat-model.md).
- **The model's reasoning or the conversation.** Only tool calls are recorded.

## Limitations

- stdio servers only. Remote servers (streamable HTTP / SSE) are not proxied.
- Record times come from the proxy's clock. Rekor anchoring and the RFC 3161 timestamp bound them from above.
- The agent version on each record is the client's version (`clientInfo`), not the model's.
- `--redact` works by key name. It does not catch secrets inside non-JSON text, inside resource or image content, or under keys you did not list.
- If a client reuses an in-flight request id, the pairing of responses to calls with that id is a first-in-first-out guess. The records flag it, but they cannot resolve it.

[mcp-local]: https://modelcontextprotocol.io/docs/2026-07-28/develop/connect-local-servers
[cursor-mcp]: https://cursor.com/docs/mcp
[claude-code-mcp]: https://docs.claude.com/en/docs/claude-code/mcp
[mcp-stdio]: https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#stdio
