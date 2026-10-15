"""A tiny stdio MCP server for tests: newline-delimited JSON-RPC, no dependencies.

Tools: ``refund`` (structured result), ``fails`` (isError result), unknown names (JSON-RPC error),
``big`` (a large text result), ``slow`` (sleeps ``delay`` seconds).
Every message it receives is appended to the file named by $FAKE_MCP_LOG, if set.
"""

import json
import os
import sys
import time

LOG = os.environ.get("FAKE_MCP_LOG")


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def handle(msg):
    method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": params.get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "fake-payments", "version": "0.0.1"}}}
    if method == "notifications/initialized":
        send({"jsonrpc": "2.0", "method": "notifications/message",
              "params": {"level": "info", "data": "ready   with a line separator"}})
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": [
            {"name": n, "inputSchema": {"type": "object"}} for n in ("refund", "fails", "big", "slow")]}}
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        if name == "refund":
            sc = {"refund_id": "R-" + str(args.get("order")), "amount": args.get("amount")}
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": json.dumps(sc)}], "structuredContent": sc, "isError": False}}
        if name == "fails":
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": "refund not allowed"}], "isError": True}}
        if name == "big":
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": "x" * int(args.get("size", 1000))}]}}
        if name == "slow":
            time.sleep(float(args.get("delay", 0)))
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": []}}
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown tool {name}",
                                                       "data": {"tool": name}}}
    if method == "notifications/cancelled":
        return None
    if mid is not None and method is not None:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}
    return None


def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        if LOG:
            with open(LOG, "a", encoding="utf-8") as fh:
                fh.write(line if line.endswith("\n") else line + "\n")
        msg = json.loads(line)
        if isinstance(msg, list):
            out = [r for r in (handle(m) for m in msg) if r is not None]
            if out:
                send(out)
            continue
        reply = handle(msg)
        if reply is not None:
            send(reply)


if __name__ == "__main__":
    main()
