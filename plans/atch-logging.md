# Persistent Session Logging (Plan)

Downstream-only design note. Not implemented yet. Inspired by
[atch](https://github.com/dand-oss/atch), which keeps a durable,
replayable record of terminal sessions.

## Goals

- Record the raw PTY byte stream of every session to disk as it is
  produced, so a history of what happened survives detach, gateway
  restarts, and reboots.
- Expose `zmosh tail <session>` to follow and inspect that record.

## Non-Goals

- Logging is strictly separate from attach, reconnect, and restore.
  Nothing in the attach or restore paths reads or writes the log, and
  no logged byte is ever replayed into a client terminal by these
  features.
- The ghostty-vt terminal state is never persisted. The log holds raw
  PTY bytes only; any rendering is done by the tail command's own
  fresh VT instance.

## Design Sketch

1. **Bounded log files.** Each session appends to
   `$ZMX_DIR/logs/<session>.log`, size-capped (default a few MB per
   session). When the cap is reached the log is truncated from the
   front (ring-style) rather than growing without bound.

2. **Safe tailing.** `zmosh tail <session>` opens the log at or near
   the end and follows it, similar to `tail -f`. It never replays the
   full history to an attaching terminal — a fresh attach still
   receives only genuine PTY bytes or an explicit `--restore`
   snapshot. `--lines N` reads the last N bytes and decodes them
   through a local VT before printing.

3. **Reboot persistence.** Logs live on disk, not in the daemon, so
   they survive reboots and daemon restarts by construction. Stale
   logs for dead sessions are pruned on a retention timer (for
   example, 7 days).

4. **Write path.** The daemon appends to the log in its existing
   single-threaded poll loop — no threads, no new IPC. A failed or
   full log degrades to "no history", never to a failed session.

## Open Questions

- Should `zmosh history` read from this log or keep its current
  scrollback source?
- Retention policy details (per-session cap vs. global cap).
