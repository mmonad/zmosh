<h1>
<p align="center">
  <img src="./docs/logo.png" alt="Logo" width="128">
  <br>zmosh
</h1>
<p align="center">
  Session persistence with auto-reconnect for terminal processes.
  <br />
  CLI + C library (macOS, iOS, Linux)
  <br />
  Built on <a href="https://github.com/neurosnap/zmx">zmx</a> · Powered by <a href="https://github.com/ghostty-org/ghostty">libghostty-vt</a>
</p>

## what is zmosh

zmosh is a fork of [zmx](https://github.com/neurosnap/zmx) that adds **encrypted UDP auto-reconnect** for remote sessions — the best idea from [mosh](https://mosh.org), applied to zmx's session persistence model.

Locally, zmosh **is** zmx. Every local feature works identically. The new capabilities only activate when you use `zmosh attach -r <host> <session>` to connect to a remote machine.

**How remote mode works:** zmosh bootstraps an SSH connection to start a UDP gateway on the remote host, negotiates a one-time XChaCha20-Poly1305 session key, then switches to encrypted UDP datagrams. If your IP changes (Wi-Fi → cellular, VPN toggle, laptop sleep/wake), the session stays alive. No reconnect. No lost state.

## features

**Local sessions** (inherited from zmx):
- Persist terminal shell sessions (pty processes)
- Attach and detach without killing the session
- Native terminal scrollback
- Multiple clients can connect to the same session
- Re-attaching restores previous terminal state and output
- Send commands to a session without attaching
- Print scrollback history in plain text, VT escape codes, or HTML
- Works on mac and linux
- Does **NOT** provide windows, tabs, or splits — that's your window manager's job

**Remote sessions** (zmosh additions):
- Encrypted UDP transport with XChaCha20-Poly1305 (Zig stdlib, zero external crypto deps)
- Auto-reconnect through IP changes, network switches, and sleep/wake cycles
- IP roaming — authenticated packets from a new address automatically update the peer
- Anti-replay protection via monotonic sequence numbers
- Heartbeat-based connection state detection with configurable timeouts
- MTU-safe chunking to avoid UDP fragmentation
- Gateway architecture — network layer is separate from the daemon; local sessions are untouched
- Status bar notification when connection is temporarily lost

## comparison with remote terminal tools

| Feature | zmosh | mosh | Eternal Terminal | tssh |
| --- | --- | --- | --- | --- |
| Encrypted transport | ✓ (XChaCha20-Poly1305) | ✓ (AES-128-OCB) | ✓ (AES) | ✓ (SSH) |
| UDP auto-reconnect | ✓ | ✓ | ✗ (TCP) | ✗ (TCP) |
| IP roaming | ✓ | ✓ | ✗ | ✗ |
| Session persistence (detach/reattach) | ✓ | ✗ | ✓ | ✗ |
| Terminal state restore | ✓ (libghostty-vt) | ✓ (own VT) | ✓ | ✗ |
| Native terminal scrollback | ✓ | ✗ | ✓ | ✓ |
| Multiple clients per session | ✓ | ✗ | ✗ | ✗ |
| Local sessions (no network) | ✓ | ✗ | ✗ | ✗ |
| Anti-replay protection | ✓ | ✓ | ✓ | ✓ |
| Predictive local echo | ✗ | ✓ | ✗ | ✗ |
| Window management | ✗ | ✗ | ✗ | ✗ |

## install

### homebrew

```bash
brew tap mmonad/zmosh
brew install zmosh
```

### arch linux (aur)

```bash
yay -S zmosh-git
# or
paru -S zmosh-git
```

### src

- Requires zig `v0.15`
- Clone the repo
- Run build cmd

```bash
zig build -Doptimize=ReleaseSafe --prefix ~/.local
# be sure to add ~/.local/bin to your PATH
```

### build targets

| Command | Output | Description |
| --- | --- | --- |
| `zig build` | `zmosh` binary | Build for host platform |
| `zig build test` | — | Run unit tests |
| `zig build check` | — | Type-check only (used by ZLS build-on-save) |
| `zig build release` | `zig-out/dist/*.tar.gz` | Release tarballs (macOS builds all platforms, Linux builds Linux only) |
| `zig build lib` | `libzmosh.a` + headers | Static C library for host platform |
| `zig build macos-lib` | `libzmosh-macos.a` | Static library for macOS aarch64 (requires macOS) |
| `zig build ios-lib` | `zmosh-ios.xcframework` | XCFramework for iOS device + simulator (requires macOS) |
| `zig build xcframework` | `zmosh.xcframework` | XCFramework with all Apple slices: macOS + iOS + iOS simulator (requires macOS) |

### libzmosh (C library)

zmosh exposes a C API (`include/zmosh.h`) for embedding the remote session client into native apps. The API is callback-driven and designed for event loop integration:

```c
// Connect to a remote zmosh gateway
zmosh_session_t *session = zmosh_connect(
    host, port, key_base64,
    rows, cols,
    output_cb,   // called with terminal output bytes
    state_cb,    // called on connection state changes (may be NULL)
    end_cb,      // called when session ends (may be NULL)
    ctx, &status
);

// Integrate with your event loop (GCD, kqueue, poll, etc.)
int fd = zmosh_get_fd(session);

// Call when fd is readable, or periodically for heartbeats
zmosh_poll(session);

// Send terminal input and resize events
zmosh_send_input(session, data, len);
zmosh_resize(session, rows, cols);

// Cleanup
zmosh_disconnect(session);
```

To build the XCFramework for an iOS/macOS app (must be run on macOS):

```bash
zig build xcframework
# produces zig-out/zmosh.xcframework — drag into Xcode
```

## usage

> [!IMPORTANT]
> We recommend closing the terminal window to detach from the session but you can also press `ctrl+\` or run `zmosh detach`.

```
Usage: zmosh <command> [args]

Commands:
  [a]ttach <name> [command...]   Attach to session, creating session if needed
  [a]ttach -r <host> <name>      Attach to remote session via UDP
  [r]un <name> [command...]      Send command without attaching, creating session if needed
  [s]erve <name>                 Start UDP gateway for remote access
  [d]etach                       Detach all clients from current session (ctrl+\ for current client)
  [l]ist [--short]               List active sessions
  [c]ompletions <shell>          Completion scripts for shell integration (bash, zsh, or fish)
  [k]ill <name>                  Kill a session and all attached clients
  [hi]story <name> [--vt|--html] Output session scrollback (--vt or --html for escape sequences)
  [w]ait <name>...               Wait for session tasks to complete
  [v]ersion                      Show version information
  [h]elp                         Show this help message
```

### local examples

```bash
zmosh attach dev              # start a shell session
zmosh a dev nvim .            # start nvim in a persistent session
zmosh attach build make -j8   # run a build, reattach to check progress
zmosh attach mux dvtm         # run a multiplexer inside zmosh

zmosh run dev cat README.md   # run the command without attaching to the session
zmosh r dev cat CHANGELOG.md  # alias
echo "ls -lah" | zmosh r dev # use stdin to run the command

zmosh r tests go test ./...   # run your tests in the background
zmosh wait tests              # waits for tests to complete
```

### remote examples

```bash
# attach to a remote session over encrypted UDP
# (bootstraps via SSH, then switches to UDP)
zmosh attach -r myserver dev

# short form
zmosh a -r myserver dev

# run a build on a remote machine, come back later to check
zmosh a -r build-box build make -j16
```

The remote workflow:
1. zmosh SSHs into `<host>` and runs `zmosh serve <session>`
2. The remote gateway binds a UDP port and prints a connect line with the session key
3. zmosh reads the key, closes the SSH pipes, and switches to encrypted UDP
4. If your network drops, the client shows a status bar and reconnects automatically when connectivity returns

## shell prompt

When you attach to a session, we provide an environment variable `ZMX_SESSION` which contains the session name.

We recommend checking for that env var inside your prompt and displaying some indication there.

### fish

Place this file in `~/.config/fish/config.fish`:

```fish
functions -c fish_prompt _original_fish_prompt 2>/dev/null

function fish_prompt --description 'Write out the prompt'
  if set -q ZMX_SESSION
    echo -n "[$ZMX_SESSION] "
  end
  _original_fish_prompt
end
```

### bash and zsh

Depending on the shell, place this in either `.bashrc` or `.zshrc`:

```bash
if [[ -n $ZMX_SESSION ]]; then
  export PS1="[$ZMX_SESSION] ${PS1}"
fi
```

### powerlevel10k zsh theme

[powerlevel10k](https://github.com/romkatv/powerlevel10k) is a theme for zsh that overwrites the default prompt statusline.

Place this in `.zshrc`:

```bash
function prompt_my_zmx_session() {
  if [[ -n $ZMX_SESSION ]]; then
    p10k segment -b '%k' -f '%f' -t "[$ZMX_SESSION]"
  fi
}
POWERLEVEL9K_RIGHT_PROMPT_ELEMENTS+=my_zmx_session
```

### oh-my-posh

[oh-my-posh](https://ohmyposh.dev) is a popular shell themeing and prompt engine. This code will display an icon and session name as part of the prompt if (and only if) you have a session active:

```
[[blocks.segments]]
   template = '{{ if .Env.ZMX_SESSION }} {{ .Env.ZMX_SESSION }}{{ end }}'
   foreground = 'p:orange'
   background = 'p:black'
   type = 'text'
   style = 'plain'
```

## shell completion

Shell auto-completion for commands and session names can be enabled using the `completions` subcommand. Once configured, you'll get auto-complete for both local commands and sessions:

```bash
zmosh completions bash  # or zsh, fish
```

### bash

Add this to your `.bashrc` file:

```bash
if command -v zmosh &> /dev/null; then
  eval "$(zmosh completions bash)"
fi
```

### zsh

Add this to your `.zshrc` file:

```zsh
if command -v zmosh &> /dev/null; then
  eval "$(zmosh completions zsh)"
fi
```

### fish

Add this to your `.config/fish/config.fish` file:

```fish
if type -q zmosh
  zmosh completions fish | source
end
```

## session prefix

We allow users to set an environment variable `ZMX_SESSION_PREFIX` which will prefix the name of the session for all commands. This means if that variable is set, every command that accepts a session will be prefixed with it.

```bash
export ZMX_SESSION_PREFIX="d."
zmosh a runner # ZMX_SESSION=d.runner
zmosh a tests  # ZMX_SESSION=d.tests
zmosh k tests  # kills d.tests
zmosh wait     # suspends until all tasks prefixed with "d." are complete
```

## philosophy

The entire argument for session persistence tools instead of something like `tmux` that has windows, panes, splits, etc. is that window management should be handled by your OS window manager. By using something like `tmux` you now have redundant functionality in your dev stack: a window manager for your OS and a window manager for your terminal. Further, in order to use modern terminal features, your terminal emulator **and** `tmux` need to have support for them. This holds back the terminal enthusiast community and feature development.

zmosh focuses on two things: **session persistence** and **network resilience**. Window management is your OS's job.

## ssh workflow

Using zmosh with `ssh` is a first-class citizen. Instead of using `ssh` to remote into your system with a single terminal and `n` tmux panes, you open `n` terminals and run `ssh` for all of them. This might sound tedious, but there are tools to make this a delightful workflow.

First, create an `ssh` config entry for your remote dev server:

```bash
Host = d.*
    HostName 192.168.1.xxx

    RemoteCommand zmosh attach %k
    RequestTTY yes
    ControlPath ~/.ssh/cm-%r@%h:%p
    ControlMaster auto
    ControlPersist 10m
```

Now you can spawn as many terminal sessions as you'd like:

```bash
ssh d.term
ssh d.irc
ssh d.pico
ssh d.dotfiles
```

This will create or attach to each session and since we are using `ControlMaster` the same `ssh` connection is reused for every call to `ssh` for near-instant connection times.

Now you can use the [`autossh`](https://linux.die.net/man/1/autossh) tool to make your ssh connections auto-reconnect. For example, if you have a laptop and close/open your laptop lid it will automatically reconnect all your ssh connections:

```bash
autossh -M 0 -q d.term
```

Or create an `alias`/`abbr`:

```fish
abbr -a ash "autossh -M 0 -q"
```

```bash
ash d.term
ash d.irc
ash d.pico
ash d.dotfiles
```

> [!TIP]
> For remote sessions that need to survive network changes without SSH reconnecting, use `zmosh attach -r <host> <session>` instead. The UDP transport handles roaming natively — no `autossh` needed.

## socket file location

Each session gets its own unix socket file. The default location depends on your environment variables (checked in priority order):

1. `ZMX_DIR` => uses exact path (e.g., `/custom/path`)
1. `XDG_RUNTIME_DIR` => uses `{XDG_RUNTIME_DIR}/zmx` (recommended on Linux, typically results in `/run/user/{uid}/zmx`)
1. `TMPDIR` => uses `{TMPDIR}/zmx-{uid}` (appends uid for multi-user safety)
1. `/tmp` => uses `/tmp/zmx-{uid}` (default fallback, appends uid for multi-user safety)

## debugging

We store global logs for cli commands in `{socket_dir}/logs/zmx.log`. We store session-specific logs in `{socket_dir}/logs/{session_name}.log`. Right now they are enabled by default and cannot be disabled. The idea here is to help with initial development until we reach a stable state.

## impl

### local mode

- The `daemon` and client processes communicate via a unix socket
- Both `daemon` and `client` loops leverage `poll()`
- Each session creates its own unix socket file
- We restore terminal state and output using `libghostty-vt`

### libghostty-vt

We use [libghostty-vt](https://github.com/ghostty-org/ghostty) to restore the previous state of the terminal when a client re-attaches to a session.

How it works:

- user creates session `zmosh attach term`
- user interacts with terminal stdin
- stdin gets sent to pty via daemon
- daemon sends pty output to client *and* `ghostty-vt`
- `ghostty-vt` holds terminal state and scrollback
- user disconnects
- user re-attaches to session
- `ghostty-vt` sends terminal snapshot to client stdout

In this way, `ghostty-vt` doesn't sit in the middle of an active terminal session, it simply receives all the same data the client receives so it can re-hydrate clients that connect to the session. This enables users to pick up where they left off as if they didn't disconnect from the terminal session at all. It also has the added benefit of being very fast, the only thing sitting in-between you and your PTY is a unix socket.

### remote mode (gateway architecture)

Remote sessions use a **gateway** pattern that bridges encrypted UDP to the existing local IPC, leaving the daemon completely untouched:

```
┌────────────┐  encrypted UDP  ┌────────────────┐ unix socket  ┌────────┐
│   client   │ ◄─────────────► │    gateway     │ ◄──────────► │ daemon │
│  (local)   │ XChaCha20-P1305 │ (zmosh serve)  │     IPC      │ (pty)  │
└────────────┘                 └────────────────┘              └────────┘
```

- `zmosh serve <session>` binds a UDP port, generates a session key, and connects to the daemon's unix socket as a regular client
- The client reads the key over SSH, then communicates directly via UDP
- Heartbeats (1s interval) detect connectivity loss; the client shows a status bar during disconnection
- If no packets arrive for 24h, the gateway shuts down (configurable `alive_timeout_ms`)
- Anti-replay: sequence numbers are monotonically increasing; packets with `seq <= max_recv_seq` don't update peer state
- Roaming: when an authenticated packet arrives from a new IP, the peer address is updated — no handshake needed

## a smol contract

- Write programs that solve a well defined problem.
- Write programs that behave the way most users expect them to behave.
- Write programs that a single person can maintain.
- Write programs that compose with other smol tools.
- Write programs that can be finished.

## known issues

- Terminal state rehydration with nested sessions through SSH: host A `zmosh` -> SSH -> host B `zmosh`
  - Specifically cursor position gets corrupted
- When re-attaching and kitty keyboard mode was previously enabled, we try to re-send that CSI query to re-enable it
  - Some programs don't know how to handle that CSI query (e.g. `psql`) so when you type it echos kitty escape sequences erroneously

## prior art and acknowledgements

zmosh is built on top of [zmx](https://github.com/neurosnap/zmx) by [neurosnap](https://github.com/neurosnap). The local session persistence model, daemon architecture, and IPC protocol are all zmx's work. zmosh adds the network transport layer.

Terminal state restoration is powered by [libghostty-vt](https://github.com/ghostty-org/ghostty) from the [Ghostty](https://ghostty.org) project.

The UDP auto-reconnect design draws from:

- **[mosh](https://mosh.org)** — The original UDP-based remote terminal. Proved that roaming + encrypted datagrams is the right model for unreliable networks. zmosh borrows the core idea of authenticated datagrams with IP roaming.
- **[Eternal Terminal](https://eternalterminal.dev)** — Showed that session persistence and network resilience can coexist. Uses TCP with reconnect rather than UDP.
- **[tssh](https://github.com/trzsz/trzsz-ssh)** — SSH client with trzsz file transfer support and other enhancements.

### other session persistence tools

- **[shpool](https://github.com/shell-pool/shpool)** — Lighter weight alternative to tmux. Provides persistent sessions with native scrollback.
- **[abduco](https://github.com/martanne/abduco)** — Session management that pairs with dvtm for a simpler alternative to tmux.
- **[dtach](https://github.com/crigler/dtach)** — Minimal detach feature emulation from screen.

## comparison with session persistence tools

| Feature | zmosh | zmx | shpool | abduco | dtach | tmux |
| --- | --- | --- | --- | --- | --- | --- |
| 1:1 Terminal emulator features | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| Terminal state restore | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ |
| Window management | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Multiple clients per session | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Native scrollback | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| Auto-daemonize | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Daemon per session | ✓ | ✓ | ✗ | ✓ | ✓ | ✗ |
| Session listing | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ |
| Encrypted remote sessions | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| UDP auto-reconnect | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| IP roaming | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |

## community tools

- [zsm](https://github.com/mdsakalu/zmx-session-manager) — TUI session manager for zmx. List, preview, filter, and kill sessions from an interactive terminal UI.
- [zig-skills](https://github.com/rudedogg/zig-skills) — Claude Code skill for up-to-date Zig 0.15.x patterns. Powers this project's AI-assisted development, avoiding outdated patterns from training data.
