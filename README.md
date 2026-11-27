# qBit Lite

A small, mobile-friendly web UI for [qBittorrent](https://www.qbittorrent.org/). It runs in its own container and talks to qBittorrent's Web UI API. qBittorrent itself is not modified.

- Torrent list: cards on phones, a sortable table on desktop.
- Filters (All / Downloading / Seeding / Stopped / Completed / Active / Errors), search and sorting.
- Live download and upload speeds, free disk space, and a toggle for qBittorrent's alternative speed limits (turtle mode).
- Add `.torrent` files (pick them, or drag them from Finder/Explorer onto the page), with:
  - a folder browser for the save path: you tap your way down one level at a time, and the folders are listed through qBittorrent, so you see exactly what it sees; recent paths are one tap away;
  - a choice per torrent: download to the incomplete folder first and move when done (for example to a fast SSD), or directly to the save path;
  - a category, and an option to add stopped.
- Torrent details with peers: start, stop, reannounce, force recheck, remove, or delete with files.
- Live move progress: when a finished torrent is moved from the incomplete folder to its save path, it shows **Moving NN%**, with the amount copied, speed and time left (optional, see below).
- Automatic turtle mode: unlimited speeds normally, qBittorrent's alternative limits only while something is downloading (optional, see below).
- A first-run setup wizard, and no login if you want it.
- Installable on the phone home screen.

## Install

You need Docker with Docker Compose v2, and qBittorrent with its Web UI enabled (Options → Web UI).

```bash
git clone https://github.com/sorinb99/qbitlite.git
cd qbitlite
cp .env.example .env     # optional: only needed to change the port or set up move progress
docker compose up -d --build
```

Open `http://<server>:8097`. The setup wizard asks for:

1. **qBittorrent's Web UI address.** The wizard looks for it by itself: on the Docker host (common Web UI ports), under usual container names (`qbittorrent`, `gluetun`…), and on ports 8080/8090 of the local network around the address you opened qBit Lite with. Pick what it found, or enter the address as seen from the container:
   - qBittorrent on the same machine with host networking: `http://host.docker.internal:8080`
   - qBittorrent in another container on the same Docker network: `http://<container-name>:8080`
   - qBittorrent on another computer: `http://<its-ip>:8080`
2. **Your qBittorrent Web UI account.**
3. **How qBit Lite should sign in:**

| Option | What it does |
|---|---|
| **No login** (recommended at home) | qBit Lite adds its own network to qBittorrent's *Bypass authentication for clients in whitelisted IP subnets* list. Nobody has to sign in, and your password isn't stored. |
| **Remember my account** | qBit Lite stores the username and password in its config volume (`settings.json`, readable only by the container user) and signs in by itself. |
| **Ask for a login** | Every browser signs in with the qBittorrent account, like qBittorrent's own Web UI. |

With the first two options, anyone who can open qBit Lite can control qBittorrent. Keep it on your local network, or put it behind a reverse proxy with authentication.

You can change this later with the ⚙︎ **Settings** button → **Run setup again**.

### How "No login" works

qBittorrent can skip the login for chosen IP ranges. qBit Lite runs in its own Docker network with a fixed subnet (`172.31.250.0/24` by default, `QBIT_LITE_SUBNET`), detects it, and adds it to that list through qBittorrent's API. qBittorrent's own Web UI still asks for a password; only qBit Lite is let in.

This works when qBittorrent runs on the same machine as qBit Lite. If qBittorrent is on another computer, it sees requests coming from the Docker host's address instead. The wizard detects this and tells you: enter that address (for example `192.168.1.20/32`) under **Network to whitelist**, or choose **Remember my account**.

Running the setup again doesn't remove the network from qBittorrent's whitelist. Remove it in qBittorrent → Options → Web UI if you no longer want it.

### Move progress (optional)

qBittorrent doesn't report how far a move has got. qBit Lite measures it from the files that have already reached the destination folder, so it needs read-only access to qBittorrent's folders, **at the same paths qBittorrent uses**. Set them in `.env`:

| Variable | Example | Description |
|---|---|---|
| `QBIT_MEDIA_HOST` / `QBIT_MEDIA_PATH` | `/srv/media` / `/downloads` | The host folder with your downloads, and the path qBittorrent sees it as. |
| `QBIT_INCOMPLETE_HOST` / `QBIT_INCOMPLETE_PATH` | `/srv/incomplete` / `/incomplete` | The same for the incomplete folder. |

If qBittorrent runs directly on the host (not in a container), both paths are the same. Without these mounts a moving torrent just shows "Moving…". Moves within one disk are instant renames, so a percentage only appears when data is actually copied between disks.

### Automatic turtle mode (optional)

Open ⚙︎ **Settings** → **Speed** to set qBittorrent's normal and turtle (alternative) limits in MB/s (empty = unlimited) and turn on **Turtle mode while downloading**. qBit Lite then checks qBittorrent every 10, 30 or 60 seconds:

- when a torrent starts downloading, it turns turtle mode on;
- when nothing has been downloading for the chosen delay (1, 2 or 5 minutes), it turns it off again.

For example: no upload limit normally, and 5 MB/s upload while you download, so seeding doesn't slow your downloads. Changes apply immediately, no restart needed. qBit Lite only switches when the wanted state changes, so tapping the turtle button by hand still works until the next change. The turtle button shows an **A** badge while automation is on.

It runs inside the qBit Lite container, so it needs the **No login** or **Remember my account** option (with **Ask for a login** qBit Lite has no session of its own). Settings are kept in `automation.json` in the config volume.

## Configuration reference

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8097` | Port of the web UI on the host. |
| `QBIT_LITE_SUBNET` | `172.31.250.0/24` | Subnet of qBit Lite's Docker network. Change it only if it clashes with one of your networks, then run the setup again. |
| `QBIT_MEDIA_HOST`, `QBIT_MEDIA_PATH`, `QBIT_INCOMPLETE_HOST`, `QBIT_INCOMPLETE_PATH` | *(empty)* | Move progress, see above. |
| `QBIT_URL` | *(empty)* | Skips the wizard: qBittorrent's address. |
| `QBIT_USERNAME` / `QBIT_PASSWORD` | *(empty)* | With `QBIT_URL`: qBit Lite signs in with this account. |
| `QBIT_AUTH_BYPASS` | `false` | With `QBIT_URL` and no username: `true` if qBittorrent already whitelists qBit Lite's network. Otherwise every browser signs in. |

The wizard's settings are kept in the `config` Docker volume. Environment variables take precedence over them.

### Updating

```bash
git pull
docker compose up -d --build
```

Settings are kept in the `config` volume.

## How it works

`app/server.py` is a Python standard-library server. It serves the single-page UI (`app/static/index.html`) and forwards `/api/v2/*` to qBittorrent, rewriting the `Host`, `Origin` and `Referer` headers so that qBittorrent's CSRF protection accepts the requests.

In "Ask for a login" mode the session cookie is passed through to the browser and kept for 30 days. qBittorrent still expires idle sessions according to its own setting, and the UI then asks you to sign in again.

qBittorrent bans an IP after several failed logins. All requests come from this container's IP, so qBit Lite stops forwarding logins after 3 failures in 5 minutes, before qBittorrent's ban kicks in.

Tested with qBittorrent 5.2 (Web API 2.15). Older 4.x versions are also supported: the UI uses `pause`/`resume` instead of `stop`/`start` when needed.

### Security

- qBit Lite has no accounts of its own. Before the setup is finished, anyone who opens it can run the setup. Afterwards only someone who can already control qBittorrent through qBit Lite can change it.
- Don't expose the port to the internet.
