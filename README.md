
# limitrr

> Note: this was vibe-coded with ChatGPT 5.2 as a one-shot. Surprisingly, it works.

A tiny Go service that throttles qBittorrent when remote users are streaming from Jellyfin.

- Event-driven via Jellyfin Webhook plugin (no polling)
- Detects remote vs local from the Jellyfin client RemoteEndPoint
- When ≥ 1 remote playback is active:
  - QBT_MODE=alt (recommended): enables qBittorrent Alternative Speed Limits (“turtle mode”)
  - QBT_MODE=global: sets a global download limit (bytes/sec)

---

## How it works

1. Jellyfin sends a webhook on PlaybackStart / PlaybackStop
2. limitrr tracks “active remote playbacks”
3. If any remote playback exists → throttle qBittorrent, else unthrottle

Remote is defined as any IP not in LOCAL_CIDRS.

---

## Requirements

- Jellyfin server + Webhook plugin installed/enabled
- qBittorrent with WebUI enabled + reachable from limitrr
- Go 1.21+ (or build a container if you prefer)

---

## Configuration (env vars)

| Variable | Required | Default | Notes |
|---|---:|---:|---|
| LISTEN_ADDR | no | :8089 | HTTP listen address |
| WEBHOOK_KEY | yes | - | Shared secret; sent as X-Webhook-Key |
| QBT_BASE_URL | yes | - | e.g. <http://qbittorrent:8080> |
| QBT_USER | no | - | If qBittorrent requires auth |
| QBT_PASS | no | - | If qBittorrent requires auth |
| QBT_MODE | no | alt | alt (turtle mode) or global |
| QBT_GLOBAL_LIMIT_BPS | no | 5000000 | bytes/sec, only used in global |
| LOCAL_CIDRS | no | common private ranges | Comma-separated CIDRs treated as “local” |

Default LOCAL_CIDRS includes:

- 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,::1/128,fc00::/7,fe80::/10

---

## qBittorrent setup

### Recommended: Alternative Speed Limits (turtle mode)

1. In qBittorrent WebUI: configure Alternative Rate Limits (download/upload)
2. Run limitrr with QBT_MODE=alt

When remote streams start, it toggles turtle mode on; when they stop, it toggles it off.

### Optional: Global download limit

Run with:

- QBT_MODE=global
- QBT_GLOBAL_LIMIT_BPS=5000000 (example: ~5 MB/s)

---

## Jellyfin Webhook plugin setup

Install the webhook plugin and create the webhook.

Destination settings:

- Name: limitrr
- URL: http://<limitrr-host>:8089/webhook

Enable notification types:

- Playback Start
- Playback Stop

Add Request Header:

- Key: X-Webhook-Key
- Value: <WEBHOOK_KEY>

### Body template

Use this template:

    {
      "event": "{{NotificationType}}",
      "username": "{{Username}}",
      "deviceId": "{{DeviceId}}",
      "mediaSourceId": "{{MediaSourceId}}",
      "itemId": "{{ItemId}}",
      "remoteEndPoint": "{{RemoteEndPoint}}"
    }

Notes:

- Avoid using the Webhook plugin json_encode helper unless you guard it; it can throw if you try to encode a null value (often RemoteEndPoint).
- Live TV may not emit these playback notifications depending on your Jellyfin/Webhook behavior.

---

## Run

    export WEBHOOK_KEY="$(openssl rand -hex 24)"
    export QBT_BASE_URL="http://qbittorrent:8080"
    export QBT_USER="admin"
    export QBT_PASS="secret"
    export QBT_MODE="alt"   # recommended

    go build
    ./limitrr

Health check:

- GET /healthz → 200 OK

---

## Troubleshooting

- Webhook plugin error "ArgumentNullException: valueToEncode"
  You used json_encode on a field that is null (often RemoteEndPoint). Use the safe body template above.

- RemoteEndPoint is your reverse proxy IP
  If Jellyfin sits behind Traefik/Nginx, Jellyfin may only see the proxy’s IP unless configured to trust forwarded headers. Fix that first or your remote vs local logic will be wrong.

- Throttle seems stuck on
  If Jellyfin misses a PlaybackStop event (crash/network), limitrr may keep a remote stream “active”. Restarting limitrr resets state. (A periodic “reconcile sessions” mode can be added later if needed.)

---

## License

GPLv3. See LICENSE.
