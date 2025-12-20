package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	jellyfin "github.com/sj14/jellyfin-go/api"
)

type Config struct {
	ListenAddr string
	WebhookKey string // shared secret header

	// qBittorrent
	QBTBaseURL  string
	QBTUser     string
	QBTPass     string
	QBTMode     string // "alt" (recommended) or "global"
	GlobalLimit int64  // bytes/sec when throttled; only used in "global" mode

	// Local networks (CIDRs). Anything inside these is "local" => no throttle.
	LocalCIDRs []string
}

type WebhookEvent struct {
	Event         string `json:"event"` // e.g. "PlaybackStart", "PlaybackStop"
	Username      string `json:"username"`
	DeviceID      string `json:"deviceId"`
	MediaSourceID string `json:"mediaSourceId"`
	ItemID        string `json:"itemId"`
	RemoteEndPt   string `json:"remoteEndPoint"` // often "IP:port"
}

type Controller struct {
	cfg Config

	mu             sync.Mutex
	activeRemote   map[string]WebhookEvent // key -> event
	lastThrottled  *bool
	localNets      []*net.IPNet
	qbt            *QbtAPI
	jellyfinClient *jellyfin.APIClient
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	ctrl, err := NewController(cfg)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", ctrl.handleWebhook)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("listening on %s", cfg.ListenAddr)
	log.Fatal(srv.ListenAndServe())
}

func loadConfig() (Config, error) {
	get := func(k, def string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return def
	}

	cfg := Config{
		ListenAddr: get("LISTEN_ADDR", ":8089"),
		WebhookKey: get("WEBHOOK_KEY", ""),

		QBTBaseURL:  get("QBT_BASE_URL", ""),
		QBTUser:     get("QBT_USER", ""),
		QBTPass:     get("QBT_PASS", ""),
		QBTMode:     get("QBT_MODE", "alt"),                            // alt = turtle mode
		GlobalLimit: mustInt64(get("QBT_GLOBAL_LIMIT_BPS", "5000000")), // 5 MB/s default

		LocalCIDRs: strings.Split(get("LOCAL_CIDRS",
			"127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,::1/128,fc00::/7,fe80::/10"), ","),
	}

	if cfg.QBTBaseURL == "" {
		return Config{}, errors.New("QBT_BASE_URL is required (e.g. http://qbittorrent:8080)")
	}
	if cfg.WebhookKey == "" {
		return Config{}, errors.New("WEBHOOK_KEY is required (use a random secret; sent as X-Webhook-Key header)")
	}
	return cfg, nil
}

func mustInt64(s string) int64 {
	var n int64
	_, _ = fmt.Sscan(s, &n)
	return n
}

func NewController(cfg Config) (*Controller, error) {
	localNets := make([]*net.IPNet, 0, len(cfg.LocalCIDRs))
	for _, c := range cfg.LocalCIDRs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid LOCAL_CIDRS entry %q: %w", c, err)
		}
		localNets = append(localNets, ipnet)
	}

	qbt, err := NewQbtAPI(cfg.QBTBaseURL, cfg.QBTUser, cfg.QBTPass)
	if err != nil {
		return nil, err
	}

	// Jellyfin client is optional here, but wired in for later extensions.
	// jellyfin-go expects DefaultHeader Authorization: MediaBrowser Token="<API_TOKEN>" :contentReference[oaicite:4]{index=4}
	jcfg := &jellyfin.Configuration{
		Servers:       jellyfin.ServerConfigurations{{URL: "http://unused"}},
		DefaultHeader: map[string]string{},
	}
	jc := jellyfin.NewAPIClient(jcfg)

	return &Controller{
		cfg:            cfg,
		activeRemote:   map[string]WebhookEvent{},
		localNets:      localNets,
		qbt:            qbt,
		jellyfinClient: jc,
	}, nil
}

func (c *Controller) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Webhook-Key") != c.cfg.WebhookKey {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var ev WebhookEvent
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad json"))
		return
	}

	isRemote := c.isRemoteClient(ev.RemoteEndPt)
	key := c.eventKey(ev)

	c.mu.Lock()
	switch strings.ToLower(ev.Event) {
	case "playbackstart":
		if isRemote {
			c.activeRemote[key] = ev
		}
	case "playbackstop":
		delete(c.activeRemote, key)
	default:
		// Ignore other events
	}
	remoteCount := len(c.activeRemote)
	c.mu.Unlock()

	// Reconcile throttling
	shouldThrottle := remoteCount > 0
	if err := c.applyThrottle(shouldThrottle); err != nil {
		log.Printf("applyThrottle=%v failed: %v", shouldThrottle, err)
	}

	w.WriteHeader(http.StatusOK)
}

func (c *Controller) eventKey(ev WebhookEvent) string {
	// Stable key across start/stop for the same playback session:
	// DeviceId + MediaSourceId is generally unique per stream.
	return ev.DeviceID + ":" + ev.MediaSourceID
}

func (c *Controller) isRemoteClient(remoteEndPoint string) bool {
	ip := parseIP(remoteEndPoint)
	if ip == nil {
		// If we can't parse it, play it safe and treat as remote.
		return true
	}
	for _, n := range c.localNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

func parseIP(s string) net.IP {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// Common cases: "1.2.3.4:5678", "[2001:db8::1]:1234", or just "1.2.3.4"
	if host, _, err := net.SplitHostPort(s); err == nil {
		return net.ParseIP(host)
	}
	// If it had no port
	s = strings.Trim(s, "[]")
	return net.ParseIP(s)
}

func (c *Controller) applyThrottle(throttle bool) error {
	c.mu.Lock()
	if c.lastThrottled != nil && *c.lastThrottled == throttle {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch strings.ToLower(c.cfg.QBTMode) {
	case "alt":
		// Recommended: configure qBittorrent's Alternative Speed Limits in the UI,
		// then just flip "turtle mode" on/off via the API.
		if err := c.qbt.SetAltSpeedLimitsEnabled(ctx, throttle); err != nil {
			return err
		}
	case "global":
		if throttle {
			if err := c.qbt.SetGlobalDownloadLimit(ctx, c.cfg.GlobalLimit); err != nil {
				return err
			}
		} else {
			// 0 typically means "unlimited" for global limits in qBittorrent Web API usage.
			if err := c.qbt.SetGlobalDownloadLimit(ctx, 0); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown QBT_MODE %q (use alt or global)", c.cfg.QBTMode)
	}

	c.mu.Lock()
	c.lastThrottled = &throttle
	c.mu.Unlock()

	log.Printf("throttle=%v applied (mode=%s)", throttle, c.cfg.QBTMode)
	return nil
}

/************ qBittorrent Web API (minimal) ************/

type QbtAPI struct {
	base string
	hc   *http.Client
	user string
	pass string
}

func NewQbtAPI(baseURL, user, pass string) (*QbtAPI, error) {
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("QBT_BASE_URL must include scheme, got %q", baseURL)
	}
	jar, _ := cookiejar.New(nil)
	return &QbtAPI{
		base: strings.TrimRight(baseURL, "/"),
		hc: &http.Client{
			Timeout: 10 * time.Second,
			Jar:     jar,
		},
		user: user,
		pass: pass,
	}, nil
}

func (q *QbtAPI) ensureLogin(ctx context.Context) error {
	if q.user == "" && q.pass == "" {
		// qBittorrent can allow "bypass localhost auth"; in that case, no login needed.
		return nil
	}
	form := url.Values{}
	form.Set("username", q.user)
	form.Set("password", q.pass)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, q.base+"/api/v2/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := q.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("qbt login failed: %s", resp.Status)
	}
	return nil
}

func (q *QbtAPI) SetGlobalDownloadLimit(ctx context.Context, limitBps int64) error {
	if err := q.ensureLogin(ctx); err != nil {
		return err
	}
	form := url.Values{}
	form.Set("limit", fmt.Sprintf("%d", limitBps))

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, q.base+"/api/v2/transfer/setDownloadLimit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := q.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("setDownloadLimit failed: %s", resp.Status)
	}
	return nil
}

func (q *QbtAPI) getAltSpeedLimitsEnabled(ctx context.Context) (bool, error) {
	if err := q.ensureLogin(ctx); err != nil {
		return false, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, q.base+"/api/v2/transfer/speedLimitsMode", nil)
	resp, err := q.hc.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("speedLimitsMode failed: %s", resp.Status)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	// qBittorrent returns "0" or "1"
	return strings.TrimSpace(buf.String()) == "1", nil
}

func (q *QbtAPI) SetAltSpeedLimitsEnabled(ctx context.Context, enabled bool) error {
	cur, err := q.getAltSpeedLimitsEnabled(ctx)
	if err != nil {
		return err
	}
	if cur == enabled {
		return nil
	}
	// Toggle endpoint
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, q.base+"/api/v2/transfer/toggleSpeedLimitsMode", nil)
	resp, err := q.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("toggleSpeedLimitsMode failed: %s", resp.Status)
	}
	return nil
}
