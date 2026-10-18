// Command pocket-ssh-agent is an SSH agent whose private key lives on your
// phone. Every signature must be approved in the phone's PWA.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tksugimoto/pocket-ssh-agent/internal/broker"
	"github.com/tksugimoto/pocket-ssh-agent/internal/config"
	"github.com/tksugimoto/pocket-ssh-agent/internal/httpapi"
	"github.com/tksugimoto/pocket-ssh-agent/internal/listen"
	"github.com/tksugimoto/pocket-ssh-agent/internal/qrterm"
	"github.com/tksugimoto/pocket-ssh-agent/internal/sshagent"
	"github.com/tksugimoto/pocket-ssh-agent/internal/tailscale"
	"github.com/tksugimoto/pocket-ssh-agent/internal/tsnode"
)

var version = "dev"

// defaultWebURL is the URL of the phone PWA used when neither -web-url nor
// the configuration file names one. It is empty in source builds and can be
// set at build time: go build -ldflags "-X main.defaultWebURL=https://..."
var defaultWebURL = ""

type options struct {
	mode       string
	tsHostname string
	tsDir      string
	verbose    bool
	listenAddr string
	socket     string
	configPath string
	publicURL  string
	webURL     string
	name       string
	timeout    time.Duration
	pairTTL    time.Duration
	pair       bool
}

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) > 1 && os.Args[1] == "pubkey" {
		if err := printPubkey(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	var o options
	fs := flag.NewFlagSet("pocket-ssh-agent", flag.ExitOnError)
	fs.StringVar(&o.mode, "mode", "tsnet", "how the phone reaches this PC: \"tsnet\" (the agent joins the tailnet itself) or \"serve\" (loopback API exposed with `tailscale serve`)")
	fs.StringVar(&o.tsHostname, "ts-hostname", tsnode.DefaultHostname(), "tsnet mode: name of the agent's node in the tailnet")
	fs.StringVar(&o.tsDir, "ts-dir", "", "tsnet mode: state directory of the agent's node (default: user config dir)")
	fs.BoolVar(&o.verbose, "v", false, "verbose logs")
	fs.StringVar(&o.listenAddr, "listen", "127.0.0.1:7766", "serve mode: loopback address for the phone API")
	fs.StringVar(&o.socket, "socket", listen.DefaultPath(), "SSH agent socket (named pipe on Windows)")
	fs.StringVar(&o.configPath, "config", "", "configuration file (default: user config dir)")
	fs.StringVar(&o.publicURL, "public-url", "", "URL the phone uses to reach this PC (default: detected from Tailscale)")
	fs.StringVar(&o.webURL, "web-url", "", "URL the phone PWA is served from (remembered in the configuration file)")
	fs.StringVar(&o.name, "name", "", "name of this PC shown on the phone (default: hostname)")
	fs.DurationVar(&o.timeout, "timeout", 90*time.Second, "how long to wait for approval")
	fs.DurationVar(&o.pairTTL, "pair-ttl", 10*time.Minute, "validity of a pairing QR code")
	fs.BoolVar(&o.pair, "pair", false, "pair with a (new) phone even if already paired")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  pocket-ssh-agent [flags]      run the agent\n  pocket-ssh-agent pubkey       print the paired public key\n\nFlags:\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])
	if *showVersion {
		fmt.Println(version)
		return
	}
	if err := run(o); err != nil {
		log.Fatal(err)
	}
}

func openStore(path string) (*config.Store, error) {
	if path == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	return config.Open(path)
}

func printPubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	cfg := fs.String("config", "", "configuration file")
	_ = fs.Parse(args)
	store, err := openStore(*cfg)
	if err != nil {
		return err
	}
	p, _ := store.Pairing()
	if p == nil {
		return errors.New("not paired yet; run pocket-ssh-agent first")
	}
	fmt.Println(p.PublicKey)
	return nil
}

func run(o options) error {
	store, err := openStore(o.configPath)
	if err != nil {
		return err
	}
	webURL, changed, err := resolveWebURL(store, o.webURL)
	if err != nil {
		return err
	}
	o.webURL = webURL
	web, _ := url.Parse(webURL)
	if changed {
		if p, _ := store.Pairing(); p != nil {
			// The phone's key and pairing live in the old PWA's origin.
			log.Printf("The PWA URL changed; pair the phone again from the new PWA.")
			o.pair = true
		}
	}
	if o.name == "" {
		o.name, _ = os.Hostname()
	}
	if o.mode != "tsnet" && o.mode != "serve" {
		return fmt.Errorf("-mode must be \"tsnet\" or \"serve\", got %q", o.mode)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := log.Default()
	b := broker.New()
	api := &httpapi.Server{
		Store:         store,
		Broker:        b,
		AllowedOrigin: origin(web),
		PCName:        o.name,
		Log:           logger,
		OnPaired: func(p *config.Pairing) {
			fmt.Printf("\nPaired with %q.\nRegister this public key with GitHub (Settings > SSH and GPG keys) or your servers:\n\n  %s\n\n", p.DeviceName, p.PublicKey)
		},
	}

	// The SSH agent socket comes up first so that clients get a clear
	// "not paired" answer even while the tailnet login is pending.
	al, err := listen.Listen(o.socket)
	if err != nil {
		return fmt.Errorf("agent socket: %w", err)
	}
	defer al.Close()
	ag := &sshagent.Agent{Store: store, Broker: b, Timeout: o.timeout, Log: logger}
	go serveAgent(al, ag)

	log.Printf("pocket-ssh-agent %s", version)
	log.Printf("SSH agent:  %s", o.socket)

	hl, public, err := phoneListener(ctx, o)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// Bodies are at most 16 KiB; a client trickling one in must not
		// hold the connection open. Writes cover the 25 s long poll.
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  2 * time.Minute,
	}
	go func() {
		if err := srv.Serve(hl); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http: %v", err)
			stop()
		}
	}()
	log.Printf("Phone API:  %s", public)

	if p, _ := store.Pairing(); p == nil || o.pair {
		if err := startPairing(api, o, public); err != nil {
			log.Printf("pairing: %v", err)
		}
	} else {
		log.Printf("Paired with %q. Keep the PWA open on the phone to approve requests.", p.DeviceName)
	}

	<-ctx.Done()
	log.Printf("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

func serveAgent(l net.Listener, ag *sshagent.Agent) {
	for {
		c, err := l.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("agent accept: %v", err)
			}
			return
		}
		go ag.ServeConn(c)
	}
}

// origin returns the browser origin of u, without a default port.
func origin(u *url.URL) string {
	host := u.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" && !(u.Scheme == "https" && p == "443") && !(u.Scheme == "http" && p == "80") {
		host += ":" + p
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(host)
}

// resolveWebURL picks the PWA URL from the flag, the configuration file or
// the build-time default, in that order, and remembers it. It reports
// whether the URL differs from the remembered one.
func resolveWebURL(store *config.Store, flagURL string) (string, bool, error) {
	saved := store.WebURL()
	u := flagURL
	if u == "" {
		u = saved
	}
	if u == "" {
		u = defaultWebURL
	}
	if u == "" {
		return "", false, errors.New("the URL of the phone PWA is not set; start once with -web-url https://<where web/ is published>/")
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && parsed.Hostname() == "localhost")) {
		return "", false, fmt.Errorf("-web-url must be an https URL: %q", u)
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}
	parsed.RawQuery, parsed.Fragment = "", ""
	u = parsed.String()
	if u == saved {
		return u, false, nil
	}
	if err := store.SetWebURL(u); err != nil {
		return "", false, err
	}
	return u, saved != "", nil
}

// phoneListener returns the listener for the phone API and the URL the
// phone uses to reach it.
func phoneListener(ctx context.Context, o options) (net.Listener, string, error) {
	if o.mode == "tsnet" {
		dir := o.tsDir
		if dir == "" {
			cfg, err := os.UserConfigDir()
			if err != nil {
				return nil, "", err
			}
			dir = filepath.Join(cfg, "pocket-ssh-agent", "tsnet")
		}
		log.Printf("Joining the tailnet as %q (state: %s)...", o.tsHostname, dir)
		node, ln, err := tsnode.Listen(ctx, tsnode.Options{Hostname: o.tsHostname, Dir: dir, Verbose: o.verbose, Log: log.Default()})
		if err != nil {
			return nil, "", fmt.Errorf("tailnet: %w", err)
		}
		go func() {
			<-ctx.Done()
			node.Close()
		}()
		public := node.URL
		if o.publicURL != "" {
			public = o.publicURL
		}
		return ln, strings.TrimSuffix(public, "/"), nil
	}

	hl, err := net.Listen("tcp", o.listenAddr)
	if err != nil {
		return nil, "", err
	}
	if !isLoopback(hl.Addr()) {
		hl.Close()
		return nil, "", fmt.Errorf("-listen must be a loopback address, got %s", o.listenAddr)
	}
	_, port, _ := net.SplitHostPort(hl.Addr().String())
	public := o.publicURL
	if public == "" {
		name, err := tailscale.DNSName(ctx)
		if err != nil {
			hl.Close()
			return nil, "", fmt.Errorf("could not detect the Tailscale name (%v); pass -public-url", err)
		}
		public = "https://" + name + ":" + port
		fmt.Printf("\nExpose the phone API to the tailnet (once):\n\n  tailscale serve --bg --https=%s http://%s\n\n", port, hl.Addr())
	}
	return hl, strings.TrimSuffix(public, "/"), nil
}

func startPairing(api *httpapi.Server, o options, public string) error {
	code, err := api.StartPairing(o.pairTTL)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"v": 1, "url": public, "code": code, "name": o.name})
	link := o.webURL + "#pair=" + base64.RawURLEncoding.EncodeToString(payload)

	fmt.Printf("\nScan this QR code in the Pocket SSH app (valid for %s; if it expires or pairing fails, restart the agent with -pair):\n\n", o.pairTTL)
	if err := qrterm.Print(os.Stdout, link); err != nil {
		fmt.Printf("(could not render QR code: %v)\n", err)
	}
	fmt.Printf("\nOr open this link on the phone (it contains a one-time secret, do not share it):\n%s\n\n", link)
	return nil
}

func isLoopback(a net.Addr) bool {
	ta, ok := a.(*net.TCPAddr)
	return ok && ta.IP.IsLoopback()
}
