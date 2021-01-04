/*
Package unifi provides programmatic access to UniFi hardware.
*/
package unifi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// API is an interface to a UniFi controller.
type API struct {
	hc              *http.Client
	cookieBase      *url.URL
	checkConfigFile bool
	as              AuthStore
	auth            *Auth
}

// Auth holds the authentication information for accessing a UniFi controller.
type Auth struct {
	Username, Password string
	ControllerHost     string
	Cookies            []*http.Cookie
}

// NewAPI constructs a new API.
func NewAPI(as AuthStore) (*API, error) {
	auth, err := as.Load()
	if err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	cookieBase := &url.URL{
		Scheme: "https",
		Host:   auth.ControllerHost,
	}
	jar.SetCookies(cookieBase, auth.Cookies)

	api := &API{
		hc: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					// TODO: support proper certs
					InsecureSkipVerify: true,
				},
			},
			Jar: jar,
		},
		cookieBase: cookieBase,
		as:         as,
		auth:       auth,
	}
	return api, nil
}

// WriteConfig writes the configuration to the configured AuthStore.
func (api *API) WriteConfig() error {
	api.auth.Cookies = api.hc.Jar.Cookies(api.cookieBase)
	return api.as.Save(api.auth)
}

func (api *API) post(u string, src, dst interface{}, opts reqOpts) error {
	u = api.baseURL() + u
	body, err := json.Marshal(src)
	if err != nil {
		panic("internal error marshaling JSON POST body: " + err.Error())
	}
	req, err := http.NewRequest("POST", u, bytes.NewReader(body))
	if err != nil {
		panic("internal error: " + err.Error())
	}
	return api.doReq(req, dst, opts)
}

func (api *API) get(u string, dst interface{}, opts reqOpts) error {
	u = api.baseURL() + u
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		panic("internal error: " + err.Error())
	}
	return api.doReq(req, dst, opts)
}

type reqOpts struct {
	referer string
}

func (api *API) doReq(req *http.Request, dst interface{}, opts reqOpts) error {
	if opts.referer != "" {
		req.Header.Set("Referer", opts.referer)
	}

	dec := struct {
		Data interface{} `json:"data"`
		Meta struct {
			Code string `json:"rc"`
			Msg  string `json:"msg"`
		} `json:"meta"`
	}{Data: dst}

	triedLogin := false
	for {
		resp, err := api.hc.Do(req)
		if err != nil {
			return err
		}
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}

		if err := json.Unmarshal(body, &dec); err != nil {
			return fmt.Errorf("parsing response body: %v", err)
		}

		if resp.StatusCode == 200 {
			if dec.Meta.Code != "ok" {
				return fmt.Errorf("non-ok return code %q (%s)", dec.Meta.Code, dec.Meta.Msg)
			}
			return nil
		}

		if resp.StatusCode == http.StatusUnauthorized && !triedLogin { // 401
			if dec.Meta.Code == "error" && dec.Meta.Msg == "api.err.LoginRequired" {
				if err := api.login(); err != nil {
					return err
				}
				triedLogin = true
				continue
			}
		}

		return fmt.Errorf("HTTP response %s", resp.Status)
	}
}

func (api *API) baseURL() string {
	return "https://" + api.auth.ControllerHost + ":8443"
}

func (api *API) login() error {
	req := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		Username: api.auth.Username,
		Password: api.auth.Password,
	}
	return api.post("/api/login", &req, &json.RawMessage{}, reqOpts{
		referer: api.baseURL() + "/login",
	})
}

// An AuthStore is an interface for loading and saving authentication information.
// See FileAuthStore for a file-based implementation.
type AuthStore interface {
	Load() (*Auth, error)
	Save(*Auth) error
}

// DefaultAuthFile is a default place to store authentication information.
// Pass this to FileAuthStore if an alternate path isn't required.
var DefaultAuthFile = filepath.Join(os.Getenv("HOME"), ".unifi-auth")

// FileAuthStore returns an AuthStore that stores authentication information in a named file.
func FileAuthStore(filename string, checkPerm bool) AuthStore {
	return fileAuthStore{filename, checkPerm}
}

type fileAuthStore struct {
	filename         string
	checkPermissions bool
}

func (f fileAuthStore) Load() (*Auth, error) {
	// Security check.
	fi, err := os.Stat(f.filename)
	if err != nil {
		return nil, err
	}
	if f.checkPermissions && (fi.Mode()&0077) != 0 {
		return nil, fmt.Errorf("security check failed on %s: mode is %04o; it should not be accessible by group/other", f.filename, fi.Mode())
	}

	raw, err := ioutil.ReadFile(f.filename)
	if err != nil {
		return nil, err
	}
	auth := new(Auth)
	if err := json.Unmarshal(raw, auth); err != nil {
		return nil, fmt.Errorf("bad auth file %s: %v", f.filename, err)
	}
	return auth, nil
}

func (f fileAuthStore) Save(auth *Auth) error {
	raw, err := json.Marshal(auth)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(f.filename, raw, 0600)
}

type Client struct {
	ID       string `json:"_id"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Wired    bool   `json:"is_wired"`

	MAC string `json:"mac"`
	IP  string `json:"ip"`

	LastSeen time.Time

	SiteID           string `json:"site_id"`
	AssocTime        int    `json:"assoc_time"`
	LatestAssocTime  int    `json:"latest_assoc_time"`
	Oui              string `json:"oui"`
	UserID           string `json:"user_id"`
	Mac              string `json:"mac"`
	IsGuest          bool   `json:"is_guest"`
	FirstSeen        int    `json:"first_seen"`
	IsWired          bool   `json:"is_wired"`
	UptimeByUap      int    `json:"_uptime_by_uap"`
	LastSeenByUap    int    `json:"_last_seen_by_uap"`
	IsGuestByUap     bool   `json:"_is_guest_by_uap"`
	ApMac            string `json:"ap_mac"`
	Channel          int    `json:"channel"`
	Radio            string `json:"radio"`
	RadioName        string `json:"radio_name"`
	Essid            string `json:"essid"`
	Bssid            string `json:"bssid"`
	PowersaveEnabled bool   `json:"powersave_enabled"`
	Is11R            bool   `json:"is_11r"`
	Ccq              int    `json:"ccq"`
	Rssi             int    `json:"rssi"`
	Noise            int    `json:"noise"`
	Signal           int    `json:"signal"`
	TxRate           int    `json:"tx_rate"`
	RxRate           int    `json:"rx_rate"`
	TxPower          int    `json:"tx_power"`
	Idletime         int    `json:"idletime"`
	DhcpendTime      int    `json:"dhcpend_time"`
	Satisfaction     int    `json:"satisfaction"`
	Anomalies        int    `json:"anomalies"`
	Vlan             int    `json:"vlan"`
	RadioProto       string `json:"radio_proto"`
	Uptime           int    `json:"uptime"`
	TxBytes          int64  `json:"tx_bytes"`
	RxBytes          int    `json:"rx_bytes"`
	TxPackets        int    `json:"tx_packets"`
	TxRetries        int    `json:"tx_retries"`
	WifiTxAttempts   int    `json:"wifi_tx_attempts"`
	RxPackets        int    `json:"rx_packets"`
	BytesR           int    `json:"bytes-r"`
	TxBytesR         int    `json:"tx_bytes-r"`
	RxBytesR         int    `json:"rx_bytes-r"`
	Authorized       bool   `json:"authorized"`
	QosPolicyApplied bool   `json:"qos_policy_applied"`
	// TODO: other fields
}

func (c *Client) UnmarshalJSON(data []byte) error {
	type Alias Client
	aux := struct {
		*Alias

		LastSeen int64 `json:"last_seen"`
		// TODO: do this for MAC, IP
	}{Alias: (*Alias)(c)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.LastSeen = time.Unix(aux.LastSeen, 0)
	return nil
}

func (api *API) ListClients(site string) ([]Client, error) {
	var resp []Client
	if err := api.get("/api/s/"+site+"/stat/sta", &resp, reqOpts{}); err != nil {
		return nil, err
	}
	return resp, nil
}

type WirelessNetwork struct {
	ID      string `json:"_id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`

	Security string `json:"security"`
	WPAMode  string `json:"wpa_mode"`

	Guest bool `json:"is_guest,omitempty"`

	// TODO: other fields
}

func (api *API) ListWirelessNetworks(site string) ([]WirelessNetwork, error) {
	var resp []WirelessNetwork
	err := api.get("/api/s/"+site+"/list/wlanconf", &resp, reqOpts{})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (api *API) EnableWirelessNetwork(site, id string, enable bool) error {
	req := struct {
		Enabled bool `json:"enabled"`
	}{enable}
	return api.post("/api/s/"+site+"/upd/wlanconf/"+id, &req, &json.RawMessage{}, reqOpts{})
}
