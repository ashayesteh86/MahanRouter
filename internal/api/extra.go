package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// Endpoints used by the web panel: the config as JSON (the panel edits
// structured data, the agent keeps storing YAML), live state and tools.

func (s *Server) getCandidateJSON(w http.ResponseWriter, r *http.Request) {
	data, err := s.Agent.Store.Candidate()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	s.writeDocJSON(w, data)
}

func (s *Server) getRunningJSON(w http.ResponseWriter, r *http.Request) {
	data, err := s.Agent.Store.Running()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	s.writeDocJSON(w, data)
}

func (s *Server) writeDocJSON(w http.ResponseWriter, data []byte) {
	c, err := config.Parse(data)
	if err != nil {
		writeErr(w, 422, err)
		return
	}
	resp := map[string]any{"config": c, "valid": true}
	if err := config.Validate(c); err != nil {
		resp["valid"] = false
		var ve *config.ValidationError
		if errors.As(err, &ve) {
			resp["problems"] = ve.Problems
		}
	}
	writeJSON(w, 200, resp)
}

// putCandidateJSON stores a candidate sent as JSON. Unknown fields are
// rejected, like in YAML. Comments of a hand-written YAML candidate are not
// kept when the panel saves it.
func (s *Server) putCandidateJSON(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	var c config.Config
	if err := dec.Decode(&c); err != nil {
		writeErr(w, 400, err)
		return
	}
	data, err := config.Marshal(&c)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if _, err := config.Parse(data); err != nil {
		writeErr(w, 400, err)
		return
	}
	if err := s.Agent.Store.SetCandidate(data); err != nil {
		writeErr(w, 500, err)
		return
	}
	resp := map[string]any{"saved": true, "valid": true}
	if err := config.Validate(&c); err != nil {
		resp["valid"] = false
		var ve *config.ValidationError
		if errors.As(err, &ve) {
			resp["problems"] = ve.Problems
		}
	}
	writeJSON(w, 200, resp)
}

// --- system -----------------------------------------------------------

type cpuSample struct {
	busy, total uint64
	at          time.Time
}

var (
	cpuMu   sync.Mutex
	cpuLast cpuSample
	cpuPct  float64
)

func readCPU() (cpuSample, bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuSample{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return cpuSample{}, false
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSample{}, false
	}
	var total, idle uint64
	for i, v := range fields[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i == 3 || i == 4 { // idle + iowait
			idle += n
		}
	}
	return cpuSample{busy: total - idle, total: total, at: time.Now()}, true
}

// cpuPercent returns usage since the previous call (or over a short sample).
func cpuPercent() float64 {
	cpuMu.Lock()
	defer cpuMu.Unlock()
	cur, ok := readCPU()
	if !ok {
		return 0
	}
	if cpuLast.total == 0 || time.Since(cpuLast.at) > time.Minute {
		time.Sleep(200 * time.Millisecond)
		cpuLast = cur
		cur, _ = readCPU()
	}
	if dt := cur.total - cpuLast.total; dt > 0 {
		cpuPct = 100 * float64(cur.busy-cpuLast.busy) / float64(dt)
	}
	cpuLast = cur
	return cpuPct
}

func readMeminfo() map[string]uint64 {
	out := map[string]uint64{}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) > 0 {
			n, _ := strconv.ParseUint(f[0], 10, 64)
			out[k] = n * 1024
		}
	}
	return out
}

func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	resp := map[string]any{"hostname": host, "version": s.Version, "time": time.Now().Format(time.RFC3339)}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			up, _ := strconv.ParseFloat(f[0], 64)
			resp["uptime_seconds"] = int64(up)
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		var load []float64
		for _, x := range f[:min(3, len(f))] {
			v, _ := strconv.ParseFloat(x, 64)
			load = append(load, v)
		}
		resp["load"] = load
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		resp["kernel"] = strings.TrimSpace(string(b))
	}
	m := readMeminfo()
	resp["memory"] = map[string]uint64{"total": m["MemTotal"], "available": m["MemAvailable"]}
	resp["cpu_percent"] = cpuPercent()
	cores := 0
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		cores = bytes.Count(b, []byte("\nprocessor")) + 1
		if bytes.HasPrefix(b, []byte("processor")) {
			cores = bytes.Count(b, []byte("processor\t"))
		}
	}
	resp["cores"] = cores
	if fs, err := diskUsage("/"); err == nil {
		resp["disk"] = fs
	}
	resp["services"] = serviceStates("mahan-agent", "systemd-networkd", "nftables", "kea-dhcp4-server", "unbound", "chrony", "frr")
	writeJSON(w, 200, resp)
}

func serviceStates(units ...string) map[string]string {
	out := map[string]string{}
	args := append([]string{"is-active"}, units...)
	b, _ := exec.Command("systemctl", args...).Output() // non-zero exit when one is inactive
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i, u := range units {
		if i < len(lines) && lines[i] != "" {
			out[u] = lines[i]
		} else {
			out[u] = "unknown"
		}
	}
	return out
}

// --- interfaces, routes, leases ----------------------------------------

func (s *Server) interfaces(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{}
	if out, err := exec.Command("ip", "-j", "-s", "-d", "link").Output(); err == nil {
		resp["links"] = json.RawMessage(out)
	}
	if out, err := exec.Command("ip", "-j", "addr").Output(); err == nil {
		resp["addresses"] = json.RawMessage(out)
	}
	writeJSON(w, 200, resp)
}

func (s *Server) routes(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{}
	if out, err := exec.Command("ip", "-j", "route", "show", "table", "all").Output(); err == nil {
		resp["ipv4"] = json.RawMessage(out)
	}
	if out, err := exec.Command("ip", "-j", "-6", "route").Output(); err == nil {
		resp["ipv6"] = json.RawMessage(out)
	}
	writeJSON(w, 200, resp)
}

// Lease is one active DHCP lease.
type Lease struct {
	Address  string `json:"address"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
	Expires  int64  `json:"expires"`
	SubnetID string `json:"subnet_id"`
}

// LeaseFile is where Kea's memfile backend keeps DHCPv4 leases.
var LeaseFile = "/var/lib/kea/kea-leases4.csv"

func (s *Server) leases(w http.ResponseWriter, r *http.Request) {
	ls, err := ReadLeases(LeaseFile, time.Now())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		writeErr(w, 500, err)
		return
	}
	if ls == nil {
		ls = []Lease{}
	}
	writeJSON(w, 200, ls)
}

// ReadLeases returns the current leases from a Kea memfile CSV (and its
// .2/.1 rotation files). The file is append-only: the last line for an
// address wins; expired and released leases are skipped.
func ReadLeases(path string, now time.Time) ([]Lease, error) {
	latest := map[string]Lease{}
	var order []string
	var firstErr error
	for _, p := range []string{path + ".2", path + ".1", path} {
		f, err := os.Open(p)
		if err != nil {
			if p == path {
				firstErr = err
			}
			continue
		}
		rd := csv.NewReader(f)
		rd.FieldsPerRecord = -1
		header, err := rd.Read()
		if err != nil {
			f.Close()
			continue
		}
		col := map[string]int{}
		for i, h := range header {
			col[h] = i
		}
		get := func(rec []string, k string) string {
			if i, ok := col[k]; ok && i < len(rec) {
				return rec[i]
			}
			return ""
		}
		for {
			rec, err := rd.Read()
			if err != nil {
				break
			}
			addr := get(rec, "address")
			if addr == "" {
				continue
			}
			exp, _ := strconv.ParseInt(get(rec, "expire"), 10, 64)
			state := get(rec, "state")
			valid, _ := strconv.ParseInt(get(rec, "valid_lifetime"), 10, 64)
			if _, seen := latest[addr]; !seen {
				order = append(order, addr)
			}
			l := Lease{Address: addr, MAC: get(rec, "hwaddr"), Hostname: get(rec, "hostname"), Expires: exp, SubnetID: get(rec, "subnet_id")}
			if state != "0" || valid == 0 || exp <= now.Unix() {
				l.Expires = -1 // gone
			}
			latest[addr] = l
		}
		f.Close()
	}
	var out []Lease
	for _, a := range order {
		if l := latest[a]; l.Expires > 0 {
			out = append(out, l)
		}
	}
	if out == nil && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// --- tools ---------------------------------------------------------------

var hostRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$`)

func (s *Server) tool(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tool  string `json:"tool"`
		Host  string `json:"host"`
		Count int    `json:"count"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if !hostRe.MatchString(req.Host) {
		writeErr(w, 400, errors.New("enter a host name or IP address"))
		return
	}
	if req.Count < 1 || req.Count > 10 {
		req.Count = 4
	}
	var cmd []string
	switch req.Tool {
	case "ping":
		cmd = []string{"ping", "-c", strconv.Itoa(req.Count), "-W", "2", "--", req.Host}
	case "traceroute":
		cmd = []string{"mtr", "-r", "-n", "-w", "-c", "2", "--", req.Host}
	case "dns":
		cmd = []string{"dig", "+time=3", "+tries=1", "@127.0.0.1", "-q", req.Host}
	default:
		writeErr(w, 400, errors.New("tool must be ping, traceroute or dns"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
	resp := map[string]any{"output": string(out), "ok": err == nil}
	writeJSON(w, 200, resp)
}

func diskUsage(path string) (map[string]uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return nil, err
	}
	bs := uint64(st.Bsize)
	return map[string]uint64{"total": st.Blocks * bs, "available": st.Bavail * bs}, nil
}
