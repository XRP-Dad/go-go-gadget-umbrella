package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ping/ping"
	g "github.com/gosnmp/gosnmp"
)

// Default OIDs used when none are specified in the request
var defaultOIDs = []string{
	".1.3.6.1.2.1.1.1.0", // sysDescr
	".1.3.6.1.2.1.1.2.0", // sysObjectID
	".1.3.6.1.2.1.1.3.0", // sysUpTime
	".1.3.6.1.2.1.1.4.0", // sysContact
	".1.3.6.1.2.1.1.5.0", // sysName
	".1.3.6.1.2.1.1.6.0", // sysLocation
	".1.3.6.1.2.1.1.7.0", // sysServices
}

// Single OID for SNMP Status Check
const snmpStatusOID = ".1.3.6.1.2.1.1.1.0"

// Traceroute Timeout as a global constant (assuming 10 seconds if not specified in ConstantsConfig)
var TracerouteTimeout = 10 * time.Second

// Type Definitions

type ProxyConfig struct {
	Address  string `json:"address"`
	Hostname string `json:"hostname"`
}

type ConstantsConfig struct {
	DefaultCommunity         string  `json:"default_community"`
	OriginalPingWeight       float64 `json:"original_ping_weight"`
	OriginalSNMPWeight       float64 `json:"original_snmp_weight"`
	OriginalSSHWeight        float64 `json:"original_ssh_weight"`
	OriginalTracerouteWeight float64 `json:"original_traceroute_weight"`
	MaxPingMs                float64 `json:"max_ping_ms"`
	MaxTracerouteHops        int     `json:"max_traceroute_hops"`
	TracerouteTimeout        string  `json:"traceroute_timeout"`
	TracerouteFailurePenalty float64 `json:"traceroute_failure_penalty"`
}

type ServerConfig struct {
	Proxies     []ProxyConfig `json:"proxies"`
	Communities []string      `json:"communities"`
	DefaultOIDs []string      `json:"default_oids"`
}

type CheckRequest struct {
	Target         string   `json:"target"`
	Checks         []string `json:"checks"`
	Community      string   `json:"community,omitempty"`
	SNMPOIDs       []string `json:"snmp_oids,omitempty"`
	TracerouteHops int      `json:"traceroute_hops,omitempty"`
	SNMPVersion    string   `json:"snmp_version,omitempty"`
}

type ProxyResult struct {
	ProxyAddr     string            `json:"proxy_addr"`
	ProxyHostname string            `json:"proxy_hostname"`
	BestProxy     string            `json:"best_proxy"`
	Ping          *PingResult       `json:"ping,omitempty"`
	SNMPSuccess   bool              `json:"snmp_success"`
	SNMPResults   map[string]string `json:"snmp_results,omitempty"`
	SSH           string            `json:"ssh,omitempty"`
	Traceroute    *TracerouteResult `json:"traceroute,omitempty"`
	Error         string            `json:"error,omitempty"`
	Score         float64           `json:"score"`
	SNMP          map[string]string `json:"-"` // Internal use, not included in JSON
	SNMPVersion   string            `json:"snmp_version,omitempty"`
}

type PingResult struct {
	LatencyMs float64 `json:"latency_ms"`
	Success   bool    `json:"success"`
}

type TracerouteResult struct {
	Hops      []string `json:"hops"`
	TotalHops int      `json:"total_hops"`
	Success   bool     `json:"success"`
}

type ServerResponse struct {
	SNMP        map[string]string `json:"snmp,omitempty"`
	SNMPSource  string            `json:"snmp_source,omitempty"`
	SNMPVersion string            `json:"snmp_version,omitempty"`
	Results     []ProxyResult     `json:"results"`
	BestProxy   string            `json:"best_proxy"`
	BestScore   float64           `json:"best_score"`
}

type Server struct {
	Proxies     []ProxyConfig
	Communities []string
	DefaultOIDs []string
	Constants   *ConstantsConfig
	mu          sync.Mutex
}

// Update ProxyStatus struct
type ProxyStatus struct {
	Address     string `json:"address"`
	Hostname    string `json:"hostname"`
	Available   bool   `json:"available"`
	LastChecked string `json:"last_checked"`
	Error       string `json:"error,omitempty"`
	Version     struct {
		Version  string `json:"version"`
		Codename string `json:"codename"`
	} `json:"version"`
	Details struct {
		DNSResolved   bool   `json:"dns_resolved"`
		DNSAddress    string `json:"dns_address,omitempty"`
		TCPConnection bool   `json:"tcp_connection"`
		HTTPResponse  bool   `json:"http_response"`
		ResponseCode  int    `json:"response_code,omitempty"`
		ResponseTime  string `json:"response_time,omitempty"`
		NetworkErrors string `json:"network_errors,omitempty"`
		RouteInfo     string `json:"route_info,omitempty"`
	} `json:"details"`
}

// Update status response struct
type StatusResponse struct {
	Proxies []ProxyStatus `json:"proxies"`
}

// Single declaration of versionInfo
var versionInfo = &VersionInfo{
	Version:  os.Getenv("GOGOGADGET_VERSION"),
	Codename: os.Getenv("GOGOGADGET_CODENAME"),
}

type VersionInfo struct {
	Version  string `json:"version"`
	Codename string `json:"codename"`
}

// Configuration Loading

func loadConstantsConfig(filename string) (*ConstantsConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Dr. Claw strikes again! Failed to read constants config file %s: %v", filename, err)
		return nil, fmt.Errorf("failed to read constants config file: %v", err)
	}
	var config ConstantsConfig
	if err := json.Unmarshal(data, &config); err != nil {
		log.Printf("Penny's brilliant insight failed! Constants config parsing error: %v", err)
		return nil, fmt.Errorf("failed to parse constants config: %v", err)
	}
	// Set TracerouteTimeout if specified in config
	if config.TracerouteTimeout != "" {
		if duration, err := time.ParseDuration(config.TracerouteTimeout); err == nil {
			TracerouteTimeout = duration
		}
	}
	return &config, nil
}

func loadServerConfig(filename string) (*ServerConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Dr. Claw strikes again! Failed to read server config file %s: %v", filename, err)
		return nil, fmt.Errorf("failed to read server config file: %v", err)
	}
	var config ServerConfig
	if err := json.Unmarshal(data, &config); err != nil {
		log.Printf("Penny's brilliant insight failed! Server config parsing error: %v", err)
		return nil, fmt.Errorf("failed to parse server config: %v", err)
	}
	if len(config.Proxies) == 0 {
		log.Printf("Brain's sneaky check found no proxies! Check server config.")
		return nil, fmt.Errorf("no proxies defined in server config")
	}
	return &config, nil
}

// Server Initialization

func getSystemInfo() (hostname string, ip string, err error) {
	hostname, err = os.Hostname()
	if err != nil {
		return "", "", fmt.Errorf("failed to get hostname: %v", err)
	}

	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return hostname, "", fmt.Errorf("failed to get interfaces: %v", err)
	}

	// Look for a suitable IP address
	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if ipv4 := v.IP.To4(); ipv4 != nil && !ipv4.IsLoopback() {
					return hostname, ipv4.String(), nil
				}
			}
		}
	}

	return hostname, "", fmt.Errorf("no suitable IPv4 address found")
}

func NewServer(constants *ConstantsConfig, serverConfig *ServerConfig) (*Server, error) {
	hostname, ip, err := getSystemInfo()
	if err != nil {
		log.Printf("Dr. Claw's network confusion! System info error: %v", err)
		// Continue with defaults if we can't get system info
		hostname = "server"
		ip = "localhost"
	}

	// Add this server to the proxy list if it's not already there
	serverProxy := ProxyConfig{
		Address:  fmt.Sprintf("%s:%d", ip, 8081), // Use the proxy port
		Hostname: hostname,
	}

	// Remove any existing localhost entries and update server entry
	updatedProxies := make([]ProxyConfig, 0)
	for _, proxy := range serverConfig.Proxies {
		if !strings.Contains(proxy.Address, "localhost") &&
			proxy.Hostname != "server" &&
			proxy.Address != serverProxy.Address &&
			proxy.Hostname != hostname && // Remove duplicates by hostname
			proxy.Hostname != "" { // Remove empty entries
			updatedProxies = append(updatedProxies, proxy)
		}
	}

	// Add the server with correct information
	updatedProxies = append([]ProxyConfig{serverProxy}, updatedProxies...)

	server := &Server{
		Proxies:     updatedProxies,
		Communities: serverConfig.Communities,
		DefaultOIDs: serverConfig.DefaultOIDs,
		Constants:   constants,
	}

	// Log the final proxy list for debugging
	log.Printf("Go Go Gadget Server Configuration! Proxies: %+v", server.Proxies)

	return server, nil
}

// Asynchronous Proxy Check

func (s *Server) checkProxyAsync(proxy ProxyConfig, req CheckRequest, results chan<- ProxyResult, wg *sync.WaitGroup) {
	defer wg.Done()

	hostname, _, _ := getSystemInfo()
	if proxy.Hostname == hostname {
		result := ProxyResult{
			ProxyAddr:     proxy.Address,
			ProxyHostname: proxy.Hostname,
		}

		// Perform local checks
		if contains(req.Checks, "ping") {
			pingRes, err := checkPing(req.Target)
			if err == nil {
				result.Ping = pingRes
			}
		}

		if contains(req.Checks, "snmp") {
			community := req.Community
			if community == "" {
				community = s.Constants.DefaultCommunity
			}
			snmpRes, version, err := checkSNMP(req.Target, req.SNMPOIDs, community)
			if err == nil {
				result.SNMPSuccess = true
				result.SNMPResults = snmpRes
				result.SNMPVersion = version
				log.Printf("Go Go Gadget SNMP Success! Got results using version %s for %d OIDs from %s", version, len(snmpRes), req.Target)
			} else {
				log.Printf("Dr. Claw's SNMP trap! Error checking SNMP for %s: %v", req.Target, err)
				result.Error = fmt.Sprintf("SNMP check failed: %v", err)
			}
		}

		if contains(req.Checks, "ssh") {
			sshRes, err := checkSSH(req.Target)
			if err == nil {
				result.SSH = sshRes
			}
		}

		if contains(req.Checks, "traceroute") {
			tracerouteRes, err := checkTracerouteProxy(req.Target, req.TracerouteHops, s.Constants.TracerouteTimeout)
			if err == nil {
				result.Traceroute = tracerouteRes
			}
		}

		// Calculate score with all checks
		result.Score = calculateProxyScore(result, req.Checks,
			s.Constants.OriginalPingWeight,
			s.Constants.OriginalSNMPWeight,
			s.Constants.OriginalSSHWeight,
			s.Constants.OriginalTracerouteWeight,
			s.Constants.MaxPingMs,
			s.Constants.TracerouteFailurePenalty)

		results <- result
		return
	}

	// For remote proxies
	u, err := url.Parse(fmt.Sprintf("http://%s/check", proxy.Address))
	if err != nil {
		results <- ProxyResult{
			ProxyAddr:     proxy.Address,
			ProxyHostname: proxy.Hostname,
			Error:         fmt.Sprintf("Invalid proxy address: %v", err),
		}
		return
	}

	q := u.Query()
	q.Set("target", req.Target)
	q.Set("checks", strings.Join(req.Checks, ","))
	if len(req.SNMPOIDs) > 0 {
		q.Set("oids", strings.Join(req.SNMPOIDs, ","))
	}
	if req.Community != "" {
		q.Set("community", req.Community)
	}
	if req.TracerouteHops > 0 {
		q.Set("traceroute_hops", strconv.Itoa(req.TracerouteHops))
	}
	u.RawQuery = q.Encode()

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(u.String())
	if err != nil {
		results <- ProxyResult{
			ProxyAddr:     strings.Split(proxy.Address, ":")[0],
			ProxyHostname: proxy.Hostname,
			Error:         fmt.Sprintf("Failed to reach proxy: %v", err),
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		results <- ProxyResult{
			ProxyAddr:     strings.Split(proxy.Address, ":")[0],
			ProxyHostname: proxy.Hostname,
			Error:         fmt.Sprintf("Proxy returned status: %d", resp.StatusCode),
		}
		return
	}

	var result ProxyResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		results <- ProxyResult{
			ProxyAddr:     strings.Split(proxy.Address, ":")[0],
			ProxyHostname: proxy.Hostname,
			Error:         fmt.Sprintf("Failed to decode proxy response: %v", err),
		}
		return
	}

	// Ensure proxy address and hostname are set
	result.ProxyAddr = strings.Split(proxy.Address, ":")[0]
	result.ProxyHostname = proxy.Hostname

	results <- result
}

// Error Parsing

func parseConnectivityError(err error) string {
	if opErr, ok := err.(*net.OpError); ok {
		switch opErr.Err.Error() {
		case "no route to host":
			return "no route to host"
		case "connection refused":
			return "connection refused"
		case "i/o timeout":
			return "timeout"
		default:
			return "connection error"
		}
	}
	return "connection error"
}

// Server Check Handler

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Dr. Claw's sabotage! Invalid request body: %v", err)
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	if req.Target == "" {
		log.Printf("Penny's oversight! Missing target in request")
		http.Error(w, "Missing target", http.StatusBadRequest)
		return
	}
	if len(req.Checks) == 0 {
		req.Checks = []string{"ping"}
	}

	// Set default SNMP version if not specified
	if req.SNMPVersion == "" {
		req.SNMPVersion = "v2c" // Default to v2c
	}

	// Only use default OIDs if none specified in request
	var oids []string
	if len(req.SNMPOIDs) > 0 {
		// Validate and clean requested OIDs
		for _, oid := range req.SNMPOIDs {
			oid = strings.TrimSpace(oid)
			if isValidOID(oid) {
				oids = append(oids, oid)
			}
		}
	}

	// Only fall back to defaults if no valid OIDs were provided
	if len(oids) == 0 {
		oids = defaultOIDs
		log.Printf("No valid OIDs provided, using defaults: %v", defaultOIDs)
	} else {
		log.Printf("Using requested OIDs: %v", oids)
	}

	// Update the request with validated OIDs
	req.SNMPOIDs = oids

	// Get current hostname and IP for filtering
	currentHostname, currentIP, err := getSystemInfo()
	if err != nil {
		log.Printf("Dr. Claw's network confusion! System info error: %v", err)
		currentHostname = "server"
		currentIP = "localhost"
	}

	// Filter proxies to remove duplicates and invalid entries
	var validProxies []ProxyConfig
	seenAddresses := make(map[string]bool)
	seenHostnames := make(map[string]bool)

	// First, add the current server with its IP address
	serverProxy := ProxyConfig{
		Address:  fmt.Sprintf("%s:8081", currentIP), // Use IP instead of hostname
		Hostname: currentHostname,
	}
	validProxies = append(validProxies, serverProxy)
	seenAddresses[serverProxy.Address] = true
	seenHostnames[serverProxy.Hostname] = true

	// Then add other valid proxies
	for _, proxy := range s.Proxies {
		// Skip invalid entries
		if proxy.Address == "" || proxy.Hostname == "" {
			continue
		}
		// Skip localhost entries
		if strings.Contains(proxy.Address, "localhost") ||
			proxy.Hostname == "server" ||
			strings.Contains(proxy.Address, "127.0.") {
			continue
		}
		// Skip duplicates
		if seenAddresses[proxy.Address] || seenHostnames[proxy.Hostname] {
			continue
		}
		validProxies = append(validProxies, proxy)
		seenAddresses[proxy.Address] = true
		seenHostnames[proxy.Hostname] = true
	}

	var wg sync.WaitGroup
	resultsChan := make(chan ProxyResult, len(validProxies))
	var snmpData map[string]string
	var snmpSource string
	var snmpVersion string
	var bestProxy string
	var bestScore float64

	s.mu.Lock()
	for _, proxy := range validProxies {
		wg.Add(1)
		go s.checkProxyAsync(proxy, req, resultsChan, &wg)
	}
	s.mu.Unlock()

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	var results []ProxyResult
	for result := range resultsChan {
		// Skip empty results
		if result.ProxyAddr == "" && result.ProxyHostname == "" {
			continue
		}

		// Apply server penalty immediately if this is a core/server
		if strings.Contains(strings.ToLower(result.ProxyHostname), "core") {
			result.Score = result.Score * 0.5 // 50% penalty for server
		}

		if result.SNMPSuccess && snmpData == nil {
			snmpRes, version, err := checkSNMPWithRequestedVersion(req.Target, oids, req.Community, req.SNMPVersion)
			if err == nil {
				snmpData = snmpRes
				snmpSource = result.ProxyHostname
				snmpVersion = version
				result.SNMPResults = snmpRes
				result.SNMPVersion = version
				log.Printf("Go Go Gadget SNMP Success! Got results using version %s for %d OIDs from %s", version, len(snmpRes), req.Target)
			}
		}

		results = append(results, result)

		if result.Score > bestScore {
			bestScore = result.Score
			bestProxy = result.ProxyHostname
		}
	}

	resp := ServerResponse{
		SNMP:        snmpData,
		SNMPSource:  snmpSource,
		SNMPVersion: snmpVersion,
		Results:     results,
		BestProxy:   bestProxy,
		BestScore:   bestScore,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Dr. Claw's final trap! Failed to encode response: %v", err)
	}
}

// Dynamic Weights Calculation

func calculateDynamicWeights(checks []string, originalPingWeight, originalSNMPWeight, originalSSHWeight, originalTracerouteWeight float64) (float64, float64, float64, float64) {
	totalWeight := 0.0
	weights := map[string]float64{
		"ping":       originalPingWeight,
		"snmp":       originalSNMPWeight,
		"ssh":        originalSSHWeight,
		"traceroute": originalTracerouteWeight,
	}

	presentChecks := 0
	for _, check := range checks {
		if _, exists := weights[strings.ToLower(check)]; exists {
			presentChecks++
			totalWeight += weights[strings.ToLower(check)]
		}
	}

	if presentChecks == 0 {
		return 0, 0, 0, 0
	}

	if presentChecks < 4 {
		newTotal := 1.0
		scaleFactor := newTotal / totalWeight
		pingWeight := 0.0
		snmpWeight := 0.0
		sshWeight := 0.0
		tracerouteWeight := 0.0
		for _, check := range checks {
			switch strings.ToLower(check) {
			case "ping":
				pingWeight = originalPingWeight * scaleFactor
			case "snmp":
				snmpWeight = originalSNMPWeight * scaleFactor
			case "ssh":
				sshWeight = originalSSHWeight * scaleFactor
			case "traceroute":
				tracerouteWeight = originalTracerouteWeight * scaleFactor
			}
		}
		return pingWeight, snmpWeight, sshWeight, tracerouteWeight
	}
	return originalPingWeight, originalSNMPWeight, originalSSHWeight, originalTracerouteWeight
}

// Proxy Score Calculation

func calculateProxyScore(result ProxyResult, checks []string,
	pingWeight float64, // Adjusted to 0.3
	snmpWeight float64, // Adjusted to 0.4
	sshWeight float64, // Adjusted to 0.2
	tracerouteWeight float64, // Adjusted to 0.1
	maxPingMs float64,
	tracerouteFailurePenalty float64) float64 {

	var totalWeight, score float64
	checksMap := make(map[string]bool)
	for _, check := range checks {
		checksMap[check] = true
	}

	// Only include weights for requested checks
	if checksMap["ping"] {
		if result.Ping != nil && result.Ping.Success {
			// Make ping scoring more gradual using log scale
			// This will make small differences in latency less dramatic
			latencyScore := 1.0
			if result.Ping.LatencyMs > 0 {
				// Normalize latency between 0 and 1, with less dramatic differences
				latencyScore = 1.0 - (math.Log1p(result.Ping.LatencyMs) / math.Log1p(maxPingMs))
				if latencyScore < 0 {
					latencyScore = 0
				}
			}
			score += latencyScore * pingWeight
			totalWeight += pingWeight
		}
	}

	if checksMap["snmp"] {
		if result.SNMPSuccess {
			score += snmpWeight
			totalWeight += snmpWeight
		}
	}

	if checksMap["ssh"] {
		if result.SSH != "" {
			score += sshWeight
			totalWeight += sshWeight
		}
	}

	if checksMap["traceroute"] {
		if result.Traceroute != nil {
			if result.Traceroute.Success {
				score += tracerouteWeight
			} else {
				score -= tracerouteFailurePenalty
			}
			totalWeight += tracerouteWeight
		}
	}

	// If no checks were performed or all failed, return 0
	if totalWeight == 0 {
		return 0
	}

	finalScore := score / totalWeight

	// Ensure score is between 0 and 1
	if finalScore < 0 {
		return 0
	}
	if finalScore > 1 {
		return 1
	}

	return finalScore
}

// Proxy Check Handler

func handleProxyCheck(w http.ResponseWriter, r *http.Request, constants *ConstantsConfig) {
	target := r.URL.Query().Get("target")
	checksStr := r.URL.Query().Get("checks")
	oidsStr := r.URL.Query().Get("oids")
	community := r.URL.Query().Get("community")
	snmpVersion := r.URL.Query().Get("snmp_version")

	if target == "" {
		http.Error(w, "Missing target", http.StatusBadRequest)
		return
	}

	checks := strings.Split(checksStr, ",")
	if len(checks) == 1 && checks[0] == "" {
		checks = []string{"ping"}
	}

	// Process OIDs
	oidParts := strings.Split(oidsStr, ",")
	var oids []string
	for _, oid := range oidParts {
		trimmed := strings.TrimSpace(oid)
		if trimmed != "" && isValidOID(trimmed) {
			oids = append(oids, trimmed)
		}
	}
	if len(oids) == 0 {
		oids = defaultOIDs
	}

	if community == "" {
		community = constants.DefaultCommunity
	}

	result := ProxyResult{SNMPSuccess: false}
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Get hostname for best_proxy
	hostname, err := os.Hostname()
	if err == nil {
		result.BestProxy = hostname
	}

	// Run checks in parallel
	for _, check := range checks {
		wg.Add(1)
		go func(check string) {
			defer wg.Done()
			switch strings.ToLower(check) {
			case "ping":
				if pingRes, err := checkPing(target); err == nil {
					mu.Lock()
					result.Ping = pingRes
					mu.Unlock()
				}
			case "snmp":
				if snmpRes, version, err := checkSNMPWithRequestedVersion(target, oids, community, snmpVersion); err == nil {
					mu.Lock()
					result.SNMP = snmpRes
					result.SNMPSuccess = true
					result.SNMPResults = snmpRes
					result.SNMPVersion = version
					mu.Unlock()
				}
			case "ssh":
				if sshRes, err := checkSSH(target); err == nil {
					mu.Lock()
					result.SSH = sshRes
					mu.Unlock()
				}
			}
		}(check)
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All checks completed
	case <-time.After(5 * time.Second):
		// Timeout occurred
	}

	result.Score = calculateProxyScore(result, checks,
		constants.OriginalPingWeight,
		constants.OriginalSNMPWeight,
		constants.OriginalSSHWeight,
		constants.OriginalTracerouteWeight,
		constants.MaxPingMs,
		constants.TracerouteFailurePenalty)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Utility Functions

func removeDuplicates(items []string) []string {
	seen := make(map[string]struct{})
	var unique []string
	for _, item := range items {
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			unique = append(unique, item)
		}
	}
	return unique
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.ToLower(s) == strings.ToLower(item) {
			return true
		}
	}
	return false
}

func isValidOID(oid string) bool {
	if !strings.HasPrefix(oid, ".") || strings.HasSuffix(oid, ".") {
		return false
	}
	parts := strings.Split(oid[1:], ".")
	for _, part := range parts {
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return true
}

// SNMP Error Simplification

func simplifySNMPError(errorMsg string) string {
	if strings.Contains(errorMsg, "unable to marshal OID: Invalid object identifier") ||
		strings.Contains(errorMsg, "No response from") ||
		strings.Contains(errorMsg, "timeout") ||
		strings.Contains(errorMsg, "connection refused") {
		return "SNMP unavailable"
	}
	return "SNMP available"
}

// Check Functions

func checkPing(target string) (*PingResult, error) {
	pinger, err := ping.NewPinger(target)
	if err != nil {
		return nil, err
	}
	pinger.Count = 4
	pinger.Timeout = 5 * time.Second
	err = pinger.Run()
	if err != nil {
		return nil, err
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return &PingResult{LatencyMs: -1, Success: false}, fmt.Errorf("no packets received")
	}
	return &PingResult{LatencyMs: float64(stats.AvgRtt) / float64(time.Millisecond), Success: true}, nil
}

func checkSNMP(target string, oids []string, community string) (map[string]string, string, error) {
	// If no version specified, try v2c first then v1
	snmpV2Results, err := checkSNMPWithVersion(target, oids, community, g.Version2c)
	if err == nil {
		return snmpV2Results, "v2c", nil
	}

	// If v2c fails, try v1
	snmpV1Results, err := checkSNMPWithVersion(target, oids, community, g.Version1)
	if err == nil {
		return snmpV1Results, "v1", nil
	}

	// If both fail, return detailed error
	return nil, "", fmt.Errorf("SNMP checks failed - v2c: %v, v1: %v", err, err)
}

func checkSNMPWithVersion(target string, oids []string, community string, version g.SnmpVersion) (map[string]string, error) {
	results := make(map[string]string)

	gosnmp := &g.GoSNMP{
		Target:    target,
		Port:      161,
		Community: community,
		Version:   version,
		Timeout:   time.Duration(1) * time.Second, // Reduced from 2 to 1 second
		Retries:   0,                              // No retries, just fail fast
	}

	err := gosnmp.Connect()
	if err != nil {
		return nil, fmt.Errorf("connection failed (version %v): %v", version, err)
	}
	defer gosnmp.Conn.Close()

	pdus, err := gosnmp.Get(oids)
	if err != nil {
		return nil, fmt.Errorf("SNMP get failed (version %v): %v", version, err)
	}

	for _, pdu := range pdus.Variables {
		var value string
		switch pdu.Type {
		case g.OctetString:
			value = string(pdu.Value.([]byte))
		default:
			value = fmt.Sprintf("%v", pdu.Value)
		}
		results[pdu.Name] = value
	}

	return results, nil
}

func checkSSH(target string) (string, error) {
	conn, err := net.DialTimeout("tcp", target+":22", 5*time.Second)
	if err != nil {
		return "closed", err
	}
	conn.Close()
	return "open", nil
}

func checkTracerouteProxy(target string, maxHops int, timeoutStr string) (*TracerouteResult, error) {
	// Parse timeout duration
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		timeout = 5 * time.Second // fallback to 5s if parsing fails
	}

	cmd := exec.Command("traceroute", "-m", fmt.Sprintf("%d", maxHops), target)
	cmd.Env = append(os.Environ(), "LANG=C")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(timeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return nil, fmt.Errorf("timeout after %v", timeout)
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("traceroute failed: %v", err)
		}
	}

	lines := strings.Split(out.String(), "\n")
	var hops []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "traceroute to") {
			continue
		}
		hops = append(hops, line)
	}

	return &TracerouteResult{
		Hops:      hops,
		TotalHops: len(hops),
		Success:   true,
	}, nil
}

// Enhanced error parsing with Inspector Gadget theme
func parseDetailedConnectivityError(err error) string {
	if err == nil {
		return ""
	}

	if opErr, ok := err.(*net.OpError); ok {
		if opErr.Timeout() {
			return fmt.Sprintf("Connection timeout after %v", opErr.Timeout())
		}
		if opErr.Temporary() {
			return "Temporary network error"
		}
		if syscallErr, ok := opErr.Err.(*os.SyscallError); ok {
			return fmt.Sprintf("System error: %s", syscallErr.Error())
		}
		return fmt.Sprintf("Network error: %s", opErr.Error())
	}

	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			return "Connection timeout"
		}
		return fmt.Sprintf("Network error: %s", netErr.Error())
	}

	return err.Error()
}

// Get route information using traceroute with Inspector Gadget theme
func getRouteInfo(host string) (string, error) {
	log.Printf("Go Go Gadget Traceroute! Investigating route to %s", host)
	cmd := exec.Command("traceroute", "-n", "-w", "1", "-m", "5", host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Dr. Claw blocked our route investigation to %s: %v", host, err)
		return "", err
	}
	return string(output), nil
}

// Add function to read version info
func loadVersionInfo() (*VersionInfo, error) {
	// Try current directory first
	file, err := os.Open("version.txt")
	if err != nil {
		// If not found, try /usr/local/bin
		file, err = os.Open("/usr/local/bin/version.txt")
		if err != nil {
			return nil, fmt.Errorf("failed to open version.txt: %v", err)
		}
	}
	defer file.Close()

	info := &VersionInfo{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "VERSION":
			info.Version = value
		case "CODENAME":
			info.Codename = value
		}
	}

	if info.Version == "" || info.Codename == "" {
		return nil, fmt.Errorf("invalid version.txt format")
	}

	return info, nil
}

func getVersionString() string {
	if versionInfo == nil {
		return "unknown version"
	}
	return fmt.Sprintf("%s (Codename: %s)", versionInfo.Version, versionInfo.Codename)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(versionInfo)
}

// Main Function

func main() {
	var err error
	versionInfo, err = loadVersionInfo()
	if err != nil {
		log.Printf("Dr. Claw: \"Failed to load version info: %v\"", err)
		// Continue with unknown version
		versionInfo = &VersionInfo{
			Version:  "unknown",
			Codename: "unknown",
		}
	}

	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s [server|proxy]", os.Args[0])
	}
	role := os.Args[1]

	constantsConfigFile := "constants.json"
	constants, err := loadConstantsConfig(constantsConfigFile)
	if err != nil {
		log.Fatalf("Dr. Claw's ultimate trap! Constants config error: %v", err)
	}

	if role == "server" {
		serverConfigFile := "server_config.json"
		serverConfig, err := loadServerConfig(serverConfigFile)
		if err != nil {
			log.Fatalf("Dr. Claw's ultimate trap! Server config error: %v", err)
		}
		server, err := NewServer(constants, serverConfig)
		if err != nil {
			log.Fatalf("Dr. Claw: \"Failed to create server: %v\"", err)
		}
		http.HandleFunc("/check", server.handleCheck)
		http.HandleFunc("/status", server.handleProxyStatus)
		http.HandleFunc("/version", server.handleVersion)
		http.HandleFunc("/simplecheck", server.handleSimpleCheck)
		log.Printf("Wowzers! Go Go Gadget Server %s activated on :8080!", getVersionString())
		log.Fatal(http.ListenAndServe(":8080", nil))
	} else if role == "proxy" {
		proxy := &Proxy{
			Constants: constants,
		}
		http.HandleFunc("/check", proxy.handleCheck)
		http.HandleFunc("/version", proxy.handleVersion)
		log.Printf("Go Go Gadget Proxy %s ready for duty on :8081!", getVersionString())
		log.Fatal(http.ListenAndServe(":8081", nil))
	} else {
		log.Printf("Inspector Gadget confused! Invalid role: %s", role)
		log.Fatalf("Invalid role: %s. Use 'server' or 'proxy'", role)
	}
}

func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	statuses := make([]ProxyStatus, 0)
	currentHostname, localIP, _ := getSystemInfo()

	for _, proxy := range s.Proxies {
		startTime := time.Now()
		status := ProxyStatus{
			Address:     proxy.Address,
			Hostname:    proxy.Hostname,
			LastChecked: startTime.Format(time.RFC3339),
		}

		// Parse address and ensure port is correct
		host, port, err := net.SplitHostPort(proxy.Address)
		if err != nil {
			host = proxy.Address
			port = "8081" // default port
		}

		// Check if this is the local server
		isLocalServer := proxy.Hostname == currentHostname || strings.Contains(proxy.Address, localIP)

		// For version check
		versionURL := fmt.Sprintf("http://%s:%s/version", host, port)
		client := &http.Client{Timeout: 5 * time.Second}

		// Initialize details
		status.Details.DNSResolved = false

		// DNS resolution
		ips, err := net.LookupIP(host)
		if err == nil && len(ips) > 0 {
			status.Details.DNSResolved = true
			status.Details.DNSAddress = ips[0].String()
		}

		// TCP connection test
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)
		if err == nil {
			status.Details.TCPConnection = true
			conn.Close()
		} else {
			status.Details.TCPConnection = false
			status.Details.NetworkErrors = parseDetailedConnectivityError(err)
		}

		// Set version info for local server directly
		if isLocalServer && versionInfo != nil {
			status.Version.Version = versionInfo.Version
			status.Version.Codename = versionInfo.Codename
			status.Available = true
		} else {
			// HTTP check for remote servers
			resp, err := client.Get(versionURL)
			if err == nil {
				status.Details.HTTPResponse = true
				status.Details.ResponseCode = resp.StatusCode
				resp.Body.Close()

				// Try to get version info
				if resp.StatusCode == http.StatusOK {
					status.Available = true
					if verResp, err := client.Get(versionURL); err == nil {
						var ver VersionInfo
						if err := json.NewDecoder(verResp.Body).Decode(&ver); err == nil {
							status.Version.Version = ver.Version
							status.Version.Codename = ver.Codename
						}
						verResp.Body.Close()
					}
				}
			} else {
				status.Details.HTTPResponse = false
				status.Error = fmt.Sprintf("Connection failed: %s", parseDetailedConnectivityError(err))
			}
		}

		// Add response time
		status.Details.ResponseTime = time.Since(startTime).String()

		// Add route information using traceroute
		if routeInfo, err := checkTracerouteProxy(host, 5, "5s"); err == nil {
			status.Details.RouteInfo = strings.Join(routeInfo.Hops, "\n")
		}

		statuses = append(statuses, status)
	}

	response := StatusResponse{
		Proxies: statuses,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode proxy statuses: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// Add Proxy struct and constructor
type Proxy struct {
	Constants *ConstantsConfig
}

// Add handler methods for Proxy
func (p *Proxy) handleCheck(w http.ResponseWriter, r *http.Request) {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Create a channel for the result
	resultChan := make(chan ProxyResult, 1)

	// Run the check in a goroutine
	go func() {
		target := r.URL.Query().Get("target")
		checksStr := r.URL.Query().Get("checks")
		oidsStr := r.URL.Query().Get("oids")
		community := r.URL.Query().Get("community")
		snmpVersion := r.URL.Query().Get("snmp_version")

		if target == "" {
			log.Printf("Penny's gadget glitch! Missing target in proxy request")
			resultChan <- ProxyResult{Error: "Missing target"}
			return
		}

		// Parse OIDs properly
		var oids []string
		if oidsStr != "" {
			for _, oid := range strings.Split(oidsStr, ",") {
				oid = strings.TrimSpace(oid)
				if oid != "" && isValidOID(oid) {
					oids = append(oids, oid)
				}
			}
		}
		if len(oids) == 0 {
			oids = defaultOIDs
		}

		checks := strings.Split(checksStr, ",")
		if len(checks) == 1 && checks[0] == "" {
			checks = []string{"ping", "snmp"}
		}

		if community == "" {
			community = p.Constants.DefaultCommunity
		}

		result := ProxyResult{SNMPSuccess: false}

		// Run checks with shorter timeouts
		if contains(checks, "ping") {
			pingRes, err := checkPing(target)
			if err == nil {
				result.Ping = pingRes
			}
		}

		if contains(checks, "snmp") {
			snmpRes, version, err := checkSNMPWithRequestedVersion(target, oids, community, snmpVersion)
			if err == nil {
				result.SNMP = snmpRes
				result.SNMPSuccess = true
				result.SNMPResults = snmpRes
				result.SNMPVersion = version
			} else {
				result.Error = fmt.Sprintf("SNMP check failed: %v", err)
			}
		}

		// Calculate score
		result.Score = calculateProxyScore(result, checks,
			p.Constants.OriginalPingWeight,
			p.Constants.OriginalSNMPWeight,
			p.Constants.OriginalSSHWeight,
			p.Constants.OriginalTracerouteWeight,
			p.Constants.MaxPingMs,
			p.Constants.TracerouteFailurePenalty)

		resultChan <- result
	}()

	// Wait for either the result or timeout
	select {
	case <-ctx.Done():
		http.Error(w, "Request timeout", http.StatusGatewayTimeout)
		return
	case result := <-resultChan:
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			log.Printf("Dr. Claw's JSON trap! Failed to encode response: %v", err)
		}
	}
}

func (p *Proxy) handleVersion(w http.ResponseWriter, r *http.Request) {
	if versionInfo == nil {
		http.Error(w, "Version information not available", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(versionInfo)
}

// Helper function to get hostname
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

type InstallTestResult struct {
	Version string        `json:"version"`
	Proxies []ProxyStatus `json:"proxies"`
}

func runInstallationTest() {
	fmt.Printf("\nGo Go Gadget Tester!\n")
	fmt.Printf("------------------\n")

	// Get version and status
	resp, err := http.Get("http://localhost:8080/status")
	if err != nil {
		fmt.Printf("Error: Service check failed\n")
		return
	}
	defer resp.Body.Close()

	var result InstallTestResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("Error: Failed to decode status\n")
		return
	}

	// Print version
	fmt.Printf("Version: %s\n\n", result.Version)

	// Print proxy status in a table format
	fmt.Printf("%-15s %-20s %s\n", "IP", "HOSTNAME", "STATUS")
	fmt.Printf("----------------------------------------\n")
	for _, proxy := range result.Proxies {
		status := "✓"
		if !proxy.Available {
			status = "✗"
		}
		// Extract IP from address (remove port)
		ip := strings.Split(proxy.Address, ":")[0]
		fmt.Printf("%-15s %-20s %s\n", ip, proxy.Hostname, status)
	}
	fmt.Printf("\n")
}

func calculateBestProxy(results []ProxyResult) (string, float64) {
	var bestScore float64
	var bestProxy string
	var serverScore float64
	var serverHostname string

	// First pass: find best non-server proxy
	for _, result := range results {
		// Skip the server for now
		if strings.Contains(strings.ToLower(result.ProxyHostname), "core") {
			// Apply a stronger penalty to server score (50% of original)
			serverScore = result.Score * 0.5
			serverHostname = result.ProxyHostname
			continue
		}

		if result.Score > bestScore {
			bestScore = result.Score
			bestProxy = result.ProxyHostname
		}
	}

	// Only use server if no other proxy has a decent score (threshold 0.2)
	if bestScore < 0.2 && serverScore > 0 {
		// If server is still better than other proxies, use it
		if serverScore > bestScore {
			return serverHostname, serverScore
		}
	}

	// If we found a good proxy, use it
	if bestProxy != "" {
		return bestProxy, bestScore
	}

	// If everything else failed and we have a server, use it as last resort
	if serverHostname != "" {
		return serverHostname, serverScore
	}

	return "", 0
}

type SimpleCheckResponse struct {
	BestProxy   string            `json:"best_proxy"`
	PingLatency float64           `json:"ping_latency_ms,omitempty"`
	SNMPResults map[string]string `json:"snmp_results,omitempty"`
	SSH         string            `json:"ssh,omitempty"`
	Traceroute  *TracerouteResult `json:"traceroute,omitempty"`
}

// Add this to the Server struct methods
func (s *Server) handleSimpleCheck(w http.ResponseWriter, r *http.Request) {
	var req CheckRequest

	// Check if this is a JSON POST request
	if r.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
	} else {
		// Handle query parameters for backward compatibility
		req.Target = r.URL.Query().Get("target")
		checksStr := r.URL.Query().Get("checks")
		if checksStr != "" {
			req.Checks = strings.Split(checksStr, ",")
		}
		oidsStr := r.URL.Query().Get("oids")
		if oidsStr != "" {
			req.SNMPOIDs = strings.Split(oidsStr, ",")
		}
		if hops := r.URL.Query().Get("traceroute_hops"); hops != "" {
			if h, err := strconv.Atoi(hops); err == nil {
				req.TracerouteHops = h
			}
		}
		req.Community = r.URL.Query().Get("community")
		req.SNMPVersion = r.URL.Query().Get("snmp_version")
	}

	if req.Target == "" {
		http.Error(w, "Missing target", http.StatusBadRequest)
		return
	}

	// Set default checks if none specified
	if len(req.Checks) == 0 {
		req.Checks = []string{"ping", "snmp"}
	}

	// Validate and clean OIDs
	var oids []string
	if len(req.SNMPOIDs) > 0 {
		for _, oid := range req.SNMPOIDs {
			oid = strings.TrimSpace(oid)
			if isValidOID(oid) {
				oids = append(oids, oid)
			}
		}
	}

	// Only use defaults if no valid OIDs provided
	if len(oids) == 0 {
		oids = defaultOIDs
	}
	req.SNMPOIDs = oids

	// Set default community if not specified
	if req.Community == "" {
		req.Community = s.Constants.DefaultCommunity
	}

	// Get current hostname for default best_proxy
	currentHostname, _, _ := getSystemInfo()

	// Initialize response with default values
	response := SimpleCheckResponse{
		BestProxy: currentHostname, // Default to current hostname
	}

	// Check if we can handle the request locally first
	if contains(req.Checks, "snmp") {
		snmpResults, version, err := checkSNMPWithRequestedVersion(req.Target, req.SNMPOIDs, req.Community, req.SNMPVersion)
		if err == nil {
			response.SNMPResults = snmpResults
			log.Printf("Local SNMP check successful for %s using version %s", req.Target, version)

			// If we got successful SNMP results locally, we can just return these
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(response); err != nil {
				log.Printf("Failed to encode simple check response: %v", err)
				http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			}
			return
		}
	}

	// If we couldn't handle it locally or need other checks, try the proxies
	resultsChan := make(chan ProxyResult, len(s.Proxies))
	var wg sync.WaitGroup

	// Make sure we have at least one proxy
	if len(s.Proxies) == 0 {
		// If no proxies defined, add the local server as a proxy
		localProxy := ProxyConfig{
			Address:  fmt.Sprintf("localhost:8081"),
			Hostname: currentHostname,
		}
		wg.Add(1)
		go s.runProxyCheck(localProxy, req, &wg, resultsChan)
	} else {
		for _, proxy := range s.Proxies {
			wg.Add(1)
			go s.runProxyCheck(proxy, req, &wg, resultsChan)
		}
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Process results
	var bestProxy string
	var bestScore float64
	var bestResult ProxyResult
	var resultsReceived bool

	for result := range resultsChan {
		resultsReceived = true

		// Skip results with errors
		if result.Error != "" {
			continue
		}

		// Apply server penalty if needed
		if result.ProxyHostname == currentHostname {
			result.Score = result.Score * 0.5
		}

		if result.Score > bestScore {
			bestScore = result.Score
			bestProxy = result.ProxyHostname
			bestResult = result
		}
	}

	// If we got valid results, update the response
	if resultsReceived && bestProxy != "" {
		response.BestProxy = bestProxy

		if bestResult.Ping != nil && bestResult.Ping.Success {
			response.PingLatency = bestResult.Ping.LatencyMs
		}

		if bestResult.SNMPSuccess && bestResult.SNMPResults != nil {
			response.SNMPResults = bestResult.SNMPResults
		}

		if bestResult.SSH != "" {
			response.SSH = bestResult.SSH
		}

		if bestResult.Traceroute != nil && bestResult.Traceroute.Success {
			response.Traceroute = bestResult.Traceroute
		}
	} else {
		// Ensure we always have a best_proxy value, even if no proxy returned valid results
		log.Printf("No proxy returned valid results for %s, using current host as best_proxy", req.Target)
		// We already initialized response.BestProxy = currentHostname earlier, so it's set
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode simple check response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// Add runProxyCheck method to Server
func (s *Server) runProxyCheck(proxy ProxyConfig, req CheckRequest, wg *sync.WaitGroup, resultsChan chan<- ProxyResult) {
	defer wg.Done()

	client := &http.Client{Timeout: 30 * time.Second}

	// Build URL with parameters
	u, err := url.Parse(fmt.Sprintf("http://%s/check", proxy.Address))
	if err != nil {
		log.Printf("Dr. Claw's URL trap! Invalid proxy address %s: %v", proxy.Address, err)
		resultsChan <- ProxyResult{
			ProxyAddr:     proxy.Address,
			ProxyHostname: proxy.Hostname,
			Error:         fmt.Sprintf("Invalid proxy address: %v", err),
		}
		return
	}

	q := u.Query()
	q.Set("target", req.Target)
	q.Set("checks", strings.Join(req.Checks, ","))
	if req.Community != "" {
		q.Set("community", req.Community)
	}
	if len(req.SNMPOIDs) > 0 {
		q.Set("oids", strings.Join(req.SNMPOIDs, ","))
	}
	if req.TracerouteHops > 0 {
		q.Set("traceroute_hops", strconv.Itoa(req.TracerouteHops))
	}
	u.RawQuery = q.Encode()

	resp, err := client.Get(u.String())
	if err != nil {
		log.Printf("Dr. Claw's proxy trap! Failed to reach proxy %s: %v", proxy.Address, err)
		resultsChan <- ProxyResult{
			ProxyAddr:     proxy.Address,
			ProxyHostname: proxy.Hostname,
			Error:         fmt.Sprintf("Failed to reach proxy: %v", err),
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Dr. Claw's status trap! Proxy %s returned status: %d", proxy.Address, resp.StatusCode)
		resultsChan <- ProxyResult{
			ProxyAddr:     proxy.Address,
			ProxyHostname: proxy.Hostname,
			Error:         fmt.Sprintf("Proxy returned status: %d", resp.StatusCode),
		}
		return
	}

	var result ProxyResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Dr. Claw's JSON trap! Failed to decode response from proxy %s: %v", proxy.Address, err)
		resultsChan <- ProxyResult{
			ProxyAddr:     proxy.Address,
			ProxyHostname: proxy.Hostname,
			Error:         fmt.Sprintf("Failed to decode response: %v", err),
		}
		return
	}

	// Ensure proxy information is included
	result.ProxyAddr = proxy.Address
	result.ProxyHostname = proxy.Hostname

	resultsChan <- result
}

// Add new function for checking with specific version
func checkSNMPWithRequestedVersion(target string, oids []string, community string, requestedVersion string) (map[string]string, string, error) {
	switch strings.ToLower(requestedVersion) {
	case "v1":
		// For v1, just try once with shorter timeout
		results, err := checkSNMPWithVersion(target, oids, community, g.Version1)
		if err != nil {
			return nil, "", fmt.Errorf("SNMP v1 check failed: %v", err)
		}
		return results, "v1", nil
	case "v2c":
		// For v2c, try once with shorter timeout
		results, err := checkSNMPWithVersion(target, oids, community, g.Version2c)
		if err != nil {
			return nil, "", fmt.Errorf("SNMP v2c check failed: %v", err)
		}
		return results, "v2c", nil
	default:
		// For automatic version detection, try v2c first with very short timeout
		v2cResults, err := checkSNMPWithVersion(target, oids, community, g.Version2c)
		if err == nil {
			return v2cResults, "v2c", nil
		}

		// If v2c fails quickly, try v1
		v1Results, err := checkSNMPWithVersion(target, oids, community, g.Version1)
		if err == nil {
			return v1Results, "v1", nil
		}

		return nil, "", fmt.Errorf("SNMP checks failed - v2c: %v, v1: %v", err, err)
	}
}
