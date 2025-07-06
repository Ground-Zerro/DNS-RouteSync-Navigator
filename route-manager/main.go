package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	TunName  string `json:"tun_name"`
	IPSetName string `json:"ipset_name"`
	Interval int    `json:"interval"`
}

type RouteManager struct {
	config     Config
	client     *ssh.Client
	pending    map[string]bool
	mu         sync.Mutex
	lastCmd    time.Time
	connected  bool
	knownIPs   map[string]bool
	ipChan     chan string
}

func loadConfig(filename string) Config {
	log.Printf("Loading config from %s", filename)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Config loaded: host=%s, port=%s, interval=%d", config.Host, config.Port, config.Interval)
	return config
}

func (rm *RouteManager) connect() error {
	log.Printf("Connecting to %s:%s", rm.config.Host, rm.config.Port)
	config := &ssh.ClientConfig{
		User: rm.config.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(rm.config.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(rm.config.Host, rm.config.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		log.Printf("Connection failed: %v", err)
		return err
	}

	rm.client = client
	rm.connected = true
	rm.lastCmd = time.Now()
	log.Printf("Connected successfully")
	return nil
}

func (rm *RouteManager) executeCommand(cmd string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	if !rm.connected {
		log.Printf("Execute failed: not connected")
		return fmt.Errorf("not connected")
	}

	log.Printf("Executing: %s", cmd)
	session, err := rm.client.NewSession()
	if err != nil {
		rm.connected = false
		log.Printf("Session creation failed: %v", err)
		return err
	}
	defer session.Close()

	err = session.Run(cmd)
	if err != nil {
		rm.connected = false
		log.Printf("Command execution failed: %v", err)
		return err
	}

	rm.lastCmd = time.Now()
	log.Printf("Command executed successfully")
	return nil
}

func (rm *RouteManager) sendPending() {
	log.Printf("Sending %d pending routes", len(rm.pending))
	for ip := range rm.pending {
		cmd := fmt.Sprintf("ip route add %s dev %s", ip, rm.config.TunName)
		if rm.executeCommand(cmd) == nil {
			rm.mu.Lock()
			delete(rm.pending, ip)
			rm.mu.Unlock()
			log.Printf("Pending route added: %s", ip)
		}
	}
}

func (rm *RouteManager) addRoute(ip string) {
	log.Printf("Adding route for IP: %s", ip)
	if rm.connected {
		cmd := fmt.Sprintf("ip route add %s dev %s", ip, rm.config.TunName)
		if rm.executeCommand(cmd) == nil {
			log.Printf("Route added immediately: %s", ip)
			return
		}
	}

	rm.mu.Lock()
	rm.pending[ip] = true
	rm.mu.Unlock()
	log.Printf("Route queued for later: %s", ip)
}

func (rm *RouteManager) keepAlive() {
	log.Printf("Keep-alive goroutine started")
	for {
		time.Sleep(60 * time.Second)
		if rm.connected && time.Since(rm.lastCmd) >= 60*time.Second {
			log.Printf("Sending keep-alive")
			rm.executeCommand("echo")
		}
	}
}

func (rm *RouteManager) maintainConnection() {
	log.Printf("Connection maintenance goroutine started")
	for {
		if !rm.connected {
			log.Printf("Attempting to reconnect")
			if rm.connect() == nil {
				rm.sendPending()
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func (rm *RouteManager) handleRoutes() {
	log.Printf("Route handler goroutine started")
	for ip := range rm.ipChan {
		log.Printf("Processing IP from channel: %s", ip)
		rm.addRoute(ip)
	}
}

func (rm *RouteManager) getIPSetContents() ([]string, error) {
	log.Printf("Getting ipset contents for: %s", rm.config.IPSetName)
	cmd := exec.Command("ipset", "list", rm.config.IPSetName)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("ipset list failed: %v", err)
		return nil, fmt.Errorf("failed to list ipset %s: %v", rm.config.IPSetName, err)
	}

	var ips []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	
	ipRegex := regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d+)?.*$`)

	inMembers := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if strings.HasPrefix(line, "Members:") {
			inMembers = true
			continue
		}
		
		if !inMembers || line == "" {
			continue
		}

		if matches := ipRegex.FindStringSubmatch(line); matches != nil {
			ips = append(ips, matches[1])
		}
	}

	log.Printf("Found %d IPs in ipset", len(ips))
	return ips, nil
}

func (rm *RouteManager) updateKnownIPs() error {
	log.Printf("Updating known IPs")
	currentIPs, err := rm.getIPSetContents()
	if err != nil {
		return err
	}

	rm.knownIPs = make(map[string]bool)
	for _, ip := range currentIPs {
		rm.knownIPs[ip] = true
	}

	log.Printf("Known IPs updated: %d entries", len(rm.knownIPs))
	return nil
}

func (rm *RouteManager) checkForChanges() error {
	log.Printf("Checking for changes")
	currentIPs, err := rm.getIPSetContents()
	if err != nil {
		return err
	}

	newIPs := 0
	for _, ip := range currentIPs {
		if !rm.knownIPs[ip] {
			rm.ipChan <- ip
			rm.knownIPs[ip] = true
			newIPs++
		}
	}

	log.Printf("Found %d new IPs", newIPs)
	return nil
}

func (rm *RouteManager) monitor() {
	log.Printf("Monitor goroutine started")
	rm.updateKnownIPs()
	
	ticker := time.NewTicker(time.Duration(rm.config.Interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Printf("Monitor tick")
			rm.checkForChanges()
		}
	}
}

func main() {
	log.Printf("Starting application")
	config := loadConfig("config.json")
	
	rm := &RouteManager{
		config:   config,
		pending:  make(map[string]bool),
		knownIPs: make(map[string]bool),
		ipChan:   make(chan string, 100),
	}

	log.Printf("Initial connection attempt")
	if rm.connect() != nil {
		log.Fatal("Failed to connect")
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("Starting goroutines")
	go rm.keepAlive()
	go rm.maintainConnection()
	go rm.handleRoutes()
	go rm.monitor()

	log.Printf("Application ready, waiting for signals")
	<-sigChan
	log.Printf("Shutting down")
}