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
	"strings"
	"sync"
	"time"
)

type Config struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	TunName  string `json:"tun_name"`
}

type RouteManager struct {
	config     Config
	client     *ssh.Client
	pending    map[string]bool
	mu         sync.Mutex
	lastCmd    time.Time
	connected  bool
}

func loadConfig(filename string) Config {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatal(err)
	}
	return config
}

func (rm *RouteManager) connect() error {
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
		return err
	}

	rm.client = client
	rm.connected = true
	rm.lastCmd = time.Now()
	return nil
}

func (rm *RouteManager) executeCommand(cmd string) error {
	if !rm.connected {
		return fmt.Errorf("not connected")
	}

	session, err := rm.client.NewSession()
	if err != nil {
		rm.connected = false
		return err
	}
	defer session.Close()

	err = session.Run(cmd)
	if err != nil {
		rm.connected = false
		return err
	}

	rm.lastCmd = time.Now()
	return nil
}

func (rm *RouteManager) sendPending() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for ip := range rm.pending {
		cmd := fmt.Sprintf("ip route add %s dev %s", ip, rm.config.TunName)
		if rm.executeCommand(cmd) == nil {
			delete(rm.pending, ip)
		}
	}
}

func (rm *RouteManager) addRoute(ip string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.connected {
		cmd := fmt.Sprintf("ip route add %s dev %s", ip, rm.config.TunName)
		if rm.executeCommand(cmd) == nil {
			return
		}
	}

	rm.pending[ip] = true
}

func (rm *RouteManager) keepAlive() {
	for {
		time.Sleep(60 * time.Second)
		rm.mu.Lock()
		if rm.connected && time.Since(rm.lastCmd) >= 60*time.Second {
			rm.executeCommand("echo")
		}
		rm.mu.Unlock()
	}
}

func (rm *RouteManager) maintainConnection() {
	for {
		if !rm.connected {
			if rm.connect() == nil {
				rm.sendPending()
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func (rm *RouteManager) handleInput() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			ip := parts[0]
			rm.addRoute(ip)
		}
	}
}

func main() {
	config := loadConfig("config.json")
	
	rm := &RouteManager{
		config:  config,
		pending: make(map[string]bool),
	}

	if rm.connect() != nil {
		log.Fatal("Failed to connect")
	}

	go rm.keepAlive()
	go rm.maintainConnection()
	
	rm.handleInput()
}