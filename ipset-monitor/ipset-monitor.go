package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// IPSetMonitor структура для мониторинга ipset через периодическую проверку
type IPSetMonitor struct {
	targetSet    string
	scriptPath   string
	knownIPs     map[string]bool
	pollInterval time.Duration
}

// NewIPSetMonitor создает новый монитор
func NewIPSetMonitor(setName, scriptPath string, interval time.Duration) (*IPSetMonitor, error) {
	return &IPSetMonitor{
		targetSet:    setName,
		scriptPath:   scriptPath,
		knownIPs:     make(map[string]bool),
		pollInterval: interval,
	}, nil
}

// Start запускает мониторинг
func (m *IPSetMonitor) Start() error {
	log.Printf("Starting ipset monitor for set: %s", m.targetSet)
	log.Printf("Script to execute: %s", m.scriptPath)
	log.Printf("Poll interval: %v", m.pollInterval)

	// Обработка системных сигналов
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Получаем начальное состояние
	if err := m.updateKnownIPs(); err != nil {
		log.Printf("Warning: failed to get initial state: %v", err)
	}

	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	log.Println("Starting periodic ipset monitoring...")

	for {
		select {
		case <-ticker.C:
			if err := m.checkForChanges(); err != nil {
				log.Printf("Error checking for changes: %v", err)
			}
		case <-sigChan:
			log.Println("Received shutdown signal")
			return nil
		}
	}
}

// updateKnownIPs обновляет список известных IP адресов
func (m *IPSetMonitor) updateKnownIPs() error {
	currentIPs, err := m.getIPSetContents()
	if err != nil {
		return err
	}

	m.knownIPs = make(map[string]bool)
	for _, ip := range currentIPs {
		m.knownIPs[ip] = true
	}

	log.Printf("Updated known IPs for set '%s': %d entries", m.targetSet, len(m.knownIPs))
	return nil
}

// checkForChanges проверяет изменения в ipset
func (m *IPSetMonitor) checkForChanges() error {
	currentIPs, err := m.getIPSetContents()
	if err != nil {
		return err
	}

	// Проверяем новые IP
	for _, ip := range currentIPs {
		if !m.knownIPs[ip] {
			log.Printf("New IP detected in ipset '%s': %s", m.targetSet, ip)
			if err := m.executeScript(ip, m.targetSet); err != nil {
				log.Printf("Error executing script for IP %s: %v", ip, err)
			}
			m.knownIPs[ip] = true
		}
	}

	// Проверяем удаленные IP (опционально)
	currentIPMap := make(map[string]bool)
	for _, ip := range currentIPs {
		currentIPMap[ip] = true
	}

	for ip := range m.knownIPs {
		if !currentIPMap[ip] {
			log.Printf("IP removed from ipset '%s': %s", m.targetSet, ip)
			delete(m.knownIPs, ip)
		}
	}

	return nil
}

// getIPSetContents получает содержимое ipset
func (m *IPSetMonitor) getIPSetContents() ([]string, error) {
	var ips []string

	if m.targetSet == "" {
		// Мониторим все ipsets
		sets, err := m.getAllIPSets()
		if err != nil {
			return nil, err
		}

		for _, setName := range sets {
			setIPs, err := m.getIPSetList(setName)
			if err != nil {
				log.Printf("Error getting contents of set %s: %v", setName, err)
				continue
			}
			ips = append(ips, setIPs...)
		}
	} else {
		// Мониторим конкретный ipset
		setIPs, err := m.getIPSetList(m.targetSet)
		if err != nil {
			return nil, err
		}
		ips = setIPs
	}

	return ips, nil
}

// getAllIPSets получает список всех ipsets
func (m *IPSetMonitor) getAllIPSets() ([]string, error) {
	cmd := exec.Command("ipset", "list", "-n")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list ipsets: %v", err)
	}

	var sets []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			sets = append(sets, line)
		}
	}

	return sets, nil
}

// getIPSetList получает список IP адресов из конкретного ipset
func (m *IPSetMonitor) getIPSetList(setName string) ([]string, error) {
	cmd := exec.Command("ipset", "list", setName)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list ipset %s: %v", setName, err)
	}

	var ips []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	
	// Регулярное выражение для IP адресов
	ipRegex := regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d+)?.*$`)
	ipv6Regex := regexp.MustCompile(`^([0-9a-fA-F:]+)(/\d+)?.*$`)

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

		// Проверяем IPv4
		if matches := ipRegex.FindStringSubmatch(line); matches != nil {
			ips = append(ips, matches[1])
			continue
		}

		// Проверяем IPv6
		if matches := ipv6Regex.FindStringSubmatch(line); matches != nil {
			ips = append(ips, matches[1])
			continue
		}
	}

	return ips, nil
}

// executeScript выполняет скрипт при обнаружении нового IP
func (m *IPSetMonitor) executeScript(ipAddress, setName string) error {
	log.Printf("Executing script for IP: %s in set: %s", ipAddress, setName)
	
	cmd := exec.Command(m.scriptPath, ipAddress, setName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to execute script: %v", err)
	}
	
	log.Printf("Script executed successfully for IP: %s", ipAddress)
	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <ipset_name> <script_path> [poll_interval_seconds]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s \"\" <script_path> [poll_interval_seconds]  # monitor all ipsets\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s blacklist /opt/scripts/handle_ip.sh 5\n", os.Args[0])
		os.Exit(1)
	}

	setName := os.Args[1]
	scriptPath := os.Args[2]
	
	interval := 2 * time.Second // По умолчанию 2 секунды
	if len(os.Args) > 3 {
		if seconds, err := time.ParseDuration(os.Args[3] + "s"); err == nil {
			interval = seconds
		}
	}

	// Проверяем существование скрипта
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		log.Fatalf("Script not found: %s", scriptPath)
	}

	// Проверяем, что скрипт исполняемый
	if stat, err := os.Stat(scriptPath); err == nil {
		if stat.Mode()&0111 == 0 {
			log.Fatalf("Script is not executable: %s", scriptPath)
		}
	}

	// Создаем монитор
	monitor, err := NewIPSetMonitor(setName, scriptPath, interval)
	if err != nil {
		log.Fatalf("Failed to create monitor: %v", err)
	}

	// Запускаем мониторинг
	if err := monitor.Start(); err != nil {
		log.Fatalf("Failed to start monitor: %v", err)
	}
}