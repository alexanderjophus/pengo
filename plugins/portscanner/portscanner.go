package main

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/viper"
	"github.com/trelore/pengo/scanner"
)

type PortScanner struct {
	Target    string `json:"target"`
	PortRange string `json:"port_range"`
}

func Checker() scanner.Checker {
	target := viper.GetViper().GetString("portscanner.target")
	portRange := viper.GetViper().GetString("portscanner.portrange")
	if target == "" || portRange == "" {
		return nil
	}
	ps := &PortScanner{
		Target:    target,
		PortRange: portRange,
	}
	return ps
}

func (p *PortScanner) Check() *scanner.Result {
	ports, err := p.portScanner()
	if err != nil {
		return &scanner.Result{
			Vulnerable: false,
			Success:    false,
			Reason:     err.Error(),
		}
	}
	reason := fmt.Sprintf("open ports: %v", ports)
	return &scanner.Result{
		Vulnerable: len(ports) > 0,
		Success:    true,
		Reason:     reason,
	}
}

func (p *PortScanner) portScanner() ([]int, error) {
	portsToScan, err := p.parsePortsToScan()
	if err != nil {
		return nil, err
	}

	ports := make(chan int, 100)
	results := make(chan int, 100)
	var openPorts []int

	for i := 0; i < cap(ports); i++ {
		go p.scan(ports, results)
	}

	go func() {
		for _, port := range portsToScan {
			ports <- port
		}
	}()

	for range portsToScan {
		port := <-results
		if port != 0 {
			openPorts = append(openPorts, port)
		}
	}

	close(ports)
	close(results)
	sort.Ints(openPorts)

	return openPorts, nil
}

func (p *PortScanner) scan(ports, results chan int) {
	for port := range ports {
		address := fmt.Sprintf("%s:%d", p.Target, port)
		conn, err := net.Dial("tcp", address)
		if err != nil {
			results <- 0
			continue
		}
		conn.Close()
		results <- port
	}
}

func (p *PortScanner) parsePortsToScan() ([]int, error) {
	// regex validate
	validPortRanges := regexp.MustCompile(`^([0-9]+(-[0-9]+)?)(,([0-9]+(-[0-9]+)?))*$`)
	if !validPortRanges.MatchString(p.PortRange) {
		return nil, fmt.Errorf("💥")
	}

	// separate by commas
	ranges := strings.Split(p.PortRange, ",")

	portsToScan := make(map[int]bool)
	// for each
	for _, r := range ranges {
		limits := strings.Split(r, "-")
		// if single number `22`
		if len(limits) == 1 {
			port, err := strconv.Atoi(limits[0])
			if err != nil {
				return nil, err
			}
			portsToScan[port] = true
			continue
		}
		// else range `21-25`
		lower, err := strconv.Atoi(limits[0])
		if err != nil {
			return nil, err
		}
		upper, err := strconv.Atoi(limits[1])
		if err != nil {
			return nil, err
		}
		if lower > upper {
			return nil, fmt.Errorf("range lower (%d) was higher than upper (%d)", lower, upper)
		}
		for i := lower; i <= upper; i++ {
			portsToScan[i] = true
		}
	}

	ret := make([]int, len(portsToScan))
	i := 0
	for port := range portsToScan {
		ret[i] = port
		i++
	}

	return ret, nil
}
