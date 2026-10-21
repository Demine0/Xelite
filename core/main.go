// xelite-core is the network engine of Xelite for Windows 10 Mobile.
//
// It runs an Xray-core instance and a userspace TCP/IP stack (gVisor).
// The UWP VPN plug-in forwards every IP packet captured by the system VPN
// interface to this process as a single UDP datagram on 127.0.0.1:<port>,
// and receives reply packets the same way.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/transport/internet"
)

// useXrayDNS makes the bridge answer DNS queries itself (see bridge.resolve).
var useXrayDNS = true

func main() {
	configPath := flag.String("config", "config.json", "path to Xray JSON config")
	port := flag.Int("port", 10808, "loopback UDP port used for the packet bridge")
	mtu := flag.Int("mtu", 1500, "MTU of the VPN interface")
	statusPath := flag.String("status", "", "file to write startup status to")
	statsPath := flag.String("stats", "", "file to write traffic counters to every few seconds")
	ppid := flag.Int("ppid", 0, "exit when the process with this PID exits")
	allowIPv6 := flag.Bool("ipv6", false, "proxy IPv6 flows instead of rejecting them")
	flag.BoolVar(&useXrayDNS, "xraydns", true, "answer apps' DNS queries with Xray's DNS (DoH through the proxy) instead of relaying them as UDP")
	relayPort := flag.Int("relay", 0, "open outbound connections through the VPN plug-in's relay on this loopback port")
	flag.Parse()

	writeStatus := func(s string) {
		if *statusPath != "" {
			_ = os.WriteFile(*statusPath, []byte(s), 0o644)
		}
	}
	fail := func(err error) {
		writeStatus("error: " + err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	cfg, err := os.ReadFile(*configPath)
	if err != nil {
		fail(err)
	}
	// Created before Xray starts so the relay dialer can count into it.
	st := &stats{}
	if *relayPort != 0 {
		internet.UseAlternativeSystemDialer(&relayDialer{addr: fmt.Sprintf("127.0.0.1:%d", *relayPort), stats: st})
	}

	inst, err := core.StartInstance("json", cfg)
	if err != nil {
		fail(err)
	}
	defer inst.Close()

	b, err := newBridge(inst, *port, uint32(*mtu), !*allowIPv6, st)
	if err != nil {
		fail(err)
	}
	defer b.Close()
	writeStatus("ready")
	if *statsPath != "" {
		go b.stats.writeLoop(*statsPath, b.ctx.Done())
	}
	go b.heartbeatLoop(b.stats.fileError)

	if *ppid != 0 {
		go func() {
			if waitForProcess(*ppid) {
				os.Exit(0)
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
