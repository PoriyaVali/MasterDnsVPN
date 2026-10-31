//go:build linux

// Command node runs a MasterDnsVPN node the way V2bX embeds it (server.New,
// ChaCha20) for the CPU benchmark in ../drv, and profiles it on demand:
// SIGUSR1 starts a CPU profile, SIGUSR2 stops it and writes the allocation
// profile next to it (and the blocking profile, with MDNS_BLOCKPROF=1).
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"

	mdns "masterdnsvpn-go/server"
)

func uuidFor(i int) string { return fmt.Sprintf("5f0c6a8e-1111-4222-8333-%012d", i) }

func main() {
	port := flag.Int("port", 0, "UDP port")
	method := flag.Int("method", 2, "encryption method")
	users := flag.Int("users", 1, "users to register")
	prefix := flag.String("profile", "", "profile path prefix")
	egress := flag.Int("egress", 0, "SOCKS5 egress port on 127.0.0.1")
	flag.Parse()
	srv, err := mdns.New(mdns.Options{
		Domains:           []string{"t.e2e.test"},
		UDPHost:           "127.0.0.1",
		UDPPort:           *port,
		EncryptionMethod:  *method,
		EncryptionKey:     "0123456789abcdef0123456789abcdef",
		NodeSecret:        "e2e-node-secret",
		LogLevel:          "error",
		UseExternalSOCKS5: *egress != 0,
		ForwardIP:         "127.0.0.1",
		ForwardPort:       *egress,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for i := 0; i < *users; i++ {
		srv.AddUser(uuidFor(i))
	}
	if err := srv.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("READY")
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGTERM, syscall.SIGINT)
	n := 0
	var cpu *os.File
	for s := range sig {
		switch s {
		case syscall.SIGUSR1:
			if *prefix == "" || cpu != nil {
				continue
			}
			n++
			cpu, _ = os.Create(fmt.Sprintf("%s.%d.cpu", *prefix, n))
			_ = pprof.StartCPUProfile(cpu)
			if os.Getenv("MDNS_BLOCKPROF") != "" {
				runtime.SetBlockProfileRate(1)
			}
		case syscall.SIGUSR2:
			if cpu == nil {
				continue
			}
			pprof.StopCPUProfile()
			_ = cpu.Close()
			cpu = nil
			runtime.GC()
			if os.Getenv("MDNS_BLOCKPROF") != "" {
				if f, err := os.Create(fmt.Sprintf("%s.%d.block", *prefix, n)); err == nil {
					_ = pprof.Lookup("block").WriteTo(f, 0)
					_ = f.Close()
				}
				runtime.SetBlockProfileRate(0)
			}
			if f, err := os.Create(fmt.Sprintf("%s.%d.heap", *prefix, n)); err == nil {
				_ = pprof.Lookup("allocs").WriteTo(f, 0)
				_ = f.Close()
			}
		default:
			if cpu != nil {
				pprof.StopCPUProfile()
				_ = cpu.Close()
			}
			_ = srv.Close()
			return
		}
	}
}
