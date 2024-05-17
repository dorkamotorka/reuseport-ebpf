package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go reuseportlb reuseportlb.c


import (
	"os"
	"io"
	"fmt"
	"log"
	"net"
	"syscall"
	"reflect"
	"net/http"
	"context"
	"golang.org/x/sys/unix"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/procfs"
)

func handleHello(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, fmt.Sprintf("Hello from the %s target!\n", os.Args[1]))
}

// Inspired by src/net/dial.go
func getListenConfig(prog *ebpf.Program, mode string, otherInstancesRunning bool) net.ListenConfig {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var opErr error
		// If Control is not nil, it is called after creating the network
		// connection but before binding it to the operating system.
		err := c.Control(func(fd uintptr) {
			// Set SO_REUSEPORT on the socket for both instances (because eBPF program works on socket with SO_REUSEPORT configured)
			// This sets the SO_REUSEPORT option on the socket, which allows multiple sockets to bind to the same port.
			// In "function" words, for fd on the SOL_SOCKET level, set the SO_REUSEPORT option to 1 (a.k.a. true/on).
			opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			// Set eBPF program to be invoked for socket selection
			if prog != nil && mode == "primary" && !otherInstancesRunning {
				// SO_ATTACH_REUSEPORT_EBPF program defines how packets are assigned to the sockets in the reuseport group 
				// That is, all sockets which have SO_REUSEPORT set and are using the same local address to receive packets.
				// In "function" words, for fd on the SOL_SOCKET lever, set the unix.SO_ATTACH_REUSEPORT_EBPF option to eBPF program file descriptor.
				err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_EBPF, prog.FD())
				if err != nil {
					opErr = fmt.Errorf("setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed: %w", err)
				} else {
					log.Println("eBPF program attached to the SO_REUSEPORT socket group!")
				}
			}
		}); if err != nil {
			return err
		}
		return opErr
	}}
	return lc
}

// GetFdFromListener get net.Listener's file descriptor.
func GetFdFromListener(l net.Listener) int {
	v := reflect.Indirect(reflect.ValueOf(l))
	netFD := reflect.Indirect(v.FieldByName("fd"))
	pfd := netFD.FieldByName("pfd")
	fd := int(pfd.FieldByName("Sysfd").Int())
	return fd
}

func main() {
	mode := os.Args[1]
	if mode != "primary" && mode != "standby" {
		log.Println("Server mode should either be primary or standy")
		return
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil { 
		log.Print("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	// Map needs to be pinned, such that in case the primary target is shutdown, the standby target can still see the map
	var objs reuseportlbObjects 
	if mode == "primary" {
		if err := loadReuseportlbObjects(&objs, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/tc/globals"}}); err != nil {
				log.Print("Loading eBPF objects:", err)
		}
	}
	defer objs.Close() // This only unloads the eBPF program (if it is not attached to kernel) and map, but doesn't remove the pin

	// Check if other instances are already running on the same port - because we are testing SO_REUSEPORT
	fs, _ := procfs.NewDefaultFS()
	netTCP, _ := fs.NetTCP()
	otherInstancesRunning := false
	for _, i := range netTCP {
		if i.LocalPort == 8080 {
			otherInstancesRunning = true
			break
		}
	}

	// Setup HTTP Server instance
	// We can't directly use http.ListenAndServe because it hides the socket implementation (which is what we are interested in with SetsockoptInt)
	http.HandleFunc("/hello", handleHello)
	server := http.Server{Addr: "127.0.0.1:8080", Handler: nil}
	lc := getListenConfig(objs.reuseportlbPrograms.HotStandbySelector, mode, otherInstancesRunning)
	ln, err := lc.Listen(context.Background(), "tcp", server.Addr)
	if err != nil {
		log.Fatal("Unable to listen of specified addr %w", err)
	} else {
		log.Println("Started listening in 127.0.0.1:8080 successfully !")
	}

		// NOTE: Each process has it's own file descriptor table, so don't get confused if the FDs are the same for both processes
	v := uint64(GetFdFromListener(ln))
	var k uint32
	if mode == "primary" {
		k = uint32(0)
	} else {
		k = uint32(1)
	}

	log.Printf("Updating with (key = %d , value = %d)", k, v)
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/tcp_balancing_targets", nil)
	if err != nil {
		log.Fatal("Unable to load map: %w", err)
	}

	err = m.Update(&k, &v, ebpf.UpdateAny)
	if err != nil {
		log.Fatal("Unable to update the map %w", err)
	} else {
		log.Printf("Map update succeeded")
	}

	err = server.Serve(ln)
	if err != nil {
		log.Fatal("Unable to start HTTP server %w", err)
	}
}