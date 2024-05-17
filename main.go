package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go reuseportlb reuseportlb.c


import (
	"os"
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
	log.Println("Hello called!")
}

func getListenConfig(prog *ebpf.Program, mode string, otherInstancesRunning bool) net.ListenConfig {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			// Set SO_REUSEPORT on the socket
			opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			// Set eBPF program to be invoked for socket selection
			if prog != nil && mode == "primary" && !otherInstancesRunning {
				err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_EBPF, prog.FD())
				if err != nil {
					opErr = fmt.Errorf("setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed: %w", err)
				} else {
					log.Println("SO_ATTACH_REUSEPORT_EBPF completed successfully")
				}
			}
		})
		if err != nil {
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
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil { 
		log.Print("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs reuseportlbObjects 
	if err := loadReuseportlbObjects(&objs, nil); err != nil {
			log.Print("Loading eBPF objects:", err)
	}
	defer objs.Close() 

	mode := os.Args[1]
	if mode != "primary" && mode != "standby" {
		log.Println("Server mode should either be primary or standy")
		return
	}

	// Check if other instances are running on the same port - because we are testing SO_REUSEPORT
	fs, _ := procfs.NewDefaultFS()
	netTCP, _ := fs.NetTCP()
	otherInstancesRunning := false
	for _, i := range netTCP {
		if i.LocalPort == 8080 {
			otherInstancesRunning = true
			break
		}
	}

	http.HandleFunc("/hello", handleHello)
	server := http.Server{Addr: "127.0.0.1:8080", Handler: nil}
	lc := getListenConfig(objs.reuseportlbPrograms.HotStandbySelector, mode, otherInstancesRunning)
	ln, err := lc.Listen(context.Background(), "tcp", server.Addr)
	if err != nil {
		log.Fatal("Unable to listen of specified addr %w", err)
	} else {
		log.Println("Started listening in 127.0.0.1:8080 successfully !")
	}

	// Socket FD is the same for both instances - possible because of SO_REUSEPORT
	v := uint64(GetFdFromListener(ln))
	var k uint32
	if mode == "primary" {
		k = uint32(0)
	} else {
		k = uint32(1)
	}
	log.Printf("Updating with k=%d v=%d", k, v)

	err = objs.reuseportlbMaps.TcpBalancingTargets.Update(&k, &v, unix.BPF_ANY)
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