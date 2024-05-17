module github.com/hemanthmalla/reuseport_ebpf

go 1.21.0

toolchain go1.22.3

require (
	github.com/cilium/ebpf v0.15.0
	github.com/prometheus/procfs v0.15.0
	golang.org/x/sys v0.20.0
)

require golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
