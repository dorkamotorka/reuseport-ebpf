# Custom loadbalancing for SO_REUSEPORT using eBPF

SO_REUSEPORT is a powerful feature of the Linux kernel that allows users to have more than one process listen on a given port and allow for load balancing between them. The default load-balancing strategy is round-robin, but with the help of eBPF, we can take this feature one step further and implement other load-balancing strategies. In this lightning talk, you’ll learn to implement weighted and hot standby load balancing with nothing but eBPF and SO_REUSEPORT.

### Run it Yourself

First you need to build and run the eBPF programs:
```
go generate # Generate eBPF objects
go build # Build a GO program with the eBPF objects
sudo ./reuseport_ebpf primary # In one shell run one HTTP instance
sudo ./reuseport_ebpf standby # In another shell run the second HTTP instance
```

In the third shell you can then use `curl http://localhost:8080/hello` and watch the eBPF debug information using `sudo cat /sys/kernel/debug/tracing/trace_pipe`.
The log information should give you a nice overview of what’s happening behind the scenes e.g. which instance is receiving the request. 

In brief, if you shut down the primary HTTP instance, the requests will be forwarded to the standby instance until the primarycomes back online.
