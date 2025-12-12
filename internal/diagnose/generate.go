//go:build linux

package diagnose

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang traffic ../../bpf/traffic.c -- -I../../bpf/headers -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -cc clang traffic ../../bpf/traffic.c -- -I../../bpf/headers -D__TARGET_ARCH_arm64
