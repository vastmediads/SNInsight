package capture

import (
	"net"
	"strings"
)

// DiscoverInterfaces 发现可用网卡
func DiscoverInterfaces(specified []string) ([]string, error) {
	if len(specified) > 0 {
		return specified, nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []string
	for _, iface := range ifaces {
		// 跳过回环接口
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// 跳过未启用的接口
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		// 跳过常见的虚拟接口
		name := iface.Name
		if shouldSkipInterface(name) {
			continue
		}
		result = append(result, name)
	}

	return result, nil
}

func shouldSkipInterface(name string) bool {
	skipPrefixes := []string{
		"lo",      // loopback
		"docker",  // docker
		"br-",     // docker bridge
		"veth",    // docker veth
		"virbr",   // libvirt bridge
		"vmnet",   // vmware
		"vboxnet", // virtualbox
		"utun",    // macOS utun
		"awdl",    // macOS awdl
		"llw",     // macOS llw
		"bridge",  // macOS bridge
		"gif",     // macOS gif
		"stf",     // macOS stf
		"anpi",    // macOS anpi
	}

	nameLower := strings.ToLower(name)
	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(nameLower, prefix) {
			return true
		}
	}
	return false
}
