package nginx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"nginx-proxy-guard/internal/model"
)

// GenerateCloudIPsInclude generates a separate include file for cloud provider IP geo mapping
// This significantly reduces the main config file size when many cloud IPs are blocked
func (m *Manager) GenerateCloudIPsInclude(hostID string, ipRanges []string) error {
	if len(ipRanges) == 0 {
		// Remove the include file if no IPs to block
		includePath := filepath.Join(m.configPath, "includes", fmt.Sprintf("cloud_ips_%s.conf", hostID))
		if _, err := os.Stat(includePath); err == nil {
			os.Remove(includePath)
		}
		return nil
	}

	// Ensure includes directory exists
	includesDir := filepath.Join(m.configPath, "includes")
	if err := os.MkdirAll(includesDir, 0755); err != nil {
		return fmt.Errorf("failed to create includes directory: %w", err)
	}

	// The file is included inside a geo block, one network per line. Only a
	// range that is an IP address or a CIDR range is written: the downloaded
	// lists are stored as they arrive, a provider saved before the API checked
	// its ranges can hold anything, and one line that is neither fails nginx -t
	// for every host that blocks the provider.
	ranges := make([]string, 0, len(ipRanges))
	var skipped []string
	for _, ip := range ipRanges {
		ip = strings.TrimSpace(ip)
		if model.IsIPOrCIDR(ip) {
			ranges = append(ranges, ip)
		} else {
			skipped = append(skipped, ip)
		}
	}
	if len(skipped) > 0 {
		warnSkippedOnce("cloud ip ranges "+hostID+" "+skipped[0],
			"[WARN] Host %s: %d blocked cloud provider IP range(s) are not an IP address or CIDR range, so they are left out of the nginx config (first: %.60q). Correct the provider's IP ranges.",
			hostID, len(skipped), skipped[0])
	}

	// Build the geo block content efficiently
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Cloud Provider IPs for host %s\n", hostID))
	sb.WriteString(fmt.Sprintf("# Total ranges: %d\n", len(ranges)))

	for _, ip := range ranges {
		sb.WriteString(fmt.Sprintf("    %s 1;\n", ip))
	}

	includePath := filepath.Join(includesDir, fmt.Sprintf("cloud_ips_%s.conf", hostID))
	
	// Use atomic write to prevent nginx from reading partial config
	if err := m.writeFileAtomic(includePath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("failed to write cloud IPs include file: %w", err)
	}

	return nil
}

// RemoveCloudIPsInclude removes the cloud IPs include file for a host
func (m *Manager) RemoveCloudIPsInclude(hostID string) error {
	includePath := filepath.Join(m.configPath, "includes", fmt.Sprintf("cloud_ips_%s.conf", hostID))
	if _, err := os.Stat(includePath); err == nil {
		return os.Remove(includePath)
	}
	return nil
}

// GetCloudIPsIncludePath returns the path to the cloud IPs include file
func GetCloudIPsIncludePath(hostID string) string {
	return fmt.Sprintf("/etc/nginx/conf.d/includes/cloud_ips_%s.conf", hostID)
}
