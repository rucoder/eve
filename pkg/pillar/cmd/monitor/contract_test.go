// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/types/monitorapi"
	uuid "github.com/satori/go.uuid"
)

func TestDeviceNetworkStatusToContract_NestsVLANs(t *testing.T) {
	eth0 := types.NetworkPortStatus{
		IfName:       "eth0",
		Logicallabel: "eth0",
		IsMgmt:       true,
		Up:           true,
		Cost:         0,
		Dhcp:         types.DhcpTypeClient,
		IPv4Subnet:   &net.IPNet{IP: net.ParseIP("192.168.1.0"), Mask: net.CIDRMask(24, 32)},
		AddrInfoList: []types.AddrInfo{
			{Addr: net.ParseIP("192.168.1.10")},
			{Addr: net.ParseIP("fe80::1")},      // link-local v6 -> dropped
			{Addr: net.ParseIP("2001:db8::10")}, // global v6 -> kept
		},
		DNSServers:     []net.IP{net.ParseIP("8.8.8.8")},
		DefaultRouters: []net.IP{net.ParseIP("192.168.1.1")},
	}
	eth0.ProxyConfig = types.ProxyConfig{
		NetworkProxyEnable: true,
		NetworkProxyURL:    "http://wpad/wpad.dat",
	}

	vlan := types.NetworkPortStatus{
		IfName:       "eth0.100",
		Logicallabel: "office-vlan",
		Up:           true,
		Dhcp:         types.DhcpTypeClient,
	}
	vlan.L2LinkConfig = types.L2LinkConfig{
		L2Type: types.L2LinkTypeVLAN,
		VLAN:   types.VLANConfig{ParentPort: "eth0", ID: 100},
	}

	got := deviceNetworkStatusToContract(types.DeviceNetworkStatus{
		Ports: []types.NetworkPortStatus{eth0, vlan},
	})

	if len(got.Interfaces) != 1 {
		t.Fatalf("expected 1 top-level interface (VLAN nested), got %d", len(got.Interfaces))
	}
	iface := got.Interfaces[0]
	if iface.Name != "eth0" || !iface.IsMgmt {
		t.Fatalf("unexpected interface: %+v", iface)
	}
	if _, ok := iface.Media.(monitorapi.MediaEthernet); !ok {
		t.Fatalf("expected ethernet media, got %T", iface.Media)
	}
	// addresses split by family, link-local v6 dropped.
	if len(iface.Network.IPv4) != 1 || iface.Network.IPv4[0].String() != "192.168.1.10" {
		t.Fatalf("unexpected ipv4: %v", iface.Network.IPv4)
	}
	if len(iface.Network.IPv6) != 1 || iface.Network.IPv6[0].String() != "2001:db8::10" {
		t.Fatalf("unexpected ipv6 (link-local should be dropped): %v", iface.Network.IPv6)
	}
	if iface.Network.Subnet == nil || iface.Network.Subnet.String() != "192.168.1.0/24" {
		t.Fatalf("unexpected subnet: %v", iface.Network.Subnet)
	}
	if _, ok := iface.Network.Proxy.(monitorapi.ProxyWpad); !ok {
		t.Fatalf("expected WPAD proxy, got %T", iface.Network.Proxy)
	}
	// VLAN nested under parent.
	if len(iface.VLANs) != 1 {
		t.Fatalf("expected 1 nested VLAN, got %d", len(iface.VLANs))
	}
	if v := iface.VLANs[0]; v.ID != 100 || v.Label != "office-vlan" || v.Name != "eth0.100" {
		t.Fatalf("unexpected VLAN: %+v", v)
	}
}

func TestProxyToContract_ManualByScheme(t *testing.T) {
	pc := types.ProxyConfig{
		Proxies: []types.ProxyEntry{
			{Type: types.NetworkProxyTypeHTTP, Server: "proxy", Port: 8080},
			{Type: types.NetworkProxyTypeHTTPS, Server: "proxy", Port: 8443},
		},
		Exceptions: "localhost, 127.0.0.1",
	}
	switch p := proxyToContract(pc).(type) {
	case monitorapi.ProxyManual:
		if len(p.Servers) != 2 || p.Servers[0].Scheme != monitorapi.ProxySchemeHTTP {
			t.Fatalf("unexpected servers: %+v", p.Servers)
		}
		if len(p.Exceptions) != 2 || p.Exceptions[1] != "127.0.0.1" {
			t.Fatalf("unexpected exceptions: %v", p.Exceptions)
		}
	default:
		t.Fatalf("expected ProxyManual, got %T", p)
	}
}

// A name is not a monitor. Under Xen, or for an instance that never got a
// QEMU, the reconstructed path does not exist; reporting it anyway has the
// console dial a socket that can never answer, once per app, forever.
//
// These call qmpSocketAt against qmpKvmStateDir - the production constant -
// rather than the deleted qmpSocketFor wrapper, so they exercise the same
// path appsListToContract actually runs.
func TestQmpSocketAtOnlyReportsAPathThatExists(t *testing.T) {
	if got := qmpSocketAt(qmpKvmStateDir, "", true); got != "" {
		t.Errorf("no domain name should report no socket, got %q", got)
	}
	if got := qmpSocketAt(qmpKvmStateDir, "6ba7b810-9dad-11d1-80b4-00c04fd430c8.1.1", true); got != "" {
		t.Errorf("a domain with no socket on disk should report none, got %q", got)
	}
}

// An app with no virtual GPU has no display behind its QMP socket, so the
// console must not be told to dial it.
func TestQMPSocketOnlyForVirtualGPUApps(t *testing.T) {
	if got := qmpSocketAt(qmpKvmStateDir, "vm1.1.1", false); got != "" {
		t.Errorf("an app without a virtual GPU must report no socket, got %q", got)
	}
}

// The positive case: an app that does have a virtual GPU, and whose socket
// exists on disk, must still be reported so the console can dial it. Without
// this, an implementation that ignored hasVirtualGPU entirely (or always
// returned "") would pass every other test in this file.
func TestQMPSocketReportedForVirtualGPUAppWithSocket(t *testing.T) {
	domainName := "6ba7b810-9dad-11d1-80b4-00c04fd430c8.1.1"
	dir := filepath.Join(t.TempDir(), domainName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	sock := filepath.Join(dir, "qmp")
	if err := os.WriteFile(sock, nil, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if got := qmpSocketAt(filepath.Dir(dir), domainName, true); got != sock {
		t.Errorf("expected %q, got %q", sock, got)
	}
}

// appsListToContract itself - not just qmpSocketAt - must key the GPU-mode
// lookup by UUID, never by DomainName (Task 7's settled decision:
// DomainName is "" until an app activates, and it changes across a
// controller version bump). A regression to
// types.GPUModeFor(a.DomainName) would still pass every qmpSocketAt test
// above, since those pass hasVirtualGPU in by hand; only a test that
// drives the lookup through appsListToContract itself exercises the key.
func appInstanceWithDomain(uuidStr, domainName string) types.AppInstanceStatus {
	appUUID, err := uuid.FromString(uuidStr)
	if err != nil {
		panic(err)
	}
	var a types.AppInstanceStatus
	a.UUIDandVersion.UUID = appUUID
	a.DomainName = domainName
	return a
}

func TestAppsListToContractReportsSocketForVirtualGPUApp(t *testing.T) {
	const appUUID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	domainName := appUUID + ".1.1"

	gpuModeDir := t.TempDir()
	modeFile := filepath.Join(gpuModeDir, appUUID+".json")
	if err := os.WriteFile(modeFile, []byte(`{"mode":"virtual"}`), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	qmpDir := t.TempDir()
	sockDir := filepath.Join(qmpDir, domainName)
	if err := os.MkdirAll(sockDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	sock := filepath.Join(sockDir, "qmp")
	if err := os.WriteFile(sock, nil, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	apps := []types.AppInstanceStatus{appInstanceWithDomain(appUUID, domainName)}
	got := appsListToContractAt(apps, gpuModeDir, qmpDir)
	if len(got.Instances) != 1 || got.Instances[0].QMPSocket != sock {
		t.Fatalf("expected socket %q reported, got %+v", sock, got.Instances)
	}
}

// This is the assertion that pins the keying: the mode file is named after
// DomainName rather than UUID (the shape of the regression this test
// guards against), so a correct UUID-keyed lookup finds nothing and
// defaults to passthrough - no socket - even though one exists on disk.
func TestAppsListToContractKeysGPUModeByUUIDNotDomainName(t *testing.T) {
	const appUUID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	domainName := appUUID + ".1.1"

	gpuModeDir := t.TempDir()
	modeFile := filepath.Join(gpuModeDir, domainName+".json")
	if err := os.WriteFile(modeFile, []byte(`{"mode":"virtual"}`), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	qmpDir := t.TempDir()
	sockDir := filepath.Join(qmpDir, domainName)
	if err := os.MkdirAll(sockDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sockDir, "qmp"), nil, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	apps := []types.AppInstanceStatus{appInstanceWithDomain(appUUID, domainName)}
	got := appsListToContractAt(apps, gpuModeDir, qmpDir)
	if len(got.Instances) != 1 || got.Instances[0].QMPSocket != "" {
		t.Fatalf("a mode file keyed by DomainName must not be found by a UUID-keyed lookup, got %+v", got.Instances)
	}
}
