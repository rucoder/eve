// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// pinRequest records how a domain's QEMU threads should be pinned. Applied in
// Start() after the vCPU threads exist (query-cpus-fast) but before cont.
type pinRequest struct {
	ordered  []uint32 // guest vCPU i -> host cpu ordered[i]
	emulator []uint32 // non-vCPU threads -> this set; nil => leave in cgroup cpuset
}

var domainPinning = struct {
	sync.Mutex
	m map[string]pinRequest
}{m: map[string]pinRequest{}}

func setPinRequest(domainName string, ordered, emulator []uint32) {
	domainPinning.Lock()
	defer domainPinning.Unlock()
	domainPinning.m[domainName] = pinRequest{ordered: ordered, emulator: emulator}
}

func takePinRequest(domainName string) (pinRequest, bool) {
	domainPinning.Lock()
	defer domainPinning.Unlock()
	r, ok := domainPinning.m[domainName]
	delete(domainPinning.m, domainName)
	return r, ok
}

func clearPinRequest(domainName string) {
	domainPinning.Lock()
	defer domainPinning.Unlock()
	delete(domainPinning.m, domainName)
}

func setThreadAffinity(tid int, cpus []uint32) error {
	var set unix.CPUSet
	set.Zero()
	for _, c := range cpus {
		set.Set(int(c))
	}
	return unix.SchedSetaffinity(tid, &set)
}

func qemuPid(domainName string) (int, error) {
	data, err := os.ReadFile(kvmStateDir + domainName + "/pid")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// pinDomainThreads applies the recorded pin request: vCPU threads 1:1 to their
// host cores, and (when io_placement=housekeeping) all other QEMU threads to
// the emulator set. No-op for domains without a topology-pinning request.
func (ctx KvmContext) pinDomainThreads(domainName, qmpFile string) error {
	req, ok := takePinRequest(domainName)
	if !ok || len(req.ordered) == 0 {
		return nil
	}
	tids, err := QmpGetVcpuThreadIDs(qmpFile)
	if err != nil {
		return fmt.Errorf("query-cpus-fast: %w", err)
	}
	if len(tids) != len(req.ordered) {
		return fmt.Errorf("vcpu count mismatch: qemu=%d ordered=%d", len(tids), len(req.ordered))
	}
	vcpuTid := map[int]bool{}
	for i, tid := range tids {
		if tid <= 0 {
			return fmt.Errorf("refusing to pin vcpu %d: invalid thread-id %d", i, tid)
		}
		vcpuTid[tid] = true
		if err := setThreadAffinity(tid, []uint32{req.ordered[i]}); err != nil {
			return fmt.Errorf("pin vcpu %d (tid %d) -> cpu %d: %w", i, tid, req.ordered[i], err)
		}
	}
	if len(req.emulator) == 0 {
		return nil // io_placement=dedicated: leave non-vCPU threads in the cgroup cpuset
	}
	pid, err := qemuPid(domainName)
	if err != nil {
		return fmt.Errorf("qemu pid: %w", err)
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return fmt.Errorf("read qemu task dir: %w", err)
	}
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil || vcpuTid[tid] {
			continue
		}
		// Emulator/IO threads are best-effort: some may be transient.
		if err := setThreadAffinity(tid, req.emulator); err != nil {
			logrus.Warnf("pin emulator tid %d -> %v: %v", tid, req.emulator, err)
		}
	}
	return nil
}
