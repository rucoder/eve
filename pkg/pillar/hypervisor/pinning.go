// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// setThreadAffinity pins a single OS thread (tid) to the given CPU set.
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

// pinDomainThreads pins the domain's guest vCPU threads 1:1 (guest vCPU i ->
// ordered[i]) and, when emulator is non-empty (io_placement=housekeeping),
// pins every other QEMU thread to the emulator set.
//
// It is called from Start() at the one correct point in the containerd task
// lifecycle: after task Start has launched QEMU (paused via -S, so the vCPU
// threads exist and QMP is up) and BEFORE the QMP cont — i.e. after containerd
// has already written the cgroup cpuset, so our per-thread affinity is applied
// last and is not reset by the cpuset. ordered/emulator come straight from the
// domain's DomainStatus (bound into the Task via KvmContext.Task), so there is
// no ephemeral hand-off state and this is idempotent/safe to re-run on a boot
// retry.
func (ctx KvmContext) pinDomainThreads(domainName, qmpFile string, ordered, emulator []uint32) error {
	if len(ordered) == 0 {
		return nil // not a topology-pinned domain
	}
	tids, err := QmpGetVcpuThreadIDs(qmpFile)
	if err != nil {
		return fmt.Errorf("query-cpus-fast: %w", err)
	}
	if len(tids) != len(ordered) {
		return fmt.Errorf("vcpu count mismatch: qemu=%d ordered=%d", len(tids), len(ordered))
	}
	vcpuTid := map[int]bool{}
	for i, tid := range tids {
		if tid <= 0 {
			return fmt.Errorf("refusing to pin vcpu %d: invalid thread-id %d", i, tid)
		}
		vcpuTid[tid] = true
		if err := setThreadAffinity(tid, []uint32{ordered[i]}); err != nil {
			return fmt.Errorf("pin vcpu %d (tid %d) -> cpu %d: %w", i, tid, ordered[i], err)
		}
	}
	logrus.Infof("CPU pinning: domain %s pinned %d vCPUs 1:1 to host CPUs %v", domainName, len(tids), ordered)

	if len(emulator) == 0 {
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
		if err := setThreadAffinity(tid, emulator); err != nil {
			logrus.Warnf("CPU pinning: domain %s failed to pin emulator thread %d to %v: %v", domainName, tid, emulator, err)
		}
	}
	logrus.Infof("CPU pinning: domain %s pinned emulator/IO threads to host CPUs %v", domainName, emulator)
	return nil
}
