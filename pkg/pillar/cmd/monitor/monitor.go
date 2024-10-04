// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

const (
	agentName            = "monitor"
	errorTime            = 3 * time.Minute
	warningTime          = 40 * time.Second
	stillRunningInterval = 25 * time.Second
)

var logger *logrus.Logger
var log *base.LogObject

type monitorContext struct {
	agentbase.AgentBase

	subscriptions       map[string]pubsub.Subscription
	pubDevicePortConfig pubsub.Publication
	clientConnected     chan bool
	serverNameAndPort   string

	IPCServer *IPCServer
}

func (ctx *monitorContext) readServerFile() error {
	if _, err := os.Stat(types.ServerFileName); os.IsNotExist(err) {
		ctx.serverNameAndPort = ""
		return nil
	}
	server, err := os.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatal(err)
		return err
	}
	ctx.serverNameAndPort = strings.TrimSpace(string(server))
	return nil
}

func (ctx *monitorContext) updateServerFile(newServer string) error {
	// 1. Find the CONFIG partition
	findCmd := exec.Command("/sbin/findfs", "PARTLABEL=CONFIG")
	deviceBytes, err := findCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to find CONFIG partition: %v", err)
	}
	devicePath := strings.TrimSpace(string(deviceBytes))

	// 2. Create temp directory under /run
	tempDir, err := os.MkdirTemp("/run", "config-mount-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 3. Mount the CONFIG partition as read-write
	mountCmd := exec.Command("mount", "-t", "vfat", "-o", "rw,iocharset=iso8859-1", devicePath, tempDir)
	if err := mountCmd.Run(); err != nil {
		return fmt.Errorf("failed to mount CONFIG partition: %v", err)
	}
	defer exec.Command("umount", tempDir).Run()

	// 4. Write new server file
	tempServerFile := filepath.Join(tempDir, filepath.Base(types.ServerFileName))
	if err := os.WriteFile(tempServerFile, []byte(newServer), 0644); err != nil {
		return fmt.Errorf("failed to write new server file: %v", err)
	}

	// 5. Unmount temp directory (handled by defer)

	// 6. Update shadow copy in /config
	if err := os.WriteFile(types.ServerFileName, []byte(newServer), 0644); err != nil {
		return fmt.Errorf("failed to update shadow copy: %v", err)
	}
	ctx.serverNameAndPort = newServer
	return nil
}

func newMonitorContext() *monitorContext {
	ctx := &monitorContext{
		subscriptions: make(map[string]pubsub.Subscription),
	}
	ctx.IPCServer = newIPCServer(ctx)
	ctx.clientConnected = ctx.IPCServer.C()

	return ctx
}

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int { //nolint:gocyclo
	logger = loggerArg
	log = logArg
	var err error

	ctx := newMonitorContext()

	agentbase.Init(ctx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	if err = ctx.readServerFile(); err != nil {
		log.Fatalf("Server file exists but cannot be read `%v`", err)
	}

	if err = ctx.startIPCServer(); err != nil {
		log.Fatalf("Cannot start Monitor IPC server `%v`", err)
	}

	ctx.subscribe(ps)
	ctx.process(ps)
	return 0
}
