// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
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

	IPCServer *IPCServer
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

	if err = ctx.startIPCServer(); err != nil {
		log.Fatalf("Cannot start Monitor IPC server `%v`", err)
	}

	ctx.subscribe(ps)
	ctx.process(ps)
	return 0
}
