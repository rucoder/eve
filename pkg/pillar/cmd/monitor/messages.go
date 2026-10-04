// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"io/fs"
	"os"
	"reflect"
	"regexp"
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/types/monitorapi"
)

var (
	productSerialOnce sync.Once
	productSerial     string
)

// getProductSerial returns the hardware serial, computed once (it is static and
// reading it shells out to dmidecode).
func getProductSerial() string {
	productSerialOnce.Do(func() {
		productSerial = hardware.GetProductSerial(log)
	})
	return productSerial
}

var bootVariableRe = regexp.MustCompile(`^Boot[0-9a-fA-F]{4}$`)

// sendDeviceStatus assembles and emits the aggregated node-level snapshot from
// the latest of each input the handlers have stored. Deduped to avoid resending
// an unchanged snapshot.
func (ctx *monitor) sendDeviceStatus() {
	ds := deviceStatusToContract(ctx.serverNameAndPort, ctx.lastOnboarding,
		ctx.lastEdgeNodeInfo, getProductSerial(), ctx.lastZedAgent, ctx.lastVault)

	if ctx.lastDeviceStatus != nil && reflect.DeepEqual(*ctx.lastDeviceStatus, ds) {
		return
	}
	ctx.lastDeviceStatus = &ds

	ctx.IPCServer.sendIpcMessage("DeviceStatus", ds)
}

// sendNetworkStatus emits the current network snapshot straight from the
// subscription's cache. handleNetworStatusUpdate only fires on change, so
// without this a client that connects between changes never learns the
// network state at all.
func (ctx *monitor) sendNetworkStatus() {
	sub, ok := ctx.subscriptions["NetworkStatus"]
	if !ok || sub == nil {
		return
	}
	for _, item := range sub.GetAll() {
		status, ok := item.(types.DeviceNetworkStatus)
		if !ok {
			continue
		}
		ctx.IPCServer.sendIpcMessage("NetworkStatus", deviceNetworkStatusToContract(status))
	}
}

func (ctx *monitor) getAppInstancesStatus() []types.AppInstanceStatus {
	sub := ctx.subscriptions["AppStatus"]
	items := sub.GetAll()
	apps := make([]types.AppInstanceStatus, 0)
	for _, item := range items {
		appSummary := item.(types.AppInstanceStatus)
		apps = append(apps, appSummary)
	}
	return apps
}

// assignableAdapters is domainmgr's adapter list, or nil before it has
// published one.
func (ctx *monitor) assignableAdapters() *types.AssignableAdapters {
	sub, ok := ctx.subscriptions["AssignableAdapters"]
	if !ok || sub == nil {
		return nil
	}
	item, err := sub.Get("global")
	if err != nil {
		return nil
	}
	aa := item.(types.AssignableAdapters)
	return &aa
}

func (ctx *monitor) sendAppsList() {
	// send the application list to the client
	// empty list is allowed
	appStatus := ctx.getAppInstancesStatus()
	ctx.IPCServer.sendIpcMessage("AppsList", appsListToContract(appStatus, ctx.assignableAdapters()))
}

func readEfiVars(fsys fs.FS) ([]monitorapi.EFIVariable, error) {
	vars, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}

	// read boot order
	bootOrder, err := fs.ReadFile(fsys, "BootOrder")
	if err != nil {
		return nil, err
	}

	// read boot variables
	bootVars := make([]monitorapi.EFIVariable, 0)
	for _, varFile := range vars {
		varName := varFile.Name()
		if varFile.IsDir() || !bootVariableRe.MatchString(varName) {
			continue
		}
		varValue, err := fs.ReadFile(fsys, varName)
		if err != nil {
			return nil, err
		}
		bootVars = append(bootVars, monitorapi.EFIVariable{Name: varName, Value: varValue})
	}

	bootVars = append(bootVars, monitorapi.EFIVariable{Name: "BootOrder", Value: bootOrder})

	return bootVars, nil
}

func (ctx *monitor) sendTpmLogs() {
	currentGoodTpmLog, currentFailedTpmLog := evetpm.GetTpmLogFileNames()
	backupGoodTpmLog, backupFailedTpmLog := evetpm.GetTpmLogBackupFileNames()

	goodLog, err := os.ReadFile(currentGoodTpmLog)

	if err != nil {
		log.Warnf("Cannot read last good TPM log: %v", err)
		goodLog = nil
	}

	failedLog, err := os.ReadFile(currentFailedTpmLog)
	if err != nil {
		log.Warnf("Cannot read failed TPM log: %v", err)
		failedLog = nil
	}

	// backup logs
	backupGoodLog, err := os.ReadFile(backupGoodTpmLog)
	if err != nil {
		log.Warnf("Cannot read backup good TPM log: %v", err)
		backupGoodLog = nil
	}

	backupFailedLog, err := os.ReadFile(backupFailedTpmLog)
	if err != nil {
		log.Warnf("Cannot read backup failed TPM log: %v", err)
		backupFailedLog = nil
	}

	efiVarsDirSuccess, efiVarsDirFailed := evetpm.GetBootVariablesDirNames()

	bootVarsSuccess, err := readEfiVars(os.DirFS(efiVarsDirSuccess))
	if err != nil {
		log.Warnf("Cannot read boot variables: %v", err)
		bootVarsSuccess = nil
	}

	bootVarsFailed, err := readEfiVars(os.DirFS(efiVarsDirFailed))
	if err != nil {
		log.Warnf("Cannot read boot variables: %v", err)
		bootVarsFailed = nil
	}

	tpmLogs := monitorapi.TpmLogs{
		LastFailedLog:   failedLog,
		LastGoodLog:     goodLog,
		BackupFailedLog: backupFailedLog,
		BackupGoodLog:   backupGoodLog,
		EFIVarsSuccess:  bootVarsSuccess,
		EFIVarsFailed:   bootVarsFailed,
	}

	ctx.IPCServer.sendIpcMessage("TpmLogs", tpmLogs)
}

func (ctx *monitor) processGlobalConfig(cfg *types.ConfigItemValueMap) {
	if cfg == nil {
		return
	}

	logLevel := cfg.GlobalValueString(types.TUIMonitorLogLevel)

	ctx.IPCServer.sendIpcMessage("TUIConfig", tuiConfigToContract(logLevel))
}
