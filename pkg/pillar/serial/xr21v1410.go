// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// XR21V1410 Serial Controller support package
// documentstion: https://assets.maxlinear.com/web/documents/xr21v1412.pdf

package serial

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	XR_USB_SERIAL_GET_REG = 0xc0047601
	XR_USB_SERIAL_SET_REG = 0xc0047602
)

const (
	GPIO_MODE_REG    = 0x1A
	FLOW_CONTROL_REG = 0x0C
)

type Xr21v1410Reg struct {
	channel int
	reg     int
	value   int
}

type Xr21v1410Controller struct {
}

func xr21v1410IoCtl(fd int, op int, data Xr21v1410Reg) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(op),
		uintptr(unsafe.Pointer(&data)),
	)

	return errno
}

func setRegister(fd int, channel int, reg int, value int) error {
	data := Xr21v1410Reg{channel, reg, value}
	return xr21v1410IoCtl(fd, XR_USB_SERIAL_SET_REG, data)
}

type Xr21v1410Port struct {
	channelId  int
	mode       SerialPortMode
	rs485Mode  Rs485Mode
	devicePath string
}

func (p Xr21v1410Port) SetPortMode(mode SerialPortMode) error {
	p.mode = mode
	return nil
}

func (p Xr21v1410Port) SetRs485Mode(mode Rs485Mode) error {
	p.rs485Mode = mode
	return nil
}

func (p Xr21v1410Port) ApplySettings() error {
	var err error = nil

	// open the port
	file, err := os.Open(p.devicePath)
	defer file.Close()

	if err != nil {
		return err
	}

	if p.mode == SerialPortModeRS485 {
		fd := int(file.Fd())

		err = setRegister(fd, p.channelId, GPIO_MODE_REG, 0x0B)
		if err != nil {
			return err
		}
		if p.rs485Mode == Rs485ModeFullDuplex {
			err = setRegister(fd, p.channelId, FLOW_CONTROL_REG, 0x00)
		} else {
			err = setRegister(fd, p.channelId, FLOW_CONTROL_REG, 0x08)
		}
		if err != nil {
			return err
		}
	}
	return err
}

func (c *Xr21v1410Controller) GetPort(devicePath string) (SerialPort, error) {
	// devicePath should be /dev/ttyXRUSB*. We use the last character to get the channel id
	// check if the devicePath matches the expected pattern
	regexp := regexp.MustCompile(`/dev/ttyXRUSB(?P<Channel>\d{1})`)
	matches := regexp.FindStringSubmatch(devicePath)
	channelIndex := regexp.SubexpIndex("Channel")
	if len(matches) == 0 {
		return nil, fmt.Errorf("devicePath %s does not match the expected pattern", devicePath)
	}
	if len(matches) <= channelIndex || channelIndex == -1 {
		return nil, fmt.Errorf("devicePath %s does not contain channel id", devicePath)
	}
	channelIdStr := matches[channelIndex]
	// convert the channel id to int32
	// we can safely ignore the error here since we have already validated the channel id
	channelId, _ := strconv.Atoi(channelIdStr)

	return Xr21v1410Port{devicePath: devicePath, channelId: channelId, mode: SerialPortModeRS232}, nil
}
