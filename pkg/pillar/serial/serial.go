// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Serial Controller support package
// This package provides functions to setup desired mode for serial controller
// such as RS485, RS232, etc. and extra configurations like No RX while TX, etc.
package serial

import (
	"fmt"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	SERIAL_CONTROLLER_TYPE        = "serial-controller-type"
	SERIAL_PORT_MODE              = "serial-port-mode"
	SERIAL_PORT_MODE_RS232        = "rs232"
	SERIAL_PORT_MODE_RS485        = "rs485"
	SERIAL_PORT_MODE_RS422        = "rs422"
	SERIAL_RS485_MODE             = "rs485-mode"
	SERIAL_RS485_MODE_FULL_DUPLEX = "full-duplex"
	SERIAL_RS485_MODE_HALF_DUPLEX = "half-duplex"
)

type SerialPortMode int

const (
	SerialPortModeRS232 SerialPortMode = iota
	SerialPortModeRS485
	SerialPortModeRS422
)

type Rs485Mode int

const (
	Rs485ModeFullDuplex Rs485Mode = iota
	Rs485ModeHalfDuplex
)

// to string function for SerialPortMode
func (s SerialPortMode) String() string {
	return [...]string{"RS232", "RS485", "RS422"}[s]
}

func (r Rs485Mode) String() string {
	return [...]string{"Full Duplex", "Half Duplex"}[r]
}

// from string function for SerialPortMode
func SerialPortModeFromString(s string) (SerialPortMode, error) {
	s = strings.ToLower(s)
	switch s {
	case SERIAL_PORT_MODE_RS232:
		return SerialPortModeRS232, nil
	case SERIAL_PORT_MODE_RS485:
		return SerialPortModeRS485, nil
	case SERIAL_PORT_MODE_RS422:
		return SerialPortModeRS422, nil
	default:
		return SerialPortModeRS232, fmt.Errorf("Invalid Serial Port Mode: %s", s)
	}
}

// rs485 mode from a string
func Rs485ModeFromString(s string) (Rs485Mode, error) {
	s = strings.ToLower(s)
	switch s {
	case SERIAL_RS485_MODE_FULL_DUPLEX:
		return Rs485ModeFullDuplex, nil
	case SERIAL_RS485_MODE_HALF_DUPLEX:
		return Rs485ModeHalfDuplex, nil
	default:
		return Rs485ModeFullDuplex, fmt.Errorf("Invalid RS485 Mode: %s", s)
	}
}

type SerialController interface {
	GetPort(devicePath string) (SerialPort, error)
}

// interface to setup a serial controller
type SerialPort interface {
	SetPortMode(portMode SerialPortMode) error
	SetRs485Mode(rs485Mode Rs485Mode) error
	ApplySettings() error
}

// supported serial controllers
// must be in lower case
var supportedControllers = map[string]SerialController{
	"xr21v1410": &Xr21v1410Controller{},
}

func SetupSerial(ib *types.IoBundle) error {
	var err error = nil
	// by default, we don't need to do anything so check for
	// available Cbattr and return if not found
	if ib.Cbattr == nil {
		return nil
	}

	// by default, we assume the port mode is RS232
	serialPortMode := SerialPortModeRS232

	if portMode, modeFound := ib.Cbattr[SERIAL_PORT_MODE]; modeFound {
		if serialPortMode, err = SerialPortModeFromString(portMode); err != nil {
			return err
		}
	}

	// check for serial controller type and setup accordingly
	if controllerType, typeFound := ib.Cbattr[SERIAL_CONTROLLER_TYPE]; typeFound {
		//convert to lower case
		controllerType = strings.ToLower(controllerType)
		// check if the controller type is supported
		if controller, supported := supportedControllers[controllerType]; !supported {
			return fmt.Errorf("Unsupported Serial Controller: %s", controllerType)
		} else {
			// get the port and setup the mode
			port, err := controller.GetPort(ib.Serial)
			if err != nil {
				return err
			}
			// setup the port mode
			port.SetPortMode(serialPortMode)

			// setup rs485 mode if needed
			if serialPortMode == SerialPortModeRS485 {
				if rs485Mode, rs485ModeFound := ib.Cbattr[SERIAL_RS485_MODE]; rs485ModeFound {
					if rs485Mode, err := Rs485ModeFromString(rs485Mode); err != nil {
						if err := port.SetRs485Mode(rs485Mode); err != nil {
							return err
						}
					} else {
						return err
					}
				}
			}

			// apply settings
			if err := port.ApplySettings(); err != nil {
				return err
			}
		}
	}

	return nil
}
