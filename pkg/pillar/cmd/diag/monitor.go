package diag

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	framed "github.com/getlantern/framed"
)

type networkInterface struct {
	Name   string `json:"name"`
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	IPv6   string `json:"ipv6"`
	Method string `json:"method"`
}

type networkData struct {
	Interfaces []networkInterface `json:"interfaces"`
}

type diagData struct {
	Network networkData `json:"network"`
}

type Request struct {
	Command string `json:"command"`
	Id      uint64 `json:"id"`
}

type Response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
	Id     uint64          `json:"id"` // Id is the id of the request that this response is for
}

type IPCServer struct {
	codec *framed.ReadWriteCloser
	// dataReady chan bool
	ctx       *diagContext
	dataReady string
}

// constructor
func NewIPCServer(conn net.Conn) *IPCServer {
	return &IPCServer{
		// the format of the frame is length + data
		// when the length is 16 bit unsigned integer
		codec: framed.NewReadWriteCloser(conn),
	}
}

// close the server
func (s *IPCServer) Close() {
	s.codec.Close()
}

// chack data ready
func (s *IPCServer) isDataReady() bool {
	return s.ctx.dataUpdater != ""
}

// main loop
func (s *IPCServer) run(ctx *diagContext) {
	// we never exit from the loop until the connection is closed
	// other errors are logged and we continue
	s.ctx = ctx
	for {
		// read request
		req, err := s.readRequest()
		if err != nil {
			log.Warnf("Error reading request: %v", err)
			// exit if EOF
			if errors.Is(err, io.EOF) {
				return
			}
			continue
		}
		// handle request
		resp := s.handleRequest(ctx, req)
		log.Noticef("Response: %v", resp)
		// send response
		if err := s.sendResponse(resp); err != nil {
			if errors.Is(err, io.EOF) {
				log.Notice("Connection closed by client")
				return
			}
			log.Warnf("Error sending response: %v", err)
		}
	}
}

// read request
func (s *IPCServer) readRequest() (*Request, error) {
	frame, err := s.codec.ReadFrame()
	if err != nil {
		return nil, err
	}
	log.Noticef("Received frame: %v", string(frame))
	var req Request
	if err := json.Unmarshal(frame, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// send response
func (s *IPCServer) sendResponse(resp *Response) error {
	var err error

	if data, err := json.Marshal(resp); err == nil {
		_, err = s.codec.Write(data)
	}
	return err
}

// handle request
func (s *IPCServer) handleRequest(ctx *diagContext, req *Request) *Response {
	// handle request
	switch req.Command {
	case "ping":
		return s.handlePing(req)
	case "GetData":
		return s.handleGetData(req)
	default:
		return &Response{
			Error: "Unknown command",
			Id:    req.Id,
		}
	}
}

// handle ping
func (s *IPCServer) handlePing(req *Request) *Response {
	// send pong and the current time
	currentTime := time.Now()

	result := struct {
		Pong string `json:"pong"`
	}{Pong: fmt.Sprintf("pong %s", currentTime.Format("2017-09-07 17:06:06"))}

	if result, err := json.Marshal(result); err != nil {
		return &Response{
			Error: "Error marshalling response to ping",
			Id:    req.Id,
		}
	} else {
		return &Response{
			Result: result,
			Id:     req.Id,
		}
	}
}

// extract nexessary data from the context
func (s *IPCServer) extractData() diagData {
	// get network data
	network := networkData{
		Interfaces: []networkInterface{
			{
				Name:   "eth0",
				IP:     "1.1.1.1",
				MAC:    "00:00:00:00:00:00",
				IPv6:   "2001:db8::1",
				Method: "dhcp",
			},
		},
	}
	return diagData{
		Network: network,
	}
}

// handle GetData
func (s *IPCServer) handleGetData(req *Request) *Response {
	// check if data is ready
	if !s.isDataReady() {
		return &Response{
			Error: "Data not ready",
			Id:    req.Id,
		}
	}
	// extract data
	data := s.extractData()
	// marshal data
	if result, err := json.Marshal(data); err != nil {
		return &Response{
			Error: "Error marshalling response to GetData",
			Id:    req.Id,
		}
	} else {
		return &Response{
			Result: result,
			Id:     req.Id,
		}
	}
}

func startMonitorIPCServer(ctx *diagContext) error {
	// Start the RPC server
	sockPath := "/run/monitor.sock"
	log.Noticef("Starting RPC server on %s", sockPath)

	go func() {
		for {
			ctx.dataUpdater = <-ctx.dataUpdaterChan
			log.Notice("Data ready")
		}
	}()

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}

	log.Notice("RPC server started")

	go func() {
		defer listener.Close()
		for {
			log.Notice("Waiting for IPC connection")
			conn, err := listener.Accept()
			log.Notice("Accepted connection")
			if err != nil {
				log.Warnf("Accept for RPC call failed: %v", err)
				continue
			}
			server := NewIPCServer(conn)

			go func() {
				defer server.Close()
				server.run(ctx)
			}()
		}
	}()
	return nil
}
