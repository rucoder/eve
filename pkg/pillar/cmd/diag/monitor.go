package diag

import (
	"encoding/json"
	"errors"
	"io"
	"net"

	framed "github.com/getlantern/framed"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

type Request struct {
	Command string `json:"command"`
	Id      uint64 `json:"id"`
}

type Response struct {
	Type   string          `json:"type"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
	Id     uint64          `json:"id"` // Id is the id of the request that this response is for
}

type IpcMessage struct {
	Type    string          `json:"type"`
	Message json.RawMessage `json:"message"`
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

	err = s.sendIpcMessage("response", resp)

	return err
}

func (s *IPCServer) sendIpcMessage(t string, msg any) error {
	var err error

	if data, err := json.Marshal(msg); err == nil {
		ipcMessage := IpcMessage{Type: t, Message: json.RawMessage(data)}
		if data, err = json.Marshal(ipcMessage); err == nil {
			log.Noticef("Sending IPC message: %s", string(data))
			_, err = s.codec.Write(data)
		}
	}
	return err
}

func (s *IPCServer) unimplementedResponse(req *Request) *Response {
	return &Response{
		Error: "Unimplemented",
		Id:    req.Id,
	}
}

func (s *IPCServer) unknownCommandResponse(req *Request) *Response {
	return &Response{
		Error: "Unknown command",
		Id:    req.Id,
	}
}

// handle request
func (s *IPCServer) handleRequest(ctx *diagContext, req *Request) *Response {
	switch req.Command {
	case "SetDPC":
		return s.unimplementedResponse(req)
	default:
		return s.unknownCommandResponse(req)
	}
}

func startMonitorIPCServer(ctx *diagContext) error {
	// Start the RPC server
	sockPath := "/run/monitor.sock"
	log.Noticef("Starting RPC server on %s", sockPath)

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
			ctx.IPCServer = server

			go func() {
				defer server.Close()
				server.run(ctx)
			}()

			go func() {
				for {
					ctx.dataUpdater = <-ctx.dataUpdaterChan
					log.Notice("[MON] Data for Monitor IPC is ready")
					if ctx.gotDPCList {
						log.Notice("[MON] Got DPC list")

						ctx.IPCServer.sendIpcMessage("DPCList", ctx.DevicePortConfigList)
					}
					if ctx.gotDNS {
						log.Notice("[MON] Got Device Network Status")

						ctx.IPCServer.sendIpcMessage("NetworkStatus", ctx.DeviceNetworkStatus)
					}

					// send info about downloads
					items := ctx.subDownloaderStatus.GetAll()
					for index, item := range items {
						ds := item.(types.DownloaderStatus)
						log.Notice("[MON] Got Downloader Status %d/%d", index, len(items))
						ctx.IPCServer.sendIpcMessage("DownloaderStatus", ds)
					}

				}
			}()
		}
	}()
	return nil
}
