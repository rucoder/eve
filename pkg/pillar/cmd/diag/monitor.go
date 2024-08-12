package diag

import (
	"encoding/json"
	"errors"
	"io"
	"net"

	framed "github.com/getlantern/framed"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// All mesages except for Request type, have the following format:
// where type is one of the following:
// Request, Response, NetworkStatus, DPCList, DownloaderStatus
// message is a json object that can be flattened
//   {
//		"type": "Response",
//		"message": {
//   		"Err": "big error",
//	    	"id": 10
//		}
//   }
//
//   {
//    	"RequestType": "SetDPC",
//	    "RequestData": {
//	        "dddd": "test datat"
//	    },
//	    "id": 15
//   }

type Request struct {
	Id          uint64
	RequestType string          `json:"RequestType"`
	RequestData json.RawMessage `json:"RequestData"`
}

func (r *Request) validate() error {
	if r.RequestType == "" {
		return errors.New("RequestType is empty")
	}
	if r.RequestData == nil {
		return errors.New("RequestData is nil")
	}
	// check supported request types
	if r.RequestType != "SetDPC" {
		return errors.New("Unsupported RequestType " + r.RequestType)
	}
	return nil
}

type Response struct {
	// Ok and Err in exactly this spelling are variants or rust's Result<T, E> type
	Ok  string `json:"Ok,omitempty"`
	Err string `json:"Err,omitempty"`
	Id  uint64 `json:"id"` // Id is the id of the request that this response is for
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

	var request Request
	if err := json.Unmarshal(frame, &request); err != nil {
		return nil, err
	}
	return &request, nil
}

// send response
func (s *IPCServer) sendResponse(resp *Response) error {
	return s.sendIpcMessage("Response", resp)
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

func (r *Request) errResponse(errorText string, err error) *Response {
	if err != nil {
		errorText = errorText + ": " + err.Error()
	}
	return &Response{
		Err: errorText,
		Id:  r.Id,
	}
}

func (r *Request) okResponse() *Response {
	return &Response{
		Id: r.Id,
		Ok: "ok",
	}
}

func (r *Request) unimplementedResponse() *Response {
	return r.errResponse("Unimplemented request", nil)
}

func (r *Request) unknownRequestResponse() *Response {
	return r.errResponse("Unknown request", nil)
}

func (r *Request) malformedRequestResponse(err error) *Response {
	err_message := "Malformed request [" + string(r.RequestData) + "]"
	return r.errResponse(err_message, err)
}

func (r *Request) handleRequest(ctx *diagContext) *Response {
	switch r.RequestType {
	case "SetDPC":
		// Unmarshal the request data
		var dpc types.DevicePortConfig
		if err := json.Unmarshal(r.RequestData, &dpc); err != nil {
			if err := ctx.IPCServer.validateDPC(dpc); err != nil {
				return r.errResponse("Failed to validate DPC", err)
			}
			// publish the DPC
			if err := ctx.pubDevicePortConfig.Publish(dpc.Key, dpc); err != nil {
				return r.errResponse("Failed to publish DPC", err)
			} else {
				return r.okResponse()
			}
		} else {
			return r.malformedRequestResponse(err)
		}
	default:
		return r.unknownRequestResponse()
	}
}

func (s *IPCServer) validateDPC(dpc types.DevicePortConfig) error {
	//TODO: validate DPC
	return nil
}

// handle request
func (s *IPCServer) handleRequest(ctx *diagContext, req *Request) *Response {
	// validate request
	if err := req.validate(); err != nil {
		return req.errResponse("Failed to validate request", err)
	}
	// handle request
	return req.handleRequest(ctx)
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
					if ctx.IOAdapters.Initialized {
						log.Notice("[MON] Got IO Adapters")
						ctx.IPCServer.sendIpcMessage("IOAdapters", ctx.IOAdapters)
					}

					// send info about downloads
					items := ctx.subDownloaderStatus.GetAll()
					for key, item := range items {
						ds := item.(types.DownloaderStatus)
						log.Noticef("[MON] Got Downloader Status %s/%v", key, item)
						ctx.IPCServer.sendIpcMessage("DownloaderStatus", ds)
					}

					// send info about apps
					items = ctx.subAppInstanceStatus.GetAll()
					for _, item := range items {
						ais := item.(types.AppInstanceStatus)
						ctx.IPCServer.sendIpcMessage("AppStatus", ais)
					}

				}
			}()
		}
	}()
	return nil
}
