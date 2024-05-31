package splithttp

import (
	"context"
	"crypto/tls"
	"net/http"
    gonet "net"
	"sync"
	"time"
    "io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	v2tls "github.com/xtls/xray-core/transport/internet/tls"
)

type requestHandler struct {
	host string
	path string
	ln   *Listener
    sessions map[string]*io.PipeWriter
}

func (h *requestHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if len(h.host) > 0 && request.Host != h.host {
		newError("failed to validate host, request:", request.Host, ", config:", h.host).WriteToLog()
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	if request.URL.Path != h.path {
		newError("failed to validate path, request:", request.URL.Path, ", config:", h.path).WriteToLog()
		writer.WriteHeader(http.StatusNotFound)
		return
	}

    queryString := request.URL.Query()
    sessionId := queryString.Get("sessionId")
    if sessionId == "" {
		newError("no sessionid on request:", request.URL.Path).WriteToLog()
		writer.WriteHeader(http.StatusNotFound)
        return
    }

    forwardedAddrs := http_proto.ParseXForwardedFor(request.Header)
    remoteAddr, err := gonet.ResolveTCPAddr("tcp", request.RemoteAddr)
    if err != nil {
        remoteAddr = &gonet.TCPAddr{}
    }
    if len(forwardedAddrs) > 0 && forwardedAddrs[0].Family().IsIP() {
        remoteAddr = &net.TCPAddr{
            IP:   forwardedAddrs[0].IP(),
            Port: int(0),
        }
    }

    if request.Method == "POST" {
        uploadPipeWriter := h.sessions[sessionId] 
        io.Copy(uploadPipeWriter, request.Body)
		writer.WriteHeader(http.StatusOK)
    } else if request.Method == "GET" {
        uploadPipeReader, uploadPipeWriter := io.Pipe()
        downloadPipeReader, downloadPipeWriter := io.Pipe()

        h.sessions[sessionId] = uploadPipeWriter

        conn := serverConn {
            downloadPipe: downloadPipeWriter,
            uploadPipe: uploadPipeReader,
            remoteAddr: remoteAddr,
        }

		writer.WriteHeader(http.StatusOK)

        h.ln.addConn(stat.Connection(&conn))

        // "A ResponseWriter may not be used after [Handler.ServeHTTP] has returned."
        // therefore, let's block this goroutine with copying until it is done
        io.Copy(writer, downloadPipeReader)

        // the connection is finished, clean up map
        delete(h.sessions, sessionId)
    }
}

type serverConn struct {
    downloadPipe *io.PipeWriter
    uploadPipe *io.PipeReader
    remoteAddr gonet.Addr
}

func (c *serverConn) Write(b []byte) (int, error) {
    return c.downloadPipe.Write(b)
}

func (c *serverConn) Read(b []byte) (int, error) {
    return c.uploadPipe.Read(b)
}

func (c *serverConn) Close() error {
    err := c.downloadPipe.Close()
    if err != nil {
        return err
    }
    return c.uploadPipe.Close()
}

func (c *serverConn) LocalAddr() gonet.Addr {
    // TODO wrong
    return c.remoteAddr
}

func (c *serverConn) RemoteAddr() gonet.Addr {
    return c.remoteAddr
}

func (c *serverConn) SetDeadline(t time.Time) error {
    // TODO cannot do anything useful
    return nil
}

func (c *serverConn) SetReadDeadline(t time.Time) error {
    // TODO cannot do anything useful
    return nil
}

func (c *serverConn) SetWriteDeadline(t time.Time) error {
    // TODO cannot do anything useful
    return nil
}

type Listener struct {
	sync.Mutex
	server   http.Server
	listener net.Listener
	config   *Config
	addConn  internet.ConnHandler
}

func ListenSH(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	l := &Listener{
		addConn: addConn,
	}
	wsSettings := streamSettings.ProtocolSettings.(*Config)
	l.config = wsSettings
	if l.config != nil {
		if streamSettings.SocketSettings == nil {
			streamSettings.SocketSettings = &internet.SocketConfig{}
		}
	}
	var listener net.Listener
	var err error
	if port == net.Port(0) { // unix
		listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, newError("failed to listen unix domain socket(for SH) on ", address).Base(err)
		}
		newError("listening unix domain socket(for SH) on ", address).WriteToLog(session.ExportIDToError(ctx))
	} else { // tcp
		listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, newError("failed to listen TCP(for SH) on ", address, ":", port).Base(err)
		}
		newError("listening TCP(for SH) on ", address, ":", port).WriteToLog(session.ExportIDToError(ctx))
	}

	if config := v2tls.ConfigFromStreamSettings(streamSettings); config != nil {
		if tlsConfig := config.GetTLSConfig(); tlsConfig != nil {
			listener = tls.NewListener(listener, tlsConfig)
		}
	}

	l.listener = listener

	l.server = http.Server{
		Handler: &requestHandler{
			host: wsSettings.Host,
			path: wsSettings.GetNormalizedPath(),
			ln:   l,
		},
		ReadHeaderTimeout: time.Second * 4,
		MaxHeaderBytes:    8192,
	}

	go func() {
		if err := l.server.Serve(l.listener); err != nil {
			newError("failed to serve http for splithttp").Base(err).AtWarning().WriteToLog(session.ExportIDToError(ctx))
		}
	}()

	return l, err
}

// Addr implements net.Listener.Addr().
func (ln *Listener) Addr() net.Addr {
	return ln.listener.Addr()
}

// Close implements net.Listener.Close().
func (ln *Listener) Close() error {
	return ln.listener.Close()
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenSH))
}
