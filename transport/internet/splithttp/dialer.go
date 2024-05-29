package splithttp

import (
	"context"
	"net/http"
	"net/http/httptrace"
	"net/url"
    stdnet "net"
    "time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
)

func init() {
    common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

func maybeWrapTls(ctx context.Context, conn net.Conn, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (net.Conn, error) {
	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		tlsConfig := config.GetTLSConfig(tls.WithDestination(dest))
		if fingerprint := tls.GetFingerprint(config.Fingerprint); fingerprint != nil {
			conn = tls.UClient(conn, tlsConfig, fingerprint)
			if err := conn.(*tls.UConn).HandshakeContext(ctx); err != nil {
				return nil, err
			}
		} else {
			conn = tls.Client(conn, tlsConfig)
		}
	}

    return conn, nil
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	newError("dialing splithttp to ", dest).WriteToLog(session.ExportIDToError(ctx))

	downConn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

    downConn, err = maybeWrapTls(ctx, downConn, dest, streamSettings)
	if err != nil {
		return nil, err
	}

    transportConfiguration := streamSettings.ProtocolSettings.(*Config)

	var requestURL url.URL
    requestURL.Scheme = "http"
    requestURL.Host = dest.NetAddr()
    requestURL.Path = transportConfiguration.GetNormalizedPath()

    dialContext := func(ctxInner context.Context, network string, addr string) (net.Conn, error) {
        // XXX: ignoring network and addr param
        conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
        if err != nil {
            return nil, err
        }

        return maybeWrapTls(ctx, conn, dest, streamSettings)
    }

    httpTransport := http.Transport{
        DialContext: dialContext,
    }

    httpClient := http.Client{
        Transport: &httpTransport,
    }

    var remoteAddr stdnet.Addr

    trace := &httptrace.ClientTrace{
        GotConn: func(connInfo httptrace.GotConnInfo) {
            remoteAddr = connInfo.Conn.RemoteAddr()
        },
    }

    sessionIdUuid := uuid.New()
    sessionId := sessionIdUuid.String()

    req, err := http.NewRequest("GET", requestURL.String() + sessionId + "/down", nil)
    // TODO headers bruh
    if err != nil {
        return nil, err
    }
    req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

    downResponse, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }

    uploadUrl := requestURL.String() + sessionId + "/up"

    uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(128000))

    go func() {
        // by offloading the uploads into a buffered pipe, multiple conn.Write
        // calls get automatically batched together into larger POST requests.
        // without batching, bandwidth is extremely limited.
        for {
            chunk, err := uploadPipeReader.ReadMultiBuffer()
            if err != nil {
                break
            }

            resp, err := httpClient.Post(
                uploadUrl,
                "application/octet-stream", 
                &buf.MultiBufferContainer{ MultiBuffer: chunk },
            )

            if err != nil {
                break
            }

            if resp.Status != "200 OK" {
                break
            }
        }
    }()

    conn := splitConn {
        downResponse: downResponse,
        uploadPipe: buf.NewBufferedWriter(uploadPipeWriter),
        remoteAddr: remoteAddr,
        uploadUrl: uploadUrl,
    }

	return stat.Connection(&conn), nil
}

type splitConn struct {
    downResponse *http.Response
    uploadPipe *buf.BufferedWriter
    uploadClient http.Client
    remoteAddr stdnet.Addr
    uploadUrl string
}

func (c *splitConn) Read(b []byte) (int, error) {
    return c.downResponse.Body.Read(b)
}

func (c *splitConn) Write(b []byte) (int, error) {
    bytes, err := c.uploadPipe.Write(b)
    if err == nil {
        c.uploadPipe.Flush()
    }
    return bytes, err
}

func (c *splitConn) Close() error {
    err := c.downResponse.Body.Close()
    if err != nil {
        return err
    }
    return c.uploadPipe.Close()
}

func (c *splitConn) LocalAddr() stdnet.Addr {
    // TODO wrong
    return c.remoteAddr
}

func (c *splitConn) RemoteAddr() stdnet.Addr {
    return c.remoteAddr
}

func (c *splitConn) SetDeadline(t time.Time) error {
    // TODO cannot do anything useful
    return nil
}

func (c *splitConn) SetReadDeadline(t time.Time) error {
    // TODO cannot do anything useful
    return nil
}

func (c *splitConn) SetWriteDeadline(t time.Time) error {
    // TODO cannot do anything useful
    return nil
}
