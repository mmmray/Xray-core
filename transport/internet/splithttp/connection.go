package splithttp

import (
    "io"
    "net"
    "time"
)

type splitConn struct {
    downloadPipe io.WriteCloser
    uploadPipe io.ReadCloser
    remoteAddr net.Addr
    localAddr net.Addr
}

func (c *splitConn) Write(b []byte) (int, error) {
    return c.downloadPipe.Write(b)
}

func (c *splitConn) Read(b []byte) (int, error) {
    return c.uploadPipe.Read(b)
}

func (c *splitConn) Close() error {
    if err := c.downloadPipe.Close(); err != nil {
        return err
    }
    return c.uploadPipe.Close()
}

func (c *splitConn) LocalAddr() net.Addr {
    return c.localAddr
}

func (c *splitConn) RemoteAddr() net.Addr {
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

