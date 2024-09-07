//go:build wasm
// +build wasm

package buf

import (
	"io"
	"syscall"

	"github.com/xtls/xray-core/features/stats"
)

const useReadv = false

func NewReadVReader(reader io.Reader, rawConn syscall.RawConn, counter stats.Counter) Reader {
	panic("not implemented")
}
