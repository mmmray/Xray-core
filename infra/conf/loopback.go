package conf

import (
	"github.com/xtls/xray-core/proxy/loopback"
	"google.golang.org/protobuf/proto"
)

func (l LoopbackConfig) Build() (proto.Message, error) {
	return &loopback.Config{InboundTag: l.InboundTag}, nil
}
