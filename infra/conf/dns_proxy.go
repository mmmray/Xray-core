//go:build !wasm
// +build !wasm

package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/dns"
	"google.golang.org/protobuf/proto"
)


func (c *DNSOutboundConfig) Build() (proto.Message, error) {
	config := &dns.Config{
		Server: &net.Endpoint{
			Network: c.Network.Build(),
			Port:    uint32(c.Port),
		},
		UserLevel: c.UserLevel,
	}
	if c.Address != nil {
		config.Server.Address = c.Address.Build()
	}
	switch c.NonIPQuery {
	case "":
		c.NonIPQuery = "drop"
	case "drop", "skip":
	default:
		return nil, errors.New(`unknown "nonIPQuery": `, c.NonIPQuery)
	}
	config.Non_IPQuery = c.NonIPQuery
	return config, nil
}
