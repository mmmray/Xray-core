//go:build !wasm
// +build !wasm

package conf

import (
	"github.com/xtls/xray-core/proxy/dokodemo"
	"google.golang.org/protobuf/proto"
)


func (v *DokodemoConfig) Build() (proto.Message, error) {
	config := new(dokodemo.Config)
	if v.Host != nil {
		config.Address = v.Host.Build()
	}
	config.Port = uint32(v.PortValue)
	config.Networks = v.NetworkList.Build()
	config.Timeout = v.TimeoutValue
	config.FollowRedirect = v.Redirect
	config.UserLevel = v.UserLevel
	return config, nil
}
