//go:build !wasm
// +build !wasm

package conf

import (
	"encoding/json"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/http"
	"google.golang.org/protobuf/proto"
)

func (v *HTTPAccount) Build() *http.Account {
	return &http.Account{
		Username: v.Username,
		Password: v.Password,
	}
}

func (c *HTTPServerConfig) Build() (proto.Message, error) {
	config := &http.ServerConfig{
		Timeout:          c.Timeout,
		AllowTransparent: c.Transparent,
		UserLevel:        c.UserLevel,
	}

	if len(c.Accounts) > 0 {
		config.Accounts = make(map[string]string)
		for _, account := range c.Accounts {
			config.Accounts[account.Username] = account.Password
		}
	}

	return config, nil
}

func (v *HTTPClientConfig) Build() (proto.Message, error) {
	config := new(http.ClientConfig)
	config.Server = make([]*protocol.ServerEndpoint, len(v.Servers))
	for idx, serverConfig := range v.Servers {
		server := &protocol.ServerEndpoint{
			Address: serverConfig.Address.Build(),
			Port:    uint32(serverConfig.Port),
		}
		for _, rawUser := range serverConfig.Users {
			user := new(protocol.User)
			if err := json.Unmarshal(rawUser, user); err != nil {
				return nil, errors.New("failed to parse HTTP user").Base(err).AtError()
			}
			account := new(HTTPAccount)
			if err := json.Unmarshal(rawUser, account); err != nil {
				return nil, errors.New("failed to parse HTTP account").Base(err).AtError()
			}
			user.Account = serial.ToTypedMessage(account.Build())
			server.User = append(server.User, user)
		}
		config.Server[idx] = server
	}
	config.Header = make([]*http.Header, 0, 32)
	for key, value := range v.Headers {
		config.Header = append(config.Header, &http.Header{
			Key:   key,
			Value: value,
		})
	}
	return config, nil
}
