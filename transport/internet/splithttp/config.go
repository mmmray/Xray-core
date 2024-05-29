package splithttp

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

func (c *Config) GetNormalizedPath() string {
	path := c.Path
	if path == "" {
		path = "/"
	}
	if path[0] != '/' {
		path = "/" + path
	}
    if path[len(path)-1] != '/' {
        path = path + "/";
    }
	return path
}

func init() {
    common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
        return new(Config)
    }))
}
