package conf

import (
	"google.golang.org/protobuf/proto"
	
	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/app/observatory/burst"
)


func (o *ObservatoryConfig) Build() (proto.Message, error) {
	return &observatory.Config{SubjectSelector: o.SubjectSelector, ProbeUrl: o.ProbeURL, ProbeInterval: int64(o.ProbeInterval), EnableConcurrency: o.EnableConcurrency}, nil
}

func (b BurstObservatoryConfig) Build() (proto.Message, error) {
	if result, err := b.HealthCheck.Build(); err == nil {
		return &burst.Config{SubjectSelector: b.SubjectSelector, PingConfig: result.(*burst.HealthPingConfig)}, nil
	} else {
		return nil, err
	}
}
