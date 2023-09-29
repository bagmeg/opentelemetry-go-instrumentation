// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auto

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/auto/internal/pkg/instrumentors"
	"go.opentelemetry.io/auto/internal/pkg/log"
	"go.opentelemetry.io/auto/internal/pkg/opentelemetry"
	"go.opentelemetry.io/auto/internal/pkg/process"
)

// COMM: 얘는 계측에 대한 타깃 바이너리를 가리키는 환경 변수의 키 값
// envTargetExeKey is the key for the environment variable value pointing to the
// target binary to instrument.
const envTargetExeKey = "OTEL_GO_AUTO_TARGET_EXE"

// COMM: 계측 정보 저장ㅎ하는 구조체
//
//	여기에는 타깃 함수, 분석기, 매니저가 포함
//	타깃 함수는 계측할 대상 함수
//	분석기는 실행중인 프로세스를 찾는 역할
//	매니저는 계측을 추가하고 관리하는 역할
//
// Instrumentation manages and controls all OpenTelemetry Go
// auto-instrumentation.
type Instrumentation struct {
	target   *process.TargetDetails
	analyzer *process.Analyzer
	manager  *instrumentors.Manager
}

// Error message returned when instrumentation is launched without a target
// binary.
var errUndefinedTarget = fmt.Errorf("undefined target Go binary, consider setting the %s environment variable pointing to the target binary to instrument", envTargetExeKey)

// COMM: 이 함수는 새로운 계측을 반환한다. 근데 제공된 opt 사용해서... 여기서는 안쓰고 있어. 언제쓰는거지??
// NewInstrumentation returns a new [Instrumentation] configured with the
// provided opts.
func NewInstrumentation(opts ...InstrumentationOption) (*Instrumentation, error) {
	// COMM: newInstConfig 결과로 타깃 바이너리를 가리키게 된다.
	c := newInstConfig(opts)
	// COMM: 타깃이 있는지 확인
	if err := c.validate(); err != nil {
		return nil, err
	}

	// COMM: 실행중인 프로세스를 찾는 analyzer 생성
	pa := process.NewAnalyzer()
	// COMM: 프로세스를 찾는다.
	pid, err := pa.DiscoverProcessID(c.target)
	if err != nil {
		return nil, err
	}

	ctrl, err := opentelemetry.NewController(Version())
	if err != nil {
		return nil, err
	}

	mngr, err := instrumentors.NewManager(ctrl)
	if err != nil {
		return nil, err
	}

	td, err := pa.Analyze(pid, mngr.GetRelevantFuncs())
	if err != nil {
		mngr.Close()
		return nil, err
	}
	log.Logger.V(0).Info(
		"target process analysis completed",
		"pid", td.PID,
		"go_version", td.GoVersion,
		"dependencies", td.Libraries,
		"total_functions_found", len(td.Functions),
	)
	mngr.FilterUnusedInstrumentors(td)

	return &Instrumentation{
		target:   td,
		analyzer: pa,
		manager:  mngr,
	}, nil
}

// Run starts the instrumentation.
func (i *Instrumentation) Run(ctx context.Context) error {
	return i.manager.Run(ctx, i.target)
}

// Close closes the Instrumentation, cleaning up all used resources.
func (i *Instrumentation) Close() error {
	i.analyzer.Close()
	i.manager.Close()
	return nil
}

// InstrumentationOption applies a configuration option to [Instrumentation].
type InstrumentationOption interface {
	apply(instConfig) instConfig
}

// COMM: 타깃에 대한 바이너리 정보 -> 타깃
type instConfig struct {
	target *process.TargetArgs
}

// COMM: 새로운 타깃 정보 갖는 설정 반환
func newInstConfig(opts []InstrumentationOption) instConfig {
	var c instConfig
	for _, opt := range opts {
		c = opt.apply(c)
	}
	c = c.applyEnv()
	return c
}

// COMM: 현재는 opt 따로 적용안하고 환경변수로 타깃 바이너리 설정한다.
func (c instConfig) applyEnv() instConfig {
	if v, ok := os.LookupEnv(envTargetExeKey); ok {
		c.target = &process.TargetArgs{ExePath: v}
	}
	return c
}

func (c instConfig) validate() error {
	if c.target == nil {
		return errUndefinedTarget
	}
	return c.target.Validate()
}

type fnOpt func(instConfig) instConfig

func (o fnOpt) apply(c instConfig) instConfig { return o(c) }

// WithTarget returns an [InstrumentationOption] defining the target binary for
// [Instrumentation] that is being executed at the provided path.
//
// If multiple of these options are provided to an [Instrumentation], the last
// one will be used.
//
// If OTEL_GO_AUTO_TARGET_EXE is defined it will take precedence over any value
// passed here.
func WithTarget(path string) InstrumentationOption {
	return fnOpt(func(c instConfig) instConfig {
		c.target = &process.TargetArgs{ExePath: path}
		return c
	})
}
