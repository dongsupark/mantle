// Copyright 2019 Red Hat
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

package unprivqemu

import (
	"os"

	"github.com/coreos/pkg/capnslog"

	"github.com/flatcar-linux/mantle/platform"
	"github.com/flatcar-linux/mantle/platform/machine/qemu"
)

const (
	Platform platform.Name = "qemu"
)

type flight struct {
	*platform.BaseFlight
	opts *qemu.Options

	diskImagePath string
	diskImageFile *os.File
}

var (
	plog = capnslog.NewPackageLogger("github.com/flatcar-linux/mantle", "platform/machine/qemu")
)

func NewFlight(opts *qemu.Options) (platform.Flight, error) {
	bf, err := platform.NewBaseFlight(opts.Options, Platform, "")
	if err != nil {
		return nil, err
	}

	qf := &flight{
		BaseFlight:    bf,
		opts:          opts,
		diskImagePath: opts.DiskImage,
	}

	return qf, nil
}

// NewCluster creates a Cluster instance, suitable for running virtual
// machines in QEMU.
func (qf *flight) NewCluster(rconf *platform.RuntimeConfig) (platform.Cluster, error) {
	bc, err := platform.NewBaseCluster(qf.BaseFlight, rconf)
	if err != nil {
		return nil, err
	}

	qc := &Cluster{
		BaseCluster: bc,
		flight:      qf,
	}

	qf.AddCluster(qc)

	return qc, nil
}

func (qf *flight) Destroy() {
	if qf.diskImageFile != nil {
		qf.diskImageFile.Close()
	}
}
