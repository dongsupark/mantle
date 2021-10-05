// Copyright 2016 CoreOS, Inc.
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

package qemu

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pborman/uuid"

	"github.com/flatcar-linux/mantle/platform"
	"github.com/flatcar-linux/mantle/platform/conf"
	"github.com/flatcar-linux/mantle/platform/local"
	"github.com/flatcar-linux/mantle/system/ns"
)

// Cluster is a local cluster of QEMU-based virtual machines.
//
// XXX: must be exported so that certain QEMU tests can access struct members
// through type assertions.
type Cluster struct {
	flight *flight

	mu sync.Mutex
	*local.LocalCluster
}

func (qc *Cluster) NewMachine(userdata *conf.UserData) (platform.Machine, error) {
	return qc.NewMachineWithOptions(userdata, platform.MachineOptions{})
}

func (qc *Cluster) NewMachineWithOptions(userdata *conf.UserData, options platform.MachineOptions) (platform.Machine, error) {
	id := uuid.New()

	dir := filepath.Join(qc.RuntimeConf().OutputDir, id)
	if err := os.Mkdir(dir, 0777); err != nil {
		return nil, err
	}

	// hacky solution for cloud config ip substitution
	// NOTE: escaping is not supported
	qc.mu.Lock()
	netif := qc.flight.Dnsmasq.GetInterface("br0")
	ip := strings.Split(netif.DHCPv4[0].String(), "/")[0]

	conf, err := qc.RenderUserData(userdata, map[string]string{
		"$public_ipv4":  "${COREOS_CUSTOM_PUBLIC_IPV4}",
		"$private_ipv4": "${COREOS_CUSTOM_PRIVATE_IPV4}",
	})
	if err != nil {
		qc.mu.Unlock()
		return nil, err
	}
	qc.mu.Unlock()

	conf.AddSystemdUnit("coreos-metadata.service", `[Unit]
Description=QEMU metadata agent
After=nss-lookup.target
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=OUTPUT=/run/metadata/flatcar
ExecStart=/usr/bin/mkdir --parent /run/metadata
ExecStart=/usr/bin/bash -c 'echo "COREOS_CUSTOM_PRIVATE_IPV4=`+ip+`\nCOREOS_CUSTOM_PUBLIC_IPV4=`+ip+`\n" > ${OUTPUT}'
ExecStartPost=/usr/bin/ln -fs /run/metadata/flatcar /run/metadata/coreos
`, false)

	var confPath string
	if conf.IsIgnition() {
		confPath = filepath.Join(dir, "ignition.json")
		if err := conf.WriteFile(confPath); err != nil {
			return nil, err
		}
	} else {
		confPath, err = local.MakeConfigDrive(conf, dir)
		if err != nil {
			return nil, err
		}
	}

	journal, err := platform.NewJournal(dir)
	if err != nil {
		return nil, err
	}

	qm := &machine{
		qc:          qc,
		id:          id,
		netif:       netif,
		journal:     journal,
		consolePath: filepath.Join(dir, "console.txt"),
	}

	qmCmd, extraFiles, err := platform.CreateQEMUCommand(qc.flight.opts.Board, qm.id, qc.flight.opts.BIOSImage, qm.consolePath, confPath, qc.flight.diskImagePath, conf.IsIgnition(), options)
	if err != nil {
		return nil, err
	}

	for _, file := range extraFiles {
		defer file.Close()
	}
	qmMac := qm.netif.HardwareAddr.String()

	qc.mu.Lock()

	tap, err := qc.NewTap("br0")
	if err != nil {
		qc.mu.Unlock()
		return nil, err
	}
	defer tap.Close()
	fdnum := 3 + len(extraFiles)
	qmCmd = append(qmCmd, "-netdev", fmt.Sprintf("tap,id=tap,fd=%d", fdnum),
		"-device", platform.Virtio(qc.flight.opts.Board, "net", "netdev=tap,mac="+qmMac))
	fdnum += 1
	extraFiles = append(extraFiles, tap.File)

	plog.Debugf("NewMachine: %q, %q, %q", qmCmd, qm.IP(), qm.PrivateIP())

	qm.qemu = qm.qc.NewCommand(qmCmd[0], qmCmd[1:]...)

	qc.mu.Unlock()

	cmd := qm.qemu.(*ns.Cmd)
	cmd.Stderr = os.Stderr

	cmd.ExtraFiles = append(cmd.ExtraFiles, extraFiles...)

	if err = qm.qemu.Start(); err != nil {
		return nil, err
	}

	plog.Debugf("qemu PID (manual cleanup needed if --remove=false): %v", qm.qemu.Pid())

	if err := platform.StartMachine(qm, qm.journal); err != nil {
		qm.Destroy()
		return nil, err
	}

	qc.AddMach(qm)

	return qm, nil
}

func (qc *Cluster) Destroy() {
	qc.LocalCluster.Destroy()
	qc.flight.DelCluster(qc)
}
