// Copyright 2015-2018 CoreOS, Inc.
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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/flatcar-linux/mantle/kola"
	"github.com/flatcar-linux/mantle/platform"
	"github.com/flatcar-linux/mantle/platform/conf"
	"github.com/flatcar-linux/mantle/platform/machine/qemu"
	"github.com/flatcar-linux/mantle/sdk"
	"github.com/flatcar-linux/mantle/sdk/omaha"

	"github.com/coreos/pkg/capnslog"
)

var (
	cmdSpawn = &cobra.Command{
		Run:    runSpawn,
		PreRun: preRun,
		Use:    "spawn",
		Short:  "spawn a CoreOS instance",
	}

	spawnNodeCount      int
	spawnUserData       string
	spawnDetach         bool
	spawnOmahaPackage   string
	spawnShell          bool
	spawnRemove         bool
	spawnMachineOptions string
	spawnSetSSHKeys     bool
	spawnSSHKeys        []string
)

func init() {
	cmdSpawn.Flags().IntVarP(&spawnNodeCount, "nodecount", "c", 1, "number of nodes to spawn")
	cmdSpawn.Flags().StringVarP(&spawnUserData, "userdata", "u", "", "file containing userdata to pass to the instances")
	cmdSpawn.Flags().BoolVarP(&spawnDetach, "detach", "t", false, "-kv --shell=false --remove=false")
	cmdSpawn.Flags().StringVar(&spawnOmahaPackage, "omaha-package", "", "add an update payload to the Omaha server, referenced by image version (e.g. 'latest')")
	cmdSpawn.Flags().BoolVarP(&spawnShell, "shell", "s", true, "spawn a shell in an instance before exiting")
	cmdSpawn.Flags().BoolVarP(&spawnRemove, "remove", "r", true, "remove instances after shell exits")
	cmdSpawn.Flags().StringVar(&spawnMachineOptions, "qemu-options", "", "experimental: path to QEMU machine options json")
	cmdSpawn.Flags().BoolVarP(&spawnSetSSHKeys, "keys", "k", false, "add SSH keys from --key options")
	cmdSpawn.Flags().StringSliceVar(&spawnSSHKeys, "key", nil, "path to SSH public key (default: SSH agent + ~/.ssh/id_{rsa,dsa,ecdsa,ed25519}.pub)")
	root.AddCommand(cmdSpawn)
}

func runSpawn(cmd *cobra.Command, args []string) {
	if err := doSpawn(cmd, args); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func doSpawn(cmd *cobra.Command, args []string) error {
	var err error

	if spawnDetach {
		spawnSetSSHKeys = true
		capnslog.SetGlobalLogLevel(capnslog.INFO)
		spawnShell = false
		spawnRemove = false
	}

	if spawnNodeCount <= 0 {
		return fmt.Errorf("Cluster Failed: nodecount must be one or more")
	}

	var userdata *conf.UserData
	if spawnUserData != "" {
		userbytes, err := ioutil.ReadFile(spawnUserData)
		if err != nil {
			return fmt.Errorf("Reading userdata failed: %v", err)
		}
		userdata = conf.Unknown(string(userbytes))
	}
	if spawnSetSSHKeys {
		if userdata == nil {
			userdata = conf.Ignition(`{"ignition": {"version": "2.0.0"}}`)
		}
		sshKeys, err := GetSSHKeys(spawnSSHKeys)
		if err != nil {
			return err
		}
		// If the user explicitly passed empty userdata, the userdata
		// will be non-nil but Empty, and adding SSH keys will
		// silently fail.
		userdata = conf.AddSSHKeys(userdata, &sshKeys)
	}

	outputDir, err = kola.SetupOutputDir(outputDir, kolaPlatform)
	if err != nil {
		return fmt.Errorf("Setup failed: %v", err)
	}

	flight, err := kola.NewFlight(kolaPlatform)
	if err != nil {
		return fmt.Errorf("Flight failed: %v", err)
	}
	if spawnRemove {
		defer flight.Destroy()
	}

	cluster, err := flight.NewCluster(&platform.RuntimeConfig{
		OutputDir:        outputDir,
		AllowFailedUnits: true,
	})
	if err != nil {
		return fmt.Errorf("Cluster failed: %v", err)
	}

	if spawnRemove {
		defer cluster.Destroy()
	}

	var updateConf *strings.Reader
	if spawnOmahaPackage != "" {
		qc, ok := cluster.(*qemu.Cluster)
		if !ok {
			//TODO(lucab): expand platform support
			return errors.New("--omaha-package is currently only supported on qemu")
		}
		dir := sdk.BuildImageDir(kola.QEMUOptions.Board, spawnOmahaPackage)
		if err := omaha.GenerateFullUpdate(dir); err != nil {
			return fmt.Errorf("Building full update failed: %v", err)
		}
		updatePayload := filepath.Join(dir, "coreos_production_update.gz")
		if err := qc.OmahaServer.AddPackage(updatePayload, "update.gz"); err != nil {
			return fmt.Errorf("bad payload: %v", err)
		}
		hostport, err := qc.GetOmahaHostPort()
		if err != nil {
			return fmt.Errorf("getting Omaha server address: %v", err)
		}
		updateConf = strings.NewReader(fmt.Sprintf("GROUP=developer\nSERVER=http://%s/v1/update/\n", hostport))
	}

	var someMach platform.Machine
	for i := 0; i < spawnNodeCount; i++ {
		var mach platform.Machine
		var err error
		plog.Infof("Spawning machine...")
		if kolaPlatform == "qemu" && spawnMachineOptions != "" {
			var b []byte
			b, err = ioutil.ReadFile(spawnMachineOptions)
			if err != nil {
				return fmt.Errorf("Could not read machine options: %v", err)
			}

			var machineOpts platform.MachineOptions
			err = json.Unmarshal(b, &machineOpts)
			if err != nil {
				return fmt.Errorf("Could not unmarshal machine options: %v", err)
			}

			mach, err = cluster.(*qemu.Cluster).NewMachineWithOptions(userdata, machineOpts)
		} else {
			mach, err = cluster.NewMachine(userdata)
		}
		if err != nil {
			return fmt.Errorf("Spawning instance failed: %v", err)
		}
		if updateConf != nil {
			if err := platform.InstallFile(updateConf, mach, "/etc/coreos/update.conf"); err != nil {
				return fmt.Errorf("Setting update.conf: %v", err)
			}
		}

		plog.Infof("Machine %v spawned at %v\n", mach.ID(), mach.IP())

		someMach = mach
	}

	if spawnShell {
		if spawnRemove {
			reader := strings.NewReader(`PS1="\[\033[0;31m\][bound]\[\033[0m\] $PS1"` + "\n")
			if err := platform.InstallFile(reader, someMach, "/etc/profile.d/kola-spawn-bound.sh"); err != nil {
				return fmt.Errorf("Setting shell prompt failed: %v", err)
			}
		}
		if err := platform.Manhole(someMach); err != nil {
			return fmt.Errorf("Manhole failed: %v", err)
		}
	}
	return nil
}
