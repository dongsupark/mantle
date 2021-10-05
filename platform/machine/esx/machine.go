// Copyright 2017 CoreOS, Inc.
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

package esx

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/flatcar-linux/mantle/platform"
	"github.com/flatcar-linux/mantle/platform/api/esx"
)

type machine struct {
	cluster *cluster
	mach    *esx.ESXMachine
	dir     string
	journal *platform.Journal
	console string
	ipPair  *esx.IpPair
}

func (em *machine) ID() string {
	return em.mach.Name
}

func (em *machine) IP() string {
	return em.mach.IPAddress
}

func (em *machine) PrivateIP() string {
	return em.mach.IPAddress
}

func (em *machine) RuntimeConf() platform.RuntimeConfig {
	return em.cluster.RuntimeConf()
}

func (em *machine) SSHClient() (*ssh.Client, error) {
	return em.cluster.SSHClient(em.IP())
}

func (em *machine) PasswordSSHClient(user string, password string) (*ssh.Client, error) {
	return em.cluster.PasswordSSHClient(em.IP(), user, password)
}

func (em *machine) SSH(cmd string) ([]byte, []byte, error) {
	return em.cluster.SSH(em, cmd)
}

func (em *machine) Reboot() error {
	return platform.RebootMachine(em, em.journal)
}

func (em *machine) Destroy() {
	if err := em.cluster.flight.api.TerminateDevice(em.ID()); err != nil {
		plog.Errorf("Error terminating device %v: %v", em.ID(), err)
	}

	if em.ipPair != nil {
		plog.Debugf("Setting static IP addresses %v and %v as available", (*em.ipPair).Public, (*em.ipPair).Private)
		em.cluster.flight.ips <- *em.ipPair
	}

	if em.journal != nil {
		em.journal.Destroy()
	}

	if err := em.saveConsole(); err != nil {
		plog.Errorf("Error saving console for device %v: %v", em.ID(), err)
	}

	if err := em.cluster.flight.api.CleanupDevice(em.ID()); err != nil {
		plog.Errorf("Error cleaning up device for device %v: %v", em.ID(), err)
	}

	em.cluster.DelMach(em)
}

func (em *machine) ConsoleOutput() string {
	return em.console
}

func (em *machine) saveConsole() error {
	var err error
	em.console, err = em.cluster.flight.api.GetConsoleOutput(em.ID())
	if err != nil {
		return err
	}

	path := filepath.Join(em.dir, "console.txt")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(em.console)
	if err != nil {
		return fmt.Errorf("failed writing console to file: %v", err)
	}

	return nil
}

func (em *machine) JournalOutput() string {
	if em.journal == nil {
		return ""
	}

	data, err := em.journal.Read()
	if err != nil {
		plog.Errorf("Reading journal for device %v: %v", em.ID(), err)
	}
	return string(data)
}

func (em *machine) Board() string {
	return em.cluster.flight.Options().Board
}
