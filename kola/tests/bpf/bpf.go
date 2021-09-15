// Copyright © Microsoft Corporation
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

package bpf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/mantle/kola/cluster"
	"github.com/coreos/mantle/kola/register"
	"github.com/coreos/pkg/capnslog"
)

var (
	plog = capnslog.NewPackageLogger("github.com/coreos/mantle", "kola/tests/bpf")
	// cmdPrefix is a temporary hack to pull `bcc` tools into Flatcar
	cmdPrefix = "docker run -d --name %s -v /lib/modules:/lib/modules -v /sys/kernel/debug:/sys/kernel/debug -v /sys/fs/cgroup:/sys/fs/cgroup -v /sys/fs/bpf:/sys/fs/bpf --privileged --net host --pid host quay.io/iovisor/bcc %s"
)

// Log defines the standarg log format
// from Docker
// https://docs.docker.com/config/containers/logging/json-file/
type Log struct {
	Log    string `json:"log"`
	Time   string `json:"time"`
	Stream string `json:"stream"`
}

func init() {
	register.Register(&register.Test{
		Run:         execsnoopTest,
		ClusterSize: 1,
		Name:        `bpf.execsnoop`,
		Distros:     []string{"cl"},
		// required while SELinux policy is not correcly updated to support
		// `bpf` and `perfmon` permission.
		Flags: []register.Flag{register.NoEnableSelinux},
	})
}

func execsnoopTest(c cluster.TestCluster) {
	c.Run("filter name and args", func(c cluster.TestCluster) {
		m := c.Machines()[0]
		containerName := "execsnoop"

		// filter commands with `docker ps`
		plog.Infof("running %s container", containerName)
		cmd := fmt.Sprintf(cmdPrefix, containerName, "/usr/share/bcc/tools/execsnoop -n docker -l ps")
		if _, err := c.SSH(m, cmd); err != nil {
			c.Fatalf("unable to run SSH command '%s': %v", cmd, err)
		}

		// sleep 2s to be sure that the container is correctly started
		time.Sleep(2 * time.Second)

		// generate some "traffic"
		_ = c.MustSSH(m, "docker ps")
		_ = c.MustSSH(m, "docker info")

		plog.Infof("getting logs from %s container", containerName)
		logs, err := c.SSH(m, fmt.Sprintf("sudo cat $(docker inspect --format='{{.LogPath}}' %s)", containerName))
		if err != nil {
			c.Fatalf("unable to run SSH command: %v", err)
		}

		l := Log{}
		dockerLogs := bytes.Split(logs, []byte("\n"))
		if len(dockerLogs) != 3 {
			// we have the headers of the table
			// then 2 lines for docker ps and the torcx call
			c.Fatalf("docker logs should hold 3 values. Got: %d", len(dockerLogs))
		}

		execFound := false
		for _, log := range dockerLogs {
			if len(log) == 0 {
				continue
			}

			if err := json.Unmarshal(log, &l); err != nil {
				c.Fatalf("unable to unmarshal log: %v", err)
			}
			plog.Infof("handling log %v", l)

			if l.Stream == "stderr" {
				c.Fatal("stream should not log to 'stderr'")
			}

			if strings.Contains(l.Log, "docker info") {
				c.Fatal("log should not container docker info")
			}

			if strings.Contains(l.Log, "docker ps") {
				execFound = true
			}
		}

		if !execFound {
			c.Fatal("did not get 'docker ps' in the logs")
		}
	})
}
