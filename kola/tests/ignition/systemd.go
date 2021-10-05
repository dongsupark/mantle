// Copyright 2018 Red Hat
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

package ignition

import (
	"strings"

	"github.com/flatcar-linux/mantle/kola/cluster"
	"github.com/flatcar-linux/mantle/kola/register"
	"github.com/flatcar-linux/mantle/platform/conf"
)

func init() {
	register.Register(&register.Test{
		Name:        "coreos.ignition.systemd.enable-service",
		Run:         enableSystemdService,
		ClusterSize: 1,
		// enable nfs-server, touch /etc/exports as it doesn't exist by default on Container Linux,
		// and touch /var/lib/nfs/etab (https://bugzilla.redhat.com/show_bug.cgi?id=1394395) for RHCOS
		UserData: conf.Ignition(`{
    "ignition": {"version": "2.2.0"},
    "systemd": {
        "units": [{
            "name":"nfs-server.service",
            "enabled":true
        }]
    },
    "storage": {
        "files": [{
            "filesystem":"root",
            "path":"/etc/exports"
        },
        {
            "filesystem":"root",
            "path":"/var/lib/nfs/etab"
        }]
    }
}`),
		UserDataV3: conf.Ignition(`{
    "ignition": {"version": "3.0.0"},
    "systemd": {
        "units": [{
            "name":"nfs-server.service",
            "enabled":true
        }]
    },
    "storage": {
        "files": [{
            "path":"/etc/exports"
        },
        {
            "path":"/var/lib/nfs/etab"
        }]
    }
}`),
		// https://github.com/coreos/mantle/issues/999
		// On the qemu-unpriv platform the DHCP provides no data, pre-systemd 241 the DHCP server sending
		// no routes to the link to spin in the configuring state. nfs-server.service pulls in the network-online
		// target which causes the basic machine checks to fail
		ExcludePlatforms: []string{"qemu-unpriv"},
		// FCOS just ships the client (see
		// https://github.com/coreos/fedora-coreos-tracker/issues/121).
		// Should probably just pick a different unit to test with, though
		// testing the NFS workflow is useful for RHCOS/CL.
		ExcludeDistros: []string{"fcos"},
	})
}

func enableSystemdService(c cluster.TestCluster) {
	m := c.Machines()[0]

	out := c.MustSSH(m, "systemctl status nfs-server.service")
	if strings.Contains(string(out), "inactive") {
		c.Fatalf("service was not enabled or systemd-presets did not run")
	}
}
