// Copyright 2018 Red Hat, Inc.
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

package rpmostree

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/flatcar-linux/mantle/kola/cluster"
	"github.com/flatcar-linux/mantle/kola/register"
	"github.com/flatcar-linux/mantle/kola/tests/util"
	"github.com/flatcar-linux/mantle/platform"
)

func init() {
	register.Register(&register.Test{
		Run:         rpmOstreeStatus,
		ClusterSize: 1,
		Name:        "rpmostree.status",
		Distros:     []string{"fcos", "rhcos"},
	})
}

var (
	// Regex to extract version number from "rpm-ostree status"
	rpmOstreeVersionRegex string = `^Version: ([0-9a-zA-Z.]+).*`
)

// rpmOstreeCleanup calls 'rpm-ostree cleanup -rpmb' on a host and verifies
// that only one deployment remains
func rpmOstreeCleanup(c cluster.TestCluster, m platform.Machine) error {
	c.MustSSH(m, "sudo rpm-ostree cleanup -rpmb")

	// one last check to make sure we are back to the original state
	cleanupStatus, err := util.GetRpmOstreeStatusJSON(c, m)
	if err != nil {
		return fmt.Errorf(`Failed to get status JSON: %v`, err)
	}

	if len(cleanupStatus.Deployments) != 1 {
		return fmt.Errorf(`Cleanup left more than one deployment`)
	}
	return nil
}

// rpmOstreeStatus does some sanity checks on the output from
// `rpm-ostree status` and `rpm-ostree status --json`
func rpmOstreeStatus(c cluster.TestCluster) {
	m := c.Machines()[0]

	// check that rpm-ostreed is static?
	enabledOut := c.MustSSH(m, "systemctl is-enabled rpm-ostreed")
	if string(enabledOut) != "static" {
		c.Fatalf(`The "rpm-ostreed" service is not "static": got %v`, string(enabledOut))
	}

	status, err := util.GetRpmOstreeStatusJSON(c, m)
	if err != nil {
		c.Fatal(err)
	}

	// after running an 'rpm-ostree' command the daemon should be active
	statusOut := c.MustSSH(m, "systemctl is-active rpm-ostreed")
	if string(statusOut) != "active" {
		c.Fatalf(`The "rpm-ostreed" service is not active: got %v`, string(statusOut))
	}

	// a deployment should be booted (duh!)
	var deploymentBooted bool
	for _, deployment := range status.Deployments {
		deploymentBooted = deploymentBooted || deployment.Booted
	}
	if !deploymentBooted {
		c.Fatalf(`No deployment reports as being booted`)
	}

	// let's validate that the version from the JSON matches the normal output
	var rpmOstreeVersion string
	rpmOstreeStatusOut := c.MustSSH(m, "rpm-ostree status")
	reVersion, err := regexp.Compile(rpmOstreeVersionRegex)
	statusArray := strings.Split(string(rpmOstreeStatusOut), "\n")
	for _, line := range statusArray {
		versionMatch := reVersion.FindStringSubmatch(strings.Trim(line, " "))
		if versionMatch != nil {
			// versionMatch should be like `[Version: 420.8.20190711.0 (2019-07-11T09:00:04Z) 420.8.20190711.0]`
			// i.e. the full match and the group we want
			// `versionMatch[len(versionMatch)-1]` gets the last element in the array
			rpmOstreeVersion = versionMatch[len(versionMatch)-1]
		}
	}

	if rpmOstreeVersion == "" {
		c.Fatalf(`Unable to determine version from "rpm-ostree status"`)
	}

	var deployedVersionFound bool
	for _, deployment := range status.Deployments {
		deployedVersionFound = deployedVersionFound || (deployment.Version == rpmOstreeVersion)
	}
	if !deployedVersionFound {
		c.Fatalf(`The version reported by stdout %q was not found in JSON output`, rpmOstreeVersion)
	}
}
