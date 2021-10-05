# Adding Tests

## Quick Start

1. Fork and clone the [`mantle` repository](https://github.com/kinvolk/mantle/)
2. Move into `kola/tests/` and look for the package your test would best fit
3. Edit the file and add your test(s), ensuring that you register your new test(s) in the packages `init()`
4. Commit, push, and PR your result

### Example

Say we wanted to add a simple [noop](https://en.wikipedia.org/wiki/NOP_(code)) test in the `podman` test package. If we follow the above instructions it would look like this:

```
$ git clone git@github.com:$GITHUB_USERNAME/mantle.git
<snip/>
$ pushd kola/tests/
$ $EDITOR podman/podman.go  # Add the test
// Test: I'm a NOOP!
func podmanNOOP(c cluster.TestCluster) {
    // NOOP!
}
$ $EDITOR podman/podman.go # Register the test in the init
func init() {
    register.Register(&register.Test{
        Run:         podmanNOOP,
        ClusterSize: 1,
        Name:        `podman.noop`,
        Distros:     []string{"cl"},
    })
<snip/>
$ popd
$ ./build kola
# Check and ensure the test is there
$ ./bin/kola list | grep podman
podman.base                                     [all]                                   [all]   [rhcos]
podman.network                                  [all]                                   [all]   [rhcos]
podman.noop                                     [all]                                   [all]   [cl]
podman.workflow                                 [all]                                   [all]   [rhcos]
# Run your test and see what happens
$ sudo ./bin/kola run -b cl --qemu-image ~/developer-2823.0.0+2021-04-06-1555-a1/flatcar_production_qemu_image.img podman.noop
=== RUN   podman.noop
--- PASS: podman.noop (19.96s)
PASS, output in _kola_temp/qemu-2021-04-07-0924-2937
# git add/commit/push...
# Open PR to get the test added!
```

## Grouping Tests

Sometimes it makes sense to group tests together under a specific package, especially when these tests are related and require the same test parameters. For `kola` it only takes a forwarding function to do testing groups. This forwarding function should take `cluster.TestCluster` as it's only input, and execute running other tests with `cluster.TestCluster.Run()`.

It is worth noting that the tests within the group are executed sequentially and on the same machine. As such, it is not recommended to group tests which modify the system state.

Additionally, the FailFast flag can be enabled during the test registration to skip any remaining steps after a failure has occurred.

Continuing with the look at the `podman` package we can see that `podman.base` is registered like so:

```golang
    register.Register(&register.Test{
            Run:         podmanBaseTest,
            ClusterSize: 1,
            Name:        `podman.base`,
            Distros:     []string{"rhcos"},
    })
```

If we look at `podmanBaseTest` it becomes very obvious that it's not a test of it's own, but a group of tests.

```go
func podmanBaseTest(c cluster.TestCluster) {
        c.Run("info", podmanInfo)
        c.Run("resources", podmanResources)
        c.Run("network", podmanNetworksReliably)
}
```

## Adding New Packages

If you need to add a new testing package there are few steps that must be done.

1. Create a new directory in `kola/tests/` which is descriptive of what will be tested.
2. Add at least one file in the new directory with it's package the same name as it's directory name
3. Edit the kola/registry/registry.go file to include your new package
4. Add and register your new tests

As an example, let's say you want to add a new test package called `foo`.

1. First create `kola/tests/foo/`
2. Then `echo "package foo" > kola/tests/foo/foo.go`
3. Next, edit `kola/registry/registry.go` and add this to the imports `_ "github.com/flatcar-linux/mantle/kola/tests/foo"`

```golang
package registry

// Tests imported for registration side effects. These make up the OS test suite and is explicitly imported from the main package.
import (
        _ "github.com/flatcar-linux/mantle/kola/tests/coretest"
        _ "github.com/flatcar-linux/mantle/kola/tests/crio"
        _ "github.com/flatcar-linux/mantle/kola/tests/docker"
        _ "github.com/flatcar-linux/mantle/kola/tests/etcd"
        _ "github.com/flatcar-linux/mantle/kola/tests/foo"
<snip/>
```

4. Lastly, use $EDITOR on `kola/tests/foo/foo.go` adding in new test groups and tests.

## Full Example

### File: kola/tests/foo/foo.go
```golang
// Copyright 2019 Red Hat, Inc.
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

package foo

import (
        "github.com/flatcar-linux/mantle/kola/cluster"
        "github.com/flatcar-linux/mantle/kola/register"
)

// init runs when the package is imported and takes care of registering tests
func init() {
    register.Register(&register.Test{ // See: https://godoc.org/github.com/flatcar-linux/mantle/kola/register#Test
            Run:         exampleTestGroup,
            ClusterSize: 1,
            Name:        `example.example`,
            Flags:       []register.Flag{}, // See: https://godoc.org/github.com/flatcar-linux/mantle/kola/register#Flag
            Distros:     []string{"rhcos"},
            FailFast:    true,
    })
}

// exampleTestGroup groups all of the example.example tests together
func exampleTestGroup(c cluster.TestCluster) {
    c.Run("test1", exampleTestOne)
    c.Run("test2", exampleTestTwo)
}

// The first example test (and it does nothing!)
func exampleTestOne(c cluster.TestCluster) {
    // NOOP!
}

// The second example test and it makes sure os-release has content
func exampleTestTwo(c cluster.TestCluster) {
    // Get the first machine in the cluster
    m := c.Machines()[0]
    osrelease := c.MustSSH(m, `cat /etc/os-release`)
    if string(osrelease) == "" {
        c.Errorf("/etc/os-release was empty. Expected content.")
    }
}
```

### File: kola/registry/registry.go

```golang
package registry

// Tests imported for registration side effects. These make up the OS test suite and is explicitly imported from the main package.
import (
        _ "github.com/flatcar-linux/mantle/kola/tests/coretest"
        _ "github.com/flatcar-linux/mantle/kola/tests/crio"
        _ "github.com/flatcar-linux/mantle/kola/tests/docker"
        _ "github.com/flatcar-linux/mantle/kola/tests/etcd"
        _ "github.com/flatcar-linux/mantle/kola/tests/flannel"
        _ "github.com/flatcar-linux/mantle/kola/tests/foo"
        _ "github.com/flatcar-linux/mantle/kola/tests/ignition"
        _ "github.com/flatcar-linux/mantle/kola/tests/kubernetes"
        _ "github.com/flatcar-linux/mantle/kola/tests/locksmith"
        _ "github.com/flatcar-linux/mantle/kola/tests/metadata"
        _ "github.com/flatcar-linux/mantle/kola/tests/misc"
        _ "github.com/flatcar-linux/mantle/kola/tests/ostree"
        _ "github.com/flatcar-linux/mantle/kola/tests/packages"
        _ "github.com/flatcar-linux/mantle/kola/tests/podman"
        _ "github.com/flatcar-linux/mantle/kola/tests/rkt"
        _ "github.com/flatcar-linux/mantle/kola/tests/rpmostree"
        _ "github.com/flatcar-linux/mantle/kola/tests/systemd"
        _ "github.com/flatcar-linux/mantle/kola/tests/torcx"
        _ "github.com/flatcar-linux/mantle/kola/tests/update"
)
```
