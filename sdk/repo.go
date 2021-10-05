// Copyright 2015 CoreOS, Inc.
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

package sdk

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/flatcar-linux/mantle/system"
	"github.com/flatcar-linux/mantle/system/exec"
)

const (
	defaultGroup = "developer"

	// In the SDK chroot the repo is always at this location
	chrootRepoRoot = "/mnt/host/source"

	// Assorted paths under the repo root
	defaultCacheDir = ".cache"
	defaultBuildDir = "src/build"
	defaultBoardCfg = "src/scripts/.default_board"
)

func isDir(dir string) bool {
	stat, err := os.Stat(dir)
	return err == nil && stat.IsDir()
}

func envDir(env string) string {
	dir := os.Getenv(env)
	if dir == "" {
		return ""
	}
	if !filepath.IsAbs(dir) {
		log.Fatalf("%s is not an absolute path: %q", env, dir)
	}
	return dir
}

func RepoRoot() string {
	if dir := envDir("REPO_ROOT"); dir != "" {
		return dir
	}

	if isDir(chrootRepoRoot) {
		return chrootRepoRoot
	}

	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Invalid working directory: %v", err)
	}

	for dir := wd; ; dir = filepath.Dir(dir) {
		if isDir(filepath.Join(dir, ".repo")) {
			return dir
		} else if filepath.IsAbs(dir) {
			break
		}
	}

	return wd
}

func RepoCache() string {
	return filepath.Join(RepoRoot(), defaultCacheDir)
}

func DefaultBoard() string {
	defaultBoard := system.PortageArch() + "-usr"
	cfg := filepath.Join(RepoRoot(), defaultBoardCfg)
	board, err := ioutil.ReadFile(cfg)
	if err != nil {
		return defaultBoard
	}

	board = bytes.TrimSpace(board)
	if len(board) == 0 {
		return defaultBoard
	}

	return string(board)
}

func BoardRoot(board string) string {
	if board == "" {
		board = DefaultBoard()
	}
	return filepath.Join("/build", board)
}

func BuildRoot() string {
	if dir := envDir("BUILD_ROOT"); dir != "" {
		return dir
	}
	return filepath.Join(RepoRoot(), defaultBuildDir)
}

// version may be "latest" or a full version like "752.1.0+2015-07-27-1656"
func BuildImageDir(board, version string) string {
	if board == "" {
		board = DefaultBoard()
	}
	if version == "" {
		version = "latest"
	} else if version != "latest" {
		// Assume all builds are "attempt" #1
		version += "-a1"
	}
	dir := defaultGroup + "-" + version
	return filepath.Join(BuildRoot(), "images", board, dir)
}

func RepoInit(chroot, url, manifestBranch, name, repoBranch string, useHostDNS bool) error {
	return enterChroot(enter{
		Chroot:     chroot,
		CmdDir:     chrootRepoRoot,
		UseHostDNS: useHostDNS,
		Cmd: []string{"--",
			"repo", "init",
			"--manifest-url", url,
			"--manifest-branch", manifestBranch,
			"--manifest-name", name,
			"--repo-branch", repoBranch,
		}})
}

func RepoVerifyTag(branch string) error {
	manifestRepoDir := ".repo/manifests"
	if strings.HasPrefix(branch, "refs/tags/") {
		branch = strings.TrimPrefix(branch, "refs/tags/")
	}

	tag := exec.Command("git", "-C", manifestRepoDir, "tag", "-v", branch)
	tag.Stderr = os.Stderr
	return tag.Run()
}

func RepoSync(chroot string, force, verbose, useHostDNS bool) error {
	args := []string{"--", "repo", "sync", "--no-clone-bundle"}
	if force {
		args = append(args, "--force-sync")
	}
	if !verbose {
		args = append(args, "--quiet")
	}
	return enterChroot(enter{
		Chroot:     chroot,
		CmdDir:     chrootRepoRoot,
		Cmd:        args,
		UseHostDNS: useHostDNS,
	})
}

func ApplyPatch(chroot string, useHostDNS bool, repositoryPath, patchPath string) error {
	fileName := filepath.Base(patchPath)
	targetName := filepath.Join(repositoryPath, fileName) // Using a relative path

	source, err := os.Open(patchPath)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(targetName)
	if err != nil {
		return err
	}
	defer destination.Close()

	if _, err := io.Copy(destination, source); err != nil {
		return err
	}

	args := []string{"GIT_COMMITTER_NAME=Flatcar Buildbot", "GIT_COMMITTER_EMAIL=buildbot@flatcar-linux.org", "--", "git", "am", "-3", filepath.Join(chrootRepoRoot, targetName)}
	err = enterChroot(enter{
		Chroot:     chroot,
		CmdDir:     filepath.Join(chrootRepoRoot, repositoryPath),
		Cmd:        args,
		UseHostDNS: useHostDNS,
	})
	if err != nil {
		return err
	}

	return os.Remove(targetName)
}
