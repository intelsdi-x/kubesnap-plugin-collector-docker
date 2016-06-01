// +build linux

/*
http://www.apache.org/licenses/LICENSE-2.0.txt


Copyright 2015-2016 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package client

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fsouza/go-dockerclient"
	"github.com/intelsdi-x/kubesnap-plugin-collector-docker/common"
	"github.com/intelsdi-x/kubesnap-plugin-collector-docker/fs"
	"github.com/intelsdi-x/kubesnap-plugin-collector-docker/network"
	"github.com/intelsdi-x/kubesnap-plugin-collector-docker/wrapper"
	"github.com/intelsdi-x/snap-plugin-utilities/ns"
	"github.com/opencontainers/runc/libcontainer/cgroups"
)

const endpoint string = "unix:///var/run/docker.sock"

const (
	memLimitInBytesCounter     = "memory.limit_in_bytes"
	memSwapLimitInBytesCounter = "memory.memsw.limit_in_bytes"

	// output stats key for limit in bytes
	memLimitInBytesKey = "limit_in_bytes"
	// output stats key for swap limit in bytes
	memSwapLimitInBytesKey = "swap_limit_in_bytes"

	procfsMountEnv = "PROCFS_MOUNT"
	procfsMountDef = "/proc"

)

type DockerClientInterface interface {
	ListContainersAsMap() (map[string]docker.APIContainers, error)
	GetStatsFromContainer(string) (*wrapper.Statistics, error)
	InspectContainer(string) (*docker.Container, error)
	FindCgroupMountpoint(string) (string, error)
}

type dockerClient struct {
	cl *docker.Client
}

type deviceInfo struct {
	device string
	major  string
	minor  string
}

func NewDockerClient() *dockerClient {
	client, err := docker.NewClient(endpoint)
	if err != nil {
		panic(err)
	}

	return &dockerClient{cl: client}
}

func (dc *dockerClient) FindCgroupMountpoint(subsystem string) (string, error) {
	return cgroups.FindCgroupMountpoint(subsystem)
}

func (dc *dockerClient) InspectContainer(id string) (*docker.Container, error) {
	return dc.cl.InspectContainer(id)
}

func (dc *dockerClient) ListContainersAsMap() (map[string]docker.APIContainers, error) {
	containers := make(map[string]docker.APIContainers)

	containerList, err := dc.cl.ListContainers(docker.ListContainersOptions{})

	if err != nil {
		return nil, err
	}

	for _, cont := range containerList {
		shortID, _ := GetShortId(cont.ID)
		containers[shortID] = cont
	}
	containers["root"] = docker.APIContainers{ID: "/"}

	if len(containers) == 0 {
		return nil, errors.New("No docker container found")
	}

	return containers, nil
}

// isRunningSystemd returns true if the host was booted with systemd
//func isRunningSystemd() bool {
//	// todo
//	/*
//		fi, err := os.Lstat("/run/systemd/system")
//		if err != nil {
//			return false
//		}
//		return fi.IsDir()
//	*/
//	// for POC
//	return true
//}

func GetSubsystemPath(subsystem string, id string) (string, error) {
	groupPath, err := cgroups.FindCgroupMountpoint(subsystem)
	if err != nil {
		fmt.Printf("[WARNING] Could not find mount point for %s\n", subsystem)
		return "", err
	}
	if id != "/" {
		// create path to cgroup for given docker id
		groupPath = filepath.Join(groupPath, id)
	}

	return groupPath, nil
}

// GetStatsFromContainer returns docker containers stats: cgroups stats (cpu usage, memory usage, etc.) and network stats (tx_bytes, rx_bytes etc.)
// Notes: incoming container id has to be full-length to be able to inspect container
func (dc *dockerClient) GetStatsFromContainer(id string) (*wrapper.Statistics, error) {

	var (
		stats        = wrapper.NewStatistics()
		groupWrap    = wrapper.Cgroups2Stats // wrapper for cgroup name and interface for stats extraction
		err          error
		workingSet   uint64
		wrapperPaths map[string]string
	)
	container := &docker.Container{}

	var pid int
	if id != "/" {
		if !isFullLengthID(id) {
			return stats, fmt.Errorf("Container id %+v is not fully-length - cannot inspect container", id)
		}
		// inspect container based only on fully-length container id.
		container, err = dc.InspectContainer(id)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to get inspect container to get pid, err=%v", err)
			// only log error message and return stats (contains cgroups stats)
			return stats, nil
		}
		pid = container.State.Pid
		// fill cgroup paths for wrapper elements according to parsed cgroup file
		wrapperPaths, _ = parseProcCgroupFile(pid)

	} else {
		wrapperPaths = map[string]string{}
		for cg, _ := range groupWrap {
			if _, err := GetSubsystemPath(cg, "/"); err != nil {
				continue
			} else {
				wrapperPaths[cg] = "/"
			}
		}
	}

	////FIXME:REMOVEIT\/
	//fmt.Fprintf(os.Stderr, "GSFC) cg paths for  %v are %+v \n", id, wrapperPaths)

	for cg, stat := range groupWrap {
		var err error
		var groupPath string
		var cgFound bool
		if groupPath, cgFound = wrapperPaths[cg]; !cgFound {
			continue
		} else {
			groupPath, err = GetSubsystemPath(cg, groupPath)
		}

		// get cgroup stats for given docker
		err = stat.GetStats(groupPath, stats.CgroupStats)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Cannot obtain cgroups statistics, err=", err)
			return nil, err
		}

	}

	// calculate additional stats memory:working_set based on memory_stats
	if totalInactiveAnon, ok := stats.CgroupStats.MemoryStats.Stats["total_inactive_anon"]; ok {
		workingSet = stats.CgroupStats.MemoryStats.Usage.Usage
		if workingSet < totalInactiveAnon {
			workingSet = 0
		} else {
			workingSet -= totalInactiveAnon
		}

		if totalInactiveFile, ok := stats.CgroupStats.MemoryStats.Stats["total_inactive_file"]; ok {
			if workingSet < totalInactiveFile {
				workingSet = 0
			} else {
				workingSet -= totalInactiveFile
			}
		}
	}
	stats.CgroupStats.MemoryStats.Stats["working_set"] = workingSet
	// gather memory limit
	if cgPath, gotMem := wrapperPaths["memory"]; gotMem {
		groupPath, _ := GetSubsystemPath("memory", cgPath)
		memLimit, _ := common.ReadUintFromFile(filepath.Join(groupPath, memLimitInBytesCounter), 64)
		memSwLimit, _ := common.ReadUintFromFile(filepath.Join(groupPath, memSwapLimitInBytesCounter), 64)
		stats.CgroupStats.MemoryStats.Stats[memLimitInBytesKey] = memLimit
		stats.CgroupStats.MemoryStats.Stats[memSwapLimitInBytesKey] = memSwLimit
	}

	if id != "/" {
		rootFs := "/"

		stats.Network, err = network.NetworkStatsFromProc(rootFs, pid)
		extractContainerLabels := func(container *docker.Container) map[string]string {
			res := map[string]string{}
			config := container.Config
			if config == nil {
				return res
			}
			for k, v := range config.Labels {
				res[ns.ReplaceNotAllowedCharsInNamespacePart(k)] = v
			}
			return res
		}
		stats.Labels = extractContainerLabels(container)

		if err != nil {
			// only log error message
			fmt.Fprintf(os.Stderr, "Unable to get network stats, containerID=%+v, pid %d: %v", container.ID, pid, err)
		}

		stats.Connection.Tcp, err = network.TcpStatsFromProc(rootFs, pid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to get tcp stats from pid %d: %v", pid, err)
		}

		stats.Connection.Tcp6, err = network.Tcp6StatsFromProc(rootFs, pid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to get tcp6 stats from pid %d: %v", pid, err)
		}

	} else {
		stats.Network, err = network.NetworkStatsFromRoot()
		if err != nil {
			// only log error message
			fmt.Fprintf(os.Stderr, "Unable to get network stats, containerID=%v, %v", id, err)
		}

	}

	stats.Filesystem, err = fs.GetFsStats(container)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to get filesystem stats for docker: %v, err=", id, err)
	}

	return stats, nil
}

// getShortId returns short version of container ID (12 char)
func GetShortId(dockerID string) (string, error) {
	// get short version of container ID
	if len(dockerID) < 12 {
		return "", fmt.Errorf("Docker id %+s is too short (the length of id should equal at least 12)", dockerID)
	}
	return dockerID[:12], nil
}

// isFullLengthID returns true if docker id is full-length (64 char)
func isFullLengthID(dockerID string) bool {
	if len(dockerID) == 64 {
		return true
	}
	return false
}

func getProcfsMount() string {
	if mount := os.Getenv(procfsMountEnv); mount != "" {
		return mount
	}
	return procfsMountDef
}

func parseProcCgroupFile(pid int) (map[string]string, error) {
	cgroupPath := filepath.Join(getProcfsMount(), strconv.Itoa(pid), "cgroup")
	data, err := ioutil.ReadFile(cgroupPath)
	res := map[string]string{}
	if err != nil {
		return res, err
	}
	reader := strings.NewReader(string(data))
	scanner := bufio.NewScanner(reader)
	scanner.Split(bufio.ScanLines)
	getCgWrappersInLine := func(line string) (groups []string, found bool) {
		groups = []string {}
		found = false
		for cgroup, _ := range wrapper.Cgroups2Stats {
			if strings.Index(","+ line +",", ","+ cgroup +",") >= 0 {
				groups = append(groups, cgroup)
				found = true
			}
		}
		if !found {
			return nil, false
		}
		return groups, true
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		if groups, found := getCgWrappersInLine(fields[1]); !found {
			continue
		} else {
			for _, cgroup := range groups {
				res[cgroup] = fields[2]
			}
		}
	}
	return res, nil
}
