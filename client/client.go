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
	"errors"
	//"time"
	"bufio"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	//"syscall"
	//"io/ioutil"

	"github.com/fsouza/go-dockerclient"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"os"

	"github.com/intelsdi-x/kubesnap-plugin-collector-docker/wrapper"
	"github.com/intelsdi-x/snap-plugin-utilities/ns"
)

const endpoint string = "unix:///var/run/docker.sock"

type storageDriver string

const (
	devicemapperStorageDriver storageDriver = "devicemapper"
	aufsStorageDriver         storageDriver = "aufs"
	overlayStorageDriver      storageDriver = "overlay"
	zfsStorageDriver          storageDriver = "zfs"
)

const (
	// The read write layers exist here.
	aufsRWLayer = "diff"
	// Path to the directory where docker stores log files if the json logging driver is enabled.
	pathToContainersDir = "containers"
)

type DockerClientInterface interface {
	ListContainersAsMap() (map[string]docker.APIContainers, error)
	//GetContainerStats(string, time.Duration) (*docker.Stats, error)
	GetStatsFromContainer(string) (*wrapper.Statistics, error)
	InspectContainer(string) (*docker.Container, error)
	FindCgroupMountpoint(string) (string, error)
}

type dockerClient struct {
	cl *docker.Client
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

	fmt.Fprintln(os.Stderr, "Debug: The number of available containers: ", len(containerList))
	for _, cont := range containerList {
		shortID, _ := GetShortId(cont.ID)
		containers[shortID] = cont
	}

	if len(containers) == 0 {
		return nil, errors.New("No docker container found")
	}

	return containers, nil
}

/*
func (dc *dockerClient) GetContainerStats(id string, timeout time.Duration) (*docker.Stats, error) {

	var resultStats *docker.Stats

	errChan := make(chan error, 1)
	statsChan := make(chan *docker.Stats)
	done := make(chan bool)

	go func() {
		errChan <- dc.cl.Stats(docker.StatsOptions{id, statsChan, true, done, timeout})
		close(errChan)
	}()
	select {
		case stats, ok  := <-statsChan:
		resultStats = stats
			if !ok {
				statsChan = nil
				break
			}

		case err := <-errChan:
			return nil, err
	}

	return resultStats, nil
}
*/

// isRunningSystemd returns true if the host was booted with systemd
func isRunningSystemd() bool {
	// todo
	/*
		fi, err := os.Lstat("/run/systemd/system")
		if err != nil {
			return false
		}
		return fi.IsDir()
	*/
	// for POC
	return true
}

func GetSubsystemPath(subsystem string, id string) (string, error) {
	var groupPath string
	mountpoint, err := cgroups.FindCgroupMountpoint(subsystem)
	if err != nil {
		fmt.Printf("[WARNING] Could not find mount point for %s\n", subsystem)
		return "", err
	}

	if isRunningSystemd() {
		fmt.Fprintln(os.Stderr, "Debug: create path to cgroup for given docker id base on systemd")
		slice := "system.slice"
		// create path to cgroup for given docker id
		groupPath = filepath.Join(mountpoint, slice, "docker-"+id+".scope")
	} else {
		// create path to cgroup for given docker id
		groupPath = filepath.Join(mountpoint, "docker", id)
	}
	return groupPath, nil
}

// GetStatsFromContainer returns docker containers stats: cgroups stats (cpu usage, memory usage, etc.) and network stats (tx_bytes, rx_bytes etc.)
// Notes: incoming container id has to be full-length to be able to inspect container
func (dc *dockerClient) GetStatsFromContainer(id string) (*wrapper.Statistics, error) {
	var (
		stats      = wrapper.NewStatistics()
		groupWrap  = wrapper.Cgroups2Stats // wrapper for cgroup name and interface for stats extraction
		err        error
		workingSet uint64
	)

	for cg, stat := range groupWrap {

		groupPath, err := GetSubsystemPath(cg, id)

		// get cgroup stats for given docker
		err = stat.GetStats(groupPath, stats.CgroupStats)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Cannot obtain cgroups statistics, err=", err)
			return nil, err
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
	}

	if !isFullLengthID(id) {
		return stats, fmt.Errorf("Container id %+v is not fully-length - cannot inspect container", id)
	}
	// inspect container based only on fully-length container id.
	container, err := dc.InspectContainer(id)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to get inspect container to get pid, err=%v", err)
		// only log error message and return stats (contains cgroups stats)
		return stats, nil
	}

	rootFs := "/"

	stats.Network, err = networkStatsFromProc(rootFs, container.State.Pid)

	extractContainerLabels := func(container *docker.Container) map[string]string {
		res := map[string]string {}
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
		fmt.Fprintf(os.Stderr, "Unable to get network stats, containerID=%+v, pid %d: %v", container.ID, container.State.Pid, err)
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

func networkStatsFromProc(rootFs string, pid int) (map[string]wrapper.NetworkInterface, error) {

	netStats := map[string]wrapper.NetworkInterface{}
	netStatsFile := filepath.Join(rootFs, "proc", strconv.Itoa(pid), "/net/dev")

	ifaceStats, err := scanInterfaceStats(netStatsFile)
	if err != nil {
		return nil, fmt.Errorf("couldn't read network stats: %v", err)
	}

	// return network stats as a map, where name of interface is a key
	for _, ifaceStat := range ifaceStats {
		netStats[ifaceStat.Name] = ifaceStat
	}

	if len(netStats) == 0 {
		return nil, errors.New("No network interface found")
	}

	return netStats, nil
}

func isIgnoredDevice(ifName string) bool {
	ignoredDevicePrefixes := []string{"lo", "veth", "docker"}
	for _, prefix := range ignoredDevicePrefixes {
		if strings.HasPrefix(strings.ToLower(ifName), prefix) {
			return true
		}
	}
	return false
}

func scanInterfaceStats(netStatsFile string) ([]wrapper.NetworkInterface, error) {
	file, err := os.Open(netStatsFile)
	if err != nil {
		return nil, fmt.Errorf("failure opening %s: %v", netStatsFile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Discard header lines
	for i := 0; i < 2; i++ {
		if b := scanner.Scan(); !b {
			return nil, scanner.Err()
		}
	}

	stats := []wrapper.NetworkInterface{}
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.Replace(line, ":", "", -1)

		fields := strings.Fields(line)
		// If the format of the  line is invalid then don't trust any of the stats
		// in this file.
		if len(fields) != 17 {
			return nil, fmt.Errorf("invalid interface stats line: %v", line)
		}

		devName := fields[0]

		if isIgnoredDevice(devName) {
			continue
		}

		i := wrapper.NetworkInterface{
			Name: devName,
		}

		statFields := append(fields[1:5], fields[9:13]...)
		statPointers := []*uint64{
			&i.RxBytes, &i.RxPackets, &i.RxErrors, &i.RxDropped,
			&i.TxBytes, &i.TxPackets, &i.TxErrors, &i.TxDropped,
		}

		err := setInterfaceStatValues(statFields, statPointers)
		if err != nil {
			return nil, fmt.Errorf("cannot parse interface stats (%v): %v", err, line)
		}

		stats = append(stats, i)
	}

	return stats, nil
}

func setInterfaceStatValues(fields []string, pointers []*uint64) error {
	for i, v := range fields {
		val, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return err
		}
		*pointers[i] = val
	}
	return nil
}
