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
	"time"
	"fmt"
	"path/filepath"
	"strings"
	"strconv"
	"bufio"


	"github.com/fsouza/go-dockerclient"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"os"

	"github.com/intelsdi-x/kubesnap-plugin-collector-docker/wrapper"
)

const endpoint string = "unix:///var/run/docker.sock"


type DockerClientInterface interface {
	ListContainersAsMap() (map[string]docker.APIContainers, error)
	GetContainerStats(string, time.Duration) (*docker.Stats, error)
	GetStatsFromContainer(string) (*wrapper.Statistics, error)
	InspectContainer(string) (*docker.Container, error)
	//FindCgroupMountpoint(string) (string, error)
}


type dockerClient struct{
	cl *docker.Client
}

func NewDockerClient() (*dockerClient) {
	client, err := docker.NewClient(endpoint)
	if err != nil {
		panic(err)
	}
	return &dockerClient{cl: client}
}
/*
func (dc *dockerClient) FindCgroupMountpoint(subsystem string) (string, error) {
	return cgroups.FindCgroupMountpoint(subsystem)
}
*/

// getShortId returns short version of container ID (12 char)
func GetShortId(dockerID string) (string, error) {
	// get short version of container ID
	if len(dockerID) < 12 {
		return "", fmt.Errorf("Docker id %+s is too short (the length of id should equal at least 12)", dockerID)
	}
	return dockerID[:12], nil
}

func (dc *dockerClient) ListContainersAsMap() (map[string]docker.APIContainers, error) {
	containers := make(map[string]docker.APIContainers)

	containerList, err := dc.cl.ListContainers(docker.ListContainersOptions{})

	if err != nil {
		return nil, err
	}

	fmt.Fprintln(os.Stderr, "The number of available containers: ", len(containerList))
	for _, cont := range containerList {
		fmt.Fprintln(os.Stderr, "Ej co jest")
		shortID, _ := GetShortId(cont.ID)
		containers[shortID] = cont
	}

	if len(containers) == 0 {
		return nil, errors.New("No docker container found")
	}


	return containers, nil
}

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


func (dc *dockerClient) FindCgroupMountpoint(subsystem string) (string, error) {

	return cgroups.FindCgroupMountpoint(subsystem)
}

// IsRunningSystemd checks whether the host was booted with systemd as its init
// system. This functions similarly to systemd's `sd_booted(3)`: internally, it
// checks whether /run/systemd/system/ exists and is a directory.
// http://www.freedesktop.org/software/systemd/man/sd_booted.html
func isRunningSystemd() bool {
return true
//	fi, err := os.Lstat("/run/systemd/system")
//	if err != nil {
//		return false
//	}
//	return fi.IsDir()
}


func GetSubsystemPath(subsystem string, id string) (string, error) {
	var groupPath string
	mountpoint, err := cgroups.FindCgroupMountpoint(subsystem)
	if err != nil {
		fmt.Printf("[WARNING] Could not find mount point for %s\n", subsystem)
		return "", err
	}

	if isRunningSystemd() {
		fmt.Fprintln(os.Stderr, "Tak uzywa systemd!!!")
		slice := "system.slice"
		// create path to cgroup for given docker id
		groupPath = filepath.Join(mountpoint, slice, "docker-"+id+".scope")
	} else {
		// create path to cgroup for given docker id
		groupPath = filepath.Join(mountpoint, "docker", id)
	}
	return groupPath, nil
}

// long id has to be given
func (dc *dockerClient) GetStatsFromContainer(id string) (*wrapper.Statistics, error) {

	var (
		stats = wrapper.NewStatistics()
		cgstats = cgroups.NewStats()
		err   error
		//stats = wrapper.Stats{}
		groupWrap = wrapper.Cgroups2Stats     // wrapper for cgroup name and interface for stats extraction
	)

	for cg, stat := range groupWrap {

		groupPath, err := GetSubsystemPath(cg, id)
		fmt.Fprintln(os.Stderr, "Debug, iza groupdath=", groupPath, "err=", err )
		//mp, err := d.client.FindCgroupMountpoint(cg)

		//if err != nil {
		//	fmt.Printf("[WARNING] Could not find mount point for %s\n", cg)
		//	continue
		//}

		// create path to cgroup for given docker id
		//groupPath := filepath.Join(mp, "docker", id)
		// get cgroup stats for given docker
		err = stat.GetStats(groupPath, stats.CgroupStats)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Iza- Nie znalazl stats")
			return nil, err
		}

		fmt.Fprintln(os.Stderr, "Iza- znalazl stats=", cgstats.CpuStats)
	}


	container, err := dc.InspectContainer(id)

	if err != nil {
		return nil, err
	}

	rootFs := "/"

	fmt.Fprintln(os.Stderr, "container.State.Pid=", container.State.Pid)

	pid := container.State.Pid
	stats.Network, err = networkStatsFromProc(rootFs, pid)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to get network stats from pid %d: %v", pid, err)
	}

	fmt.Fprintln(os.Stderr, "netStats len=", len(stats.Network))
	for _, netStat := range stats.Network {
		fmt.Fprintln(os.Stderr, "netStat name=" ,netStat.Name)
		fmt.Fprintln(os.Stderr, "netStat RxBytes=" , netStat.RxBytes)
		fmt.Fprintln(os.Stderr, "netStat TxBytes=" , netStat.TxBytes)
	}


	fmt.Fprintln(os.Stderr, "Iza- wylazl")
	return stats, nil
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

/*
func getNetworkInterfaceStats(iface.HostInterfaceName) {

}
*/

func (dc *dockerClient) InspectContainer(id string) (*docker.Container, error) {
	fmt.Fprintln(os.Stderr, "Debug, wlazl hurra")
	return dc.cl. InspectContainer(id)
}

/*
func isIgnoredDevice(ifName string) bool {
	for _, prefix := range ignoredDevicePrefixes {
		if strings.HasPrefix(strings.ToLower(ifName), prefix) {
			return true
		}
	}
	return false
}
*/

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

