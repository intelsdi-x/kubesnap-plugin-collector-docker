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
	"io/ioutil"

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

var networkMetrics []string = []string {}

type dockerClient struct {
	cl *docker.Client
}

func NewDockerClient() *dockerClient {
	client, err := docker.NewClient(endpoint)
	if err != nil {
		panic(err)
	}
	sample := wrapper.NetworkInterface{}
	ns.FromCompositionTags(sample, "", &networkMetrics)
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
	var groupPath string
	mountpoint, err := cgroups.FindCgroupMountpoint(subsystem)
	if err != nil {
		fmt.Printf("[WARNING] Could not find mount point for %s\n", subsystem)
		return "", err
	}
	if id == "/" {
		groupPath = mountpoint
	//} else if isRunningSystemd() {
	//	fmt.Fprintln(os.Stderr, "Debug: create path to cgroup for given docker id base on systemd")
	//	slice := "system.slice"
	//	// create path to cgroup for given docker id
	//	groupPath = filepath.Join(mountpoint, slice, "docker-"+id+".scope")
	} else {
		// create path to cgroup for given docker id
		//groupPath = filepath.Join(mountpoint, "docker", id)
		groupPath = filepath.Join(mountpoint, id)
	}
	return groupPath, nil
}

// GetStatsFromContainer returns docker containers stats: cgroups stats (cpu usage, memory usage, etc.) and network stats (tx_bytes, rx_bytes etc.)
// Notes: incoming container id has to be full-length to be able to inspect container
func (dc *dockerClient) GetStatsFromContainer(id string) (*wrapper.Statistics, error) {
	var (
		stats = wrapper.NewStatistics()
		groupWrap = wrapper.Cgroups2Stats // wrapper for cgroup name and interface for stats extraction
		err error
		workingSet uint64
		wrapperPaths map[string]string
	)
	var container *docker.Container
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
		wrapperPaths = map[string]string {}
		for cg, _ := range groupWrap {
			if _, err := GetSubsystemPath(cg, "/"); err != nil {
				continue
			} else {
				wrapperPaths[cg] = "/"
			}
		}
	}
	////FIXME:REMOVEIT\/
	//fmt.Fprintf(os.Stderr, "cgroups for %s: %+v\n", id, wrapperPaths)
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

	if id != "/" {
		//if !isFullLengthID(id) {
		//	return stats, fmt.Errorf("Container id %+v is not fully-length - cannot inspect container", id)
		//}
		//// inspect container based only on fully-length container id.
		////container, err := dc.InspectContainer(id)
		//
		//if err != nil {
		//	fmt.Fprintf(os.Stderr, "Unable to get inspect container to get pid, err=%v", err)
		//	// only log error message and return stats (contains cgroups stats)
		//	return stats, nil
		//}

		rootFs := "/"

		stats.Network, err = networkStatsFromProc(rootFs, pid)
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
			fmt.Fprintf(os.Stderr, "Unable to get network stats, containerID=%+v, pid %d: %v", container.ID, pid, err)
		}

		stats.Connection.Tcp, err = tcpStatsFromProc(rootFs, pid, "net/tcp")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to get tcp stats from pid %d: %v", pid, err)
		}

		stats.Connection.Tcp6, err = tcpStatsFromProc(rootFs, pid, "net/tcp6")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to get tcp6 stats from pid %d: %v", pid, err)
		}
	} else {
		stats.Network, err = networkStatsFromRoot()
		if err != nil {
			// only log error message
			fmt.Fprintf(os.Stderr, "Unable to get network stats, containerID=%v, %v", id, err)
		}
	}

	return stats, nil
}

func tcpStatsFromProc(rootFs string, pid int, file string) (wrapper.TcpStat, error) {
	tcpStatsFile := filepath.Join(rootFs, "proc", strconv.Itoa(pid), file)

	tcpStats, err := scanTcpStats(tcpStatsFile)
	if err != nil {
		return tcpStats, fmt.Errorf("Cannot obtain tcp stats: %v", err)
	}

	return tcpStats, nil
}

func scanTcpStats(tcpStatsFile string) (wrapper.TcpStat, error) {

	var stats wrapper.TcpStat

	data, err := ioutil.ReadFile(tcpStatsFile)
	if err != nil {
		return stats, fmt.Errorf("Cannot open %s: %v", tcpStatsFile, err)
	}

	tcpStateMap := map[string]uint64{
		"01": 0, //ESTABLISHED
		"02": 0, //SYN_SENT
		"03": 0, //SYN_RECV
		"04": 0, //FIN_WAIT1
		"05": 0, //FIN_WAIT2
		"06": 0, //TIME_WAIT
		"07": 0, //CLOSE
		"08": 0, //CLOSE_WAIT
		"09": 0, //LAST_ACK
		"0A": 0, //LISTEN
		"0B": 0, //CLOSING
	}

	reader := strings.NewReader(string(data))
	scanner := bufio.NewScanner(reader)

	scanner.Split(bufio.ScanLines)

	// Discard header line
	if b := scanner.Scan(); !b {
		return stats, scanner.Err()
	}

	for scanner.Scan() {
		line := scanner.Text()

		state := strings.Fields(line)
		// TCP state is the 4th field.
		// Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt  uid timeout inode
		tcpState := state[3]
		_, ok := tcpStateMap[tcpState]
		if !ok {
			return stats, fmt.Errorf("invalid TCP stats line: %v", line)
		}
		tcpStateMap[tcpState]++
	}

	stats = wrapper.TcpStat{
		Established: tcpStateMap["01"],
		SynSent:     tcpStateMap["02"],
		SynRecv:     tcpStateMap["03"],
		FinWait1:    tcpStateMap["04"],
		FinWait2:    tcpStateMap["05"],
		TimeWait:    tcpStateMap["06"],
		Close:       tcpStateMap["07"],
		CloseWait:   tcpStateMap["08"],
		LastAck:     tcpStateMap["09"],
		Listen:      tcpStateMap["0A"],
		Closing:     tcpStateMap["0B"],
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

func networkStatsFromProc(rootFs string, pid int) (ifaceStats []wrapper.NetworkInterface, errout error) {

	netStatsFile := filepath.Join(rootFs, "proc", strconv.Itoa(pid), "/net/dev")
	var err error
	ifaceStats, err = scanInterfaceStats(netStatsFile)
	if err != nil {
		return nil, fmt.Errorf("couldn't read network stats: %v", err)
	}

	if len(ifaceStats) == 0 {
		return nil, errors.New("No network interface found")
	}

	return ifaceStats, nil
}

const networkInterfacesDir = "/sys/class/net"

func listRootNetworkDevices() (devNames []string, _ error) {
	entries, err := ioutil.ReadDir(networkInterfacesDir)
	if err != nil {
		return nil, err
	}
	devNames = []string {}
	for _, e := range entries {
		if e.Mode() & os.ModeSymlink == os.ModeSymlink {
			e, err = os.Stat(filepath.Join(networkInterfacesDir, e.Name()))
			if err != nil || !e.IsDir() {
				continue
			}
			devNames = append(devNames, e.Name())
		} else if e.IsDir() {
			devNames = append(devNames, e.Name())
		}
	}
	return devNames, nil
}

func networkStatsFromRoot() (ifaceStats []wrapper.NetworkInterface, _ error) {
	devNames, err := listRootNetworkDevices()
	if err != nil {
		return nil, err
	}
	ifaceStats = []wrapper.NetworkInterface {}
	for _, name := range(devNames) {
		if isIgnoredDevice(name) {
			continue
		}
		if stats, err := interfaceStatsFromDir(name); err != nil {
			return nil, err
		} else {
			ifaceStats = append(ifaceStats, *stats)
		}
	}
	return ifaceStats, nil
}

func interfaceStatsFromDir(ifaceName string) (*wrapper.NetworkInterface, error) {
	stats := wrapper.NetworkInterface{Name: ifaceName}
	statsValues := map[string]uint64 {}
	for _, metric := range networkMetrics {
		if metric == "name" {
			continue
		}
		valb, err := ioutil.ReadFile(filepath.Join(networkInterfacesDir, ifaceName, "statistics", metric))
		var val uint64
		if err == nil {
			val, err = strconv.ParseUint(strings.TrimSpace(string(valb)), 10, 64)
		}
		if err != nil {
			return nil, fmt.Errorf("couldn't read interface statistics %s/%s: %v", ifaceName, metric, err)
		}
		statsValues[metric] = val
	}
	setIfaceStatsFromMap(&stats, statsValues)
	return &stats, nil
}

func setIfaceStatsFromMap(stats *wrapper.NetworkInterface, values map[string]uint64) {
	stats.RxBytes = values["rx_bytes"]
	stats.RxErrors = values["rx_errors"]
	stats.RxPackets = values["rx_packets"]
	stats.RxDropped = values["rx_dropped"]
	stats.TxBytes = values["tx_bytes"]
	stats.TxErrors = values["tx_errors"]
	stats.TxPackets = values["tx_packets"]
	stats.TxDropped = values["tx_dropped"]
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

func parseProcCgroupFile(pid int) (map[string]string, error) {
	cgroupPath := filepath.Join("/proc", strconv.Itoa(pid), "cgroup")
	data, err := ioutil.ReadFile(cgroupPath)
	res := map[string]string {}
	if err != nil {
		return res, err
	}
	reader := strings.NewReader(string(data))
	scanner := bufio.NewScanner(reader)
	scanner.Split(bufio.ScanLines)
	getCgWrapperInString := func(source string) (group string, found bool) {
		for cgroup, _ := range wrapper.Cgroups2Stats {
			if strings.Index(source, cgroup) >=0 {
				return cgroup, true
			}
		}
		return "", false
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if _, found := getCgWrapperInString(line); !found {
			continue
		}
		fields := strings.Split(line, ":")
		if cgroup, found := getCgWrapperInString(fields[1]); !found {
			continue
		} else {
			res[cgroup] = fields[2]
		}
	}
	return res, nil
}
