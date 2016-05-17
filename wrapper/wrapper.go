// +build linux

/*
http://www.apache.org/licenses/LICENSE-2.0.txt


Copyright 2015 Intel Corporation

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

package wrapper

import (
	//"io/ioutil"
	//"path/filepath"
	//"strconv"
	//"strings"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs"
)

var Cgroups2Stats = map[string]Stats{
	"cpuset":     &fs.CpusetGroup{},
	"cpu":        &fs.CpuGroup{},
	"cpuacct":    &fs.CpuacctGroup{},
	"memory":     &fs.MemoryGroup{},
	"devices":    &fs.DevicesGroup{},
	"freezer":    &fs.FreezerGroup{},
	"net_cls":    &fs.NetClsGroup{},
	"blkio":      &fs.BlkioGroup{},
	"perf_event": &fs.PerfEventGroup{},
	"net_prio":   &fs.NetPrioGroup{},
	"hugetlb":    &fs.HugetlbGroup{},
}


type Stats interface {
	GetStats(path string, stats *cgroups.Stats) error
}


type Statistics struct {
	Network  map[string]NetworkInterface `json:"network"`
	CgroupStats *cgroups.Stats 	     `json:"cgroups"`
}


type NetworkInterface struct {
	// Name is the name of the network interface.
	Name string		`json:"-"`

	RxBytes   uint64	`json:"rx_bytes"`
	RxPackets uint64	`json:"rx_packets"`
	RxErrors  uint64	`json:"rx_errors"`
	RxDropped uint64	`json:"rx_dropped"`
	TxBytes   uint64	`json:"tx_bytes"`
	TxPackets uint64	`json:"tx_packets"`
	TxErrors  uint64	`json:"tx_errors"`
	TxDropped uint64	`json:"tx_dropped"`
}


func NewStatistics() *Statistics {

	return &Statistics{ Network: map[string]NetworkInterface{}, CgroupStats: cgroups.NewStats()}
}


/*
// Returns the network statistics for the network interfaces represented by the NetworkRuntimeInfo.
func getNetworkInterfaceStats(interfaceName string) (NetworkInterface, error) {
	out := &NetworkInterface{Name: interfaceName}
	// This can happen if the network runtime information is missing - possible if the
	// container was created by an old version of libcontainer.
	if interfaceName == "" {
		return out, nil
	}
	type netStatsPair struct {
		// Where to write the output.
		Out *uint64
		// The network stats file to read.
		File string
	}
	// Ingress for host veth is from the container. Hence tx_bytes stat on the host veth is actually number of bytes received by the container.
	netStats := []netStatsPair{
		{Out: &out.RxBytes, File: "tx_bytes"},
		{Out: &out.RxPackets, File: "tx_packets"},
		{Out: &out.RxErrors, File: "tx_errors"},
		{Out: &out.RxDropped, File: "tx_dropped"},

		{Out: &out.TxBytes, File: "rx_bytes"},
		{Out: &out.TxPackets, File: "rx_packets"},
		{Out: &out.TxErrors, File: "rx_errors"},
		{Out: &out.TxDropped, File: "rx_dropped"},
	}
	for _, netStat := range netStats {
		data, err := readSysfsNetworkStats(interfaceName, netStat.File)
		if err != nil {
			return nil, err
		}
		*(netStat.Out) = data
	}
	return out, nil
}

// Reads the specified statistics available under /sys/class/net/<EthInterface>/statistics
func readSysfsNetworkStats(ethInterface, statsFile string) (uint64, error) {
	data, err := ioutil.ReadFile(filepath.Join("/sys/class/net", ethInterface, "statistics", statsFile))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}
*/