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
	Network     map[string]NetworkInterface `json:"network"`
	Connection  TcpInterface                `json:"connection"` //TCP, TCP6 connection stats
	CgroupStats *cgroups.Stats              `json:"cgroups"`
}

type NetworkInterface struct {
	// Name is the name of the network interface.
	Name string `json:"-"`

	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxErrors  uint64 `json:"tx_errors"`
	TxDropped uint64 `json:"tx_dropped"`
}

func NewStatistics() *Statistics {
	return &Statistics{Network: map[string]NetworkInterface{}, CgroupStats: cgroups.NewStats(), Connection: TcpInterface{}}
}

type TcpInterface struct {
	Tcp  TcpStat `json:"tcp"`  // TCP connection stats (Established, Listen...)
	Tcp6 TcpStat `json:"tcp6"` // TCP6 connection stats (Established, Listen...)
}

type TcpStat struct {
	//Count of TCP connections in state "Established"
	Established uint64
	//Count of TCP connections in state "Syn_Sent"
	SynSent uint64
	//Count of TCP connections in state "Syn_Recv"
	SynRecv uint64
	//Count of TCP connections in state "Fin_Wait1"
	FinWait1 uint64
	//Count of TCP connections in state "Fin_Wait2"
	FinWait2 uint64
	//Count of TCP connections in state "Time_Wait
	TimeWait uint64
	//Count of TCP connections in state "Close"
	Close uint64
	//Count of TCP connections in state "Close_Wait"
	CloseWait uint64
	//Count of TCP connections in state "Listen_Ack"
	LastAck uint64
	//Count of TCP connections in state "Listen"
	Listen uint64
	//Count of TCP connections in state "Closing"
	Closing uint64
}
