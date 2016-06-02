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

package wrapper

import (
	"github.com/intelsdi-x/kubesnap-opencontainers/libcontainer/cgroups"
	"github.com/intelsdi-x/kubesnap-opencontainers/libcontainer/cgroups/fs"
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
	Network     []NetworkInterface   `json:"network"`
	Connection  TcpInterface         `json:"connection"` //TCP, TCP6 connection stats
	CgroupStats *cgroups.Stats       `json:"cgroups"`
	Labels      map[string]string    `json:"labels"`
	Filesystem  *FilesystemInterface `json:"filesystem"`
}

type NetworkInterface struct {
	// Name is the name of the network interface.
	Name string `json:"name"`

	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxErrors  uint64 `json:"tx_errors"`
	TxDropped uint64 `json:"tx_dropped"`
}

type FilesystemInterface struct {
	// The block device name associated with the filesystem.
	Device string `json:"device_name"`

	// Type of the filesystem.
	Type string `json:"type"`

	// Number of bytes that can be consumed by the container on this filesystem.
	Limit uint64 `json:"capacity"`

	// Number of bytes that is consumed by the container on this filesystem.
	Usage uint64 `json:"usage"`

	// Base Usage that is consumed by the container's writable layer.
	BaseUsage uint64 `json:"base_usage"`

	// Number of bytes available for non-root user.
	Available uint64 `json:"available"`

	// Number of available Inodes
	InodesFree uint64 `json:"inodes_free"`

	// This is the total number of reads completed successfully.
	ReadsCompleted uint64 `json:"reads_completed"`

	// This is the total number of reads merged successfully. This field lets you know how often this was done.
	ReadsMerged uint64 `json:"reads_merged"`

	// This is the total number of sectors read successfully.
	SectorsRead uint64 `json:"sectors_read"`

	// This is the total number of milliseconds spent reading
	ReadTime uint64 `json:"read_time"`

	// This is the total number of writes completed successfully.
	WritesCompleted uint64 `json:"writes_completed"`

	// This is the total number of writes merged successfully. This field lets you know how often this was done.
	WritesMerged uint64 `json:"writes_merged"`

	// This is the total number of sectors written successfully.
	SectorsWritten uint64 `json:"sectors_written"`

	// This is the total number of milliseconds spent writing
	WriteTime uint64 `json:"write_time"`

	// Number of I/Os currently in progress
	IoInProgress uint64 `json:"io_in_progress"`

	// Number of milliseconds spent doing I/Os
	IoTime uint64 `json:"io_time"`

	// weighted number of milliseconds spent doing I/Os
	// This field is incremented at each I/O start, I/O completion, I/O
	// merge, or read of these stats by the number of I/Os in progress
	// (field 9) times the number of milliseconds spent doing I/O since the
	// last update of this field.  This can provide an easy measure of both
	// I/O completion time and the backlog that may be accumulating.
	WeightedIoTime uint64 `json:"weighted_io_time"`
}

func NewStatistics() *Statistics {
	return &Statistics{
		Network:     []NetworkInterface{},
		CgroupStats: cgroups.NewStats(),
		Connection: TcpInterface{
			Tcp:  TcpStat{},
			Tcp6: TcpStat{},
		},
		Labels:     map[string]string{},
		Filesystem: &FilesystemInterface{},
	}
}

type TcpInterface struct {
	Tcp  TcpStat `json:"tcp"`  // TCP connection stats (Established, Listen...)
	Tcp6 TcpStat `json:"tcp6"` // TCP6 connection stats (Established, Listen...)
}

type TcpStat struct {
	//Count of TCP connections in state "Established"
	Established uint64 `json:"established"`
	//Count of TCP connections in state "Syn_Sent"
	SynSent uint64 `json:"syn_sent"`
	//Count of TCP connections in state "Syn_Recv"
	SynRecv uint64 `json:"syn_recv"`
	//Count of TCP connections in state "Fin_Wait1"
	FinWait1 uint64 `json:"fin_wait1"`
	//Count of TCP connections in state "Fin_Wait2"
	FinWait2 uint64 `json:"fin_wait2"`
	//Count of TCP connections in state "Time_Wait
	TimeWait uint64 `json:"time_wait"`
	//Count of TCP connections in state "Close"
	Close uint64 `json:"close"`
	//Count of TCP connections in state "Close_Wait"
	CloseWait uint64 `json:"close_wait"`
	//Count of TCP connections in state "Listen_Ack"
	LastAck uint64 `json:"last_ack"`
	//Count of TCP connections in state "Listen"
	Listen uint64 `json:"listen"`
	//Count of TCP connections in state "Closing"
	Closing uint64 `json:"closing"`
}
