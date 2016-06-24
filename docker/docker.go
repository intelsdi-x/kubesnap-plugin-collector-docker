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

package docker

import (
	"errors"
	"fmt"
	"github.com/intelsdi-x/kubesnap-plugin-collector-docker/client"
	"github.com/intelsdi-x/kubesnap-plugin-collector-docker/network"
	"github.com/intelsdi-x/snap-plugin-utilities/ns"
	"github.com/intelsdi-x/snap/control/plugin"
	"github.com/intelsdi-x/snap/control/plugin/cpolicy"
	"github.com/intelsdi-x/snap/core"
	"os"
	"strings"
	"time"

	"encoding/json"
	dock "github.com/fsouza/go-dockerclient"
	"github.com/intelsdi-x/kubesnap-plugin-collector-docker/wrapper"
	"runtime/debug"
)

const (
	// namespace vendor prefix
	NS_VENDOR = "intel"
	// namespace plugin name
	NS_PLUGIN = "docker"
	// version of plugin
	VERSION = 815
)

type containerData struct {
	Id         string              `json:"-"` // basic info about the container (status, uptime, etc.)
	Status     string              `json:"status"`
	Created    string              `json:"creation_time"`
	Image      string              `json:"image_name"`
	SizeRw     int64               `json:"size_rw"`
	SizeRootFs int64               `json:"size_root_fs"`
	Stats      *wrapper.Statistics `json:"-"` // container statistics (cpu usage, memory usage, network stats, etc.)
}

// docker collector plugin type
type docker struct {
	containers  map[string]containerData // holds data for a container under its short id
	initialized bool
	client      client.DockerClientInterface  // client for communication with docker (basic info, stats, mount points)
	list        map[string]dock.APIContainers // contain list of all available docker containers with info about their specification

}

// Docker plugin initializer
func New() *docker {
	return &docker{
		containers: map[string]containerData{},
		client:     client.NewDockerClient(),
		list:       map[string]dock.APIContainers{},
	}
}

// availableContainer returns IDs of all available docker containers
func (d *docker) availableContainers() []string {
	ids := []string{}

	// iterate over list of available dockers
	for id := range d.list {
		ids = append(ids, id)
	}

	return ids
}

// validateDockerID returns true if docker with a given dockerID has been found on list of available dockers
func (d *docker) validateDockerID(dockerID string) bool {

	if _, exist := d.list[dockerID]; exist {
		return true
	}

	return false
}

// validateMetricNamespace returns true if the given metric namespace has the required length
func validateMetricNamespace(ns []string) bool {

	if len(ns) < 5 {
		// metric namespace has to contain the following 5 elements:
		// "intel", "docker", "<docker_id>", "<metric_type: spec,cgroups or network>", "<metric_name>"
		return false
	}
	return true
}

// getRequestedIDs returns requested docker ids
func (d *docker) getRequestedIDs(mt ...plugin.MetricType) ([]string, error) {
	rids := []string{}
	for _, m := range mt {
		ns := m.Namespace().Strings()
		if ok := validateMetricNamespace(ns); !ok {
			return nil, fmt.Errorf("Invalid name of metric %+s", m.Namespace().String())
		}

		rid := m.Namespace().Strings()[2]
		if rid == "*" {
			// all available dockers are requested
			rids := d.availableContainers()
			//if len(idsOfAllContainers) == 0 {
			//	return nil, errors.New("No docker container found")
			//}
			rids = appendIfMissing(rids, "root")
			return rids, nil
		} else if rid == "root" {
			rids = appendIfMissing(rids, "root")
			continue
		}
		shortid, errId := client.GetShortId(rid)
		if errId != nil {
			return nil, errId
		}

		if !d.validateDockerID(shortid) {
			return nil, fmt.Errorf("Docker container %+s cannot be found", rid)
		}

		rids = appendIfMissing(rids, shortid)
	}

	if len(rids) == 0 {
		return nil, errors.New("Cannot retrieve requested docker id")
	}
	return rids, nil
}

func appendIfMissing(items []string, newItem string) []string {
	for _, item := range items {
		if newItem == item {
			// do not append new item
			return items
		}
	}
	return append(items, newItem)
}

func (d *docker) CollectMetrics(mts []plugin.MetricType) ([]plugin.MetricType, error) {
	//FIXME:REMOVEIT\/
	var lastStats interface{}
	var lastNs interface{}
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "CollectMetrics) defeated by error: %v\n", r)
			fmt.Fprintf(os.Stderr, "CollectMetrics) defeated at metric %v; error: %v\n", lastNs, r)
			strStats := fmt.Sprintf("%#v", lastStats)
			if jsonb, err := json.Marshal(lastStats); err == nil {
				strStats = string(jsonb)
			}
			fmt.Fprintf(os.Stderr, "CollectMetrics) last stats object: %v\n", strStats)
			debug.PrintStack()
			panic(r)
		}
	}()
	var err error
	metrics := []plugin.MetricType{}
	d.list = map[string]dock.APIContainers{}

	//get list of possible network metrics
	networkMetrics := []string{}
	ns.FromCompositionTags(wrapper.NetworkInterface{}, "", &networkMetrics)

	// get list of all running containers
	d.list, err = d.client.ListContainersAsMap()

	if err != nil {
		fmt.Fprintln(os.Stderr, "The list of running containers cannot be retrived, err=", err)
		return nil, err
	}

	// retrieve requested docker ids
	rids, err := d.getRequestedIDs(mts...)
	if err != nil {
		return nil, err
	}

	// for each requested id set adequate item into docker.container struct with stats
	for _, rid := range rids {

		if contSpec, exist := d.list[rid]; !exist {
			return nil, fmt.Errorf("Docker container does not exist, container_id=", rid)
		} else {
			stats, err := d.client.GetStatsFromContainer(contSpec.ID, true)
			if err != nil {
				return nil, err
			}

			// set new item to docker.container structure
			d.containers[rid] = containerData{
				Id:         contSpec.ID,
				Status:     contSpec.Status,
				Created:    time.Unix(contSpec.Created, 0).Format("2006-01-02T15:04:05Z07:00"),
				Image:      contSpec.Image,
				SizeRw:     contSpec.SizeRw,
				SizeRootFs: contSpec.SizeRootFs,
				Stats:      stats,
			}

		}
	}

	for _, mt := range mts {
		//FIXME:REMOVEIT\/
		lastNs = mt.Namespace()
		ids, err := d.getRequestedIDs(mt)
		if err != nil {
			return nil, err
		}

		for _, id := range ids {
			lastStats = d.containers[id].Stats
			//FIXME:REMOVEIT\/
			//fmt.Fprintf(os.Stderr, "Debug, CM_= collecting for id= %v, ns= %v\n", id, mt.Namespace())

			statsType := mt.Namespace().Strings()[3]
			metricName := mt.Namespace().Strings()[4:]

			// Extract values by namespace from temporary struct and create metrics

			switch statsType {
			case "spec": //get docker specification info
				metric := plugin.MetricType{
					Timestamp_: time.Now(),
					Namespace_: core.NewNamespace(NS_VENDOR, NS_PLUGIN, id).AddStaticElements(mt.Namespace().Strings()[3:]...),
					Data_:      ns.GetValueByNamespace(d.containers[id], metricName),
					Tags_:      mt.Tags(),
					Config_:    mt.Config(),
				}

				metrics = append(metrics, metric)

			case "filesystem": //get docker filesystem info
				devices := []string{}
				if metricName[0] == "*" {
					for deviceName := range d.containers[id].Stats.Filesystem {
						devices = append(devices, deviceName)
					}

				} else {
					devices = append(devices, metricName[0])
				}

				for _, device := range devices {
					metric := plugin.MetricType{
						Timestamp_: time.Now(),
						Namespace_: core.NewNamespace(NS_VENDOR, NS_PLUGIN, id, statsType, device).AddStaticElements(mt.Namespace().Strings()[5:]...),
						Data_:      ns.GetValueByNamespace(d.containers[id].Stats.Filesystem[device], metricName[1:]),
						Tags_:      mt.Tags(),
						Config_:    mt.Config(),
					}

					metrics = append(metrics, metric)
				}

			case "labels":
				labelKeys := []string{}
				if metricName[0] == "*" {
					for k, _ := range d.containers[id].Stats.Labels {
						labelKeys = append(labelKeys, k)
					}
				} else {
					labelKeys = append(labelKeys, metricName[0])
				}
				for _, labelName := range labelKeys {
					metric := plugin.MetricType{
						Timestamp_: time.Now(),
						Namespace_: core.NewNamespace(NS_VENDOR, NS_PLUGIN, id).AddStaticElements("labels", labelName, "value"),
						Data_:      d.containers[id].Stats.Labels[labelName],
						Tags_:      mt.Tags(),
						Config_:    mt.Config(),
					}

					metrics = append(metrics, metric)
				}

			case "cgroups": // get docker cgroups stats

				metric := plugin.MetricType{
					Timestamp_: time.Now(),
					Namespace_: core.NewNamespace(NS_VENDOR, NS_PLUGIN, id).AddStaticElements(mt.Namespace().Strings()[3:]...),
					Data_:      ns.GetValueByNamespace(d.containers[id].Stats.CgroupStats, metricName),
					Tags_:      mt.Tags(),
					Config_:    mt.Config(),
				}
				metrics = append(metrics, metric)

			case "connection": // get docker connection stats (tcp and tcp6)
				metric := plugin.MetricType{
					Timestamp_: time.Now(),
					Namespace_: core.NewNamespace(NS_VENDOR, NS_PLUGIN, id).AddStaticElements(mt.Namespace().Strings()[3:]...),
					Data_:      ns.GetValueByNamespace(d.containers[id].Stats.Connection, metricName),
					Tags_:      mt.Tags(),
					Config_:    mt.Config(),
				}
				metrics = append(metrics, metric)
			case "network": //get docker network information
				// support wildcard on interface name
				netInterfaces := []string{}
				ifaceMap := map[string]wrapper.NetworkInterface{}
				for _, iface := range d.containers[id].Stats.Network {
					ifaceMap[iface.Name] = iface
				}
				if metricName[0] == "*" {
					for _, netInterface := range d.containers[id].Stats.Network {
						netInterfaces = append(netInterfaces, netInterface.Name)
					}
				} else {
					netInterfaces = append(netInterfaces, metricName[0])
				}
				extractFirstIfaceStats := func(containerId string, containerStats *wrapper.Statistics) wrapper.NetworkInterface {
					addOtherStats := func(dest, other map[string]uint64) {
						for k, v := range other {
							if acc, ok := dest[k]; !ok {
								dest[k] = v
							} else {
								dest[k] = acc + v
							}
						}
						return
					}
					firstIface := wrapper.NetworkInterface{}
					//if containerId == "root" {
					summary := map[string]uint64{}
					for _, iface := range containerStats.Network {
						tmp := map[string]uint64{}
						network.SetMapFromIfaceStats(tmp, &iface)
						addOtherStats(summary, tmp)
					}
					network.SetIfaceStatsFromMap(&firstIface, summary)
					firstIface.Name = "total"
					//} else {
					//	if netStats := containerStats.Network; len(netStats) > 0 {
					//		firstIface = netStats[0]
					//	}
					//}
					return firstIface
				}
				firstIface := extractFirstIfaceStats(id, d.containers[id].Stats)
				if len(metricName) == 1 {
					// referring to most important interface only
					var metricElems []string
					if metricName[0] == "*" {
						metricElems = networkMetrics
					} else {
						metricElems = []string{metricName[0]}
					}
					for _, elemName := range metricElems {
						metric := plugin.MetricType{
							Timestamp_: time.Now(),
							Namespace_: core.NewNamespace(NS_VENDOR, NS_PLUGIN, id).
								AddStaticElements(statsType, elemName),
							Data_:   ns.GetValueByNamespace(firstIface, []string{elemName}),
							Tags_:   mt.Tags(),
							Config_: mt.Config(),
						}

						metrics = append(metrics, metric)
					}
				} else {
					for _, ifaceName := range netInterfaces {
						metric := plugin.MetricType{
							Timestamp_: time.Now(),
							Namespace_: core.NewNamespace(NS_VENDOR, NS_PLUGIN, id).
								AddStaticElements(statsType, ifaceName, metricName[1]),
							Data_:   ns.GetValueByNamespace(ifaceMap[ifaceName], metricName[1:]),
							Tags_:   mt.Tags(),
							Config_: mt.Config(),
						}

						metrics = append(metrics, metric)
					}
				}

			}

		}

	}

	if len(metrics) == 0 {
		return nil, errors.New("No metric found")
	}

	return metrics, nil
}

func (d *docker) GetMetricTypes(_ plugin.ConfigType) ([]plugin.MetricType, error) {
	defer func() {
		if r := recover(); r != nil {
			//fmt.Fprintf(os.Stderr, "GetMetricTypes) defeated by error: %v\n", r)
			debug.PrintStack()
			panic(r)
		}
	}()
	var metricTypes []plugin.MetricType
	stats := wrapper.NewStatistics()
	var err error

	//fmt.Fprintln(os.Stderr, "Debug, phase 1 - list containers as map...")
	// try to list all running containers to check docker client conn
	d.list, err = d.client.ListContainersAsMap()
	//fmt.Fprintln(os.Stderr, "Debug, phase 1 - list containers as map...done, err=", err)
	if err != nil {
		fmt.Fprintln(os.Stderr, "The list of running containers cannot be retrived, err=%+v", err)
		return nil, err
	}

	//fmt.Fprintln(os.Stderr, "Debug, phase 2 - get stats from host...")
	stats, err = d.client.GetStatsFromContainer("/", false)
	//fmt.Fprintln(os.Stderr, "Debug, phase 2 - get stats from host...done, err=", err)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot initialize stats structure from a root cgroup, err=", err)
		return nil, err
	}

	//fmt.Fprintln(os.Stderr, "Debug, phase 3 - set stats to containerData...")
	// set new item to docker.container structure
	data := containerData{
		Stats: stats,
	}
	//fmt.Fprintln(os.Stderr, "Debug, phase 3 - set stats to containerData...done")

	// Generate available namespace for data container structure

	specificationMetrics := []string{}
	cgroupsMetrics := []string{}
	networkMetrics := []string{}
	connectionMetrics := []string{}
	filesystemMetrics := []string{}

	//fmt.Fprintln(os.Stderr, "Debug, phase 4 - generate namespaces...")

	// take names of available metrics based on tags for containerData type; do not add prefix (empty string)
	ns.FromCompositionTags(data, "spec", &specificationMetrics)
	ns.FromCompositionTags(data.Stats.CgroupStats, "cgroups", &cgroupsMetrics)
	ns.FromCompositionTags(wrapper.NetworkInterface{}, "", &networkMetrics)
	ns.FromCompositionTags(data.Stats.Connection, "connection", &connectionMetrics)
	ns.FromCompositionTags(wrapper.FilesystemInterface{}, "", &filesystemMetrics)

	//fmt.Fprintln(os.Stderr, "Debug, phase 4.1 - generate namespaces...")
	for _, metricName := range specificationMetrics {
		ns := core.NewNamespace(NS_VENDOR, NS_PLUGIN).
			AddDynamicElement("docker_id", "an id of docker container").
			AddStaticElements(strings.Split(metricName, "/")...)

		metricType := plugin.MetricType{
			Namespace_: ns,
		}

		metricTypes = append(metricTypes, metricType)
	}
	//fmt.Fprintln(os.Stderr, "Debug, phase 4.2 - generate namespaces...")

	for _, metricName := range filesystemMetrics {
		ns := core.NewNamespace(NS_VENDOR, NS_PLUGIN).
			AddDynamicElement("docker_id", "an id of docker container").
			AddStaticElement("filesystem").
			AddDynamicElement("device_id", "an id of filesystem device").
			AddStaticElements(strings.Split(metricName, "/")...)

		metricType := plugin.MetricType{
			Namespace_: ns,
		}

		metricTypes = append(metricTypes, metricType)
	}
	//fmt.Fprintln(os.Stderr, "Debug, phase 4.3 - generate namespaces...")

	for _, metricName := range cgroupsMetrics {
		ns := core.NewNamespace(NS_VENDOR, NS_PLUGIN).
			AddDynamicElement("docker_id", "an id of docker container").
			AddStaticElements(strings.Split(metricName, "/")...)

		metricType := plugin.MetricType{
			Namespace_: ns,
		}

		metricTypes = append(metricTypes, metricType)
	}
	//fmt.Fprintln(os.Stderr, "Debug, phase 4.4 - generate namespaces...")

	metricType := plugin.MetricType{
		Namespace_: core.NewNamespace(NS_VENDOR, NS_PLUGIN).
			AddDynamicElement("docker_id", "an id of docker container").
			AddStaticElement("labels").
			AddDynamicElement("label", "name of a container label").
			AddStaticElement("value"),
	}

	metricTypes = append(metricTypes, metricType)

	//fmt.Fprintln(os.Stderr, "Debug, phase 4.5 - generate namespaces...")

	for _, metricName := range networkMetrics {
		ns := core.NewNamespace(NS_VENDOR, NS_PLUGIN).
			AddDynamicElement("docker_id", "an id of docker container").
			AddStaticElement("network").
			AddDynamicElement("network_interface", "a name of network interface").
			AddStaticElement(metricName)

		metricType := plugin.MetricType{
			Namespace_: ns,
		}

		metricTypes = append(metricTypes, metricType)

		ns = core.NewNamespace(NS_VENDOR, NS_PLUGIN).
			AddDynamicElement("docker_id", "an id of docker container").
			AddStaticElement("network").
			AddStaticElement(metricName)

		metricType = plugin.MetricType{
			Namespace_: ns,
		}

		metricTypes = append(metricTypes, metricType)
	}

	//fmt.Fprintln(os.Stderr, "Debug, phase 4.6 - generate namespaces...")

	for _, metricName := range connectionMetrics {

		ns := core.NewNamespace(NS_VENDOR, NS_PLUGIN).
			AddDynamicElement("docker_id", "an id of docker container").
			AddStaticElements(strings.Split(metricName, "/")...)

		metricType := plugin.MetricType{
			Namespace_: ns,
		}

		metricTypes = append(metricTypes, metricType)
	}

	//fmt.Fprintln(os.Stderr, "Debug, phase 4 - generate namespaces...done, len(metrics)=", len(metricTypes))

	return metricTypes, nil

}

func (d *docker) GetConfigPolicy() (*cpolicy.ConfigPolicy, error) {
	return cpolicy.New(), nil
}

// arbitraryContainerSpecification returns a docker specification info about an arbitrary container
func arbitraryContainerSpecification(containers map[string]dock.APIContainers) dock.APIContainers {
	for _, contSpec := range containers {
		return contSpec
	}
	return dock.APIContainers{}
}
