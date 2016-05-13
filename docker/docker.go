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
	"fmt"
	"strings"
	"github.com/intelsdi-x/snap/core"
	"os"
	"time"
	"errors"
	"github.com/intelsdi-x/snap-plugin-collector-docker/client"
	"github.com/intelsdi-x/snap-plugin-utilities/ns"
	"github.com/intelsdi-x/snap/control/plugin"
	"github.com/intelsdi-x/snap/control/plugin/cpolicy"

	dock "github.com/fsouza/go-dockerclient"
)

const (
	// namespace vendor prefix
	NS_VENDOR = "intel"
	// namespace plugin name
	NS_PLUGIN = "docker"
	// version of plugin
	VERSION = 4
)



type containerData struct {
	Id         string  	`json:"-"`
	Status     string  	`json:"status"`
	Created    int64   	`json:"creation_time"`
	Image      string  	`json:"image_name"`
	SizeRw     int64   	`json:"size_rw"`
	SizeRootFs int64   	`json:"size_root_fs"`    // basic info about the container (status, uptime, etc.)
	Stats      *dock.Stats 	`json:"stats"`		// container statistics (cpu usage, memory usage, network stats, etc.)
}

// docker collector plugin type
type docker struct {
	containers  	map[string]containerData 	// holds data for a container under its short id
	initialized 	bool
	client      	client.DockerClientInterface 	// client for communication with docker (basic info, stats, mount points)
	list		map[string]dock.APIContainers	// contain list of all available docker containers with info about their specification


}

// Docker plugin initializer
func New() *docker {
	return &docker{
		containers:  map[string]containerData{},
		client: client.NewDockerClient(),
		list: map[string]dock.APIContainers{},
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
func (d *docker) validateDockerID(dockerID string) (bool) {

	if _, exist := d.list[dockerID]; exist {
		return true
	}

	return false
}

// validateMetricNamespace returns true if the given metric namespace has the required length
func validateMetricNamespace(ns []string) (bool) {

	if len(ns) < 4 {
		// metric namespace has to contain the following 4 elements:
		// "intel", "docker", "<docker_id>", "<metric_name>"
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
			idsOfAllContainers := d.availableContainers()
			if len(idsOfAllContainers) == 0 {
				return nil, errors.New("No docker container found")
			}
			return idsOfAllContainers, nil
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
	metrics := []plugin.MetricType{}
	var err error

	// get list of all running containers
	d.list, err = d.client.ListContainersAsMap()
	if err != nil {
		fmt.Fprintln(os.Stderr, "The list of running containers cannot be retrived, err=%+v", err)
		return nil, err
	}

	// retrieve requested docker ids
	rids, err := d.getRequestedIDs(mts...)
	if err != nil {
		return nil, err
	}

	// for each requested id set adequate item into docker.container struct with stats
	for _, rid := range rids {

		if contSpec, exist := d.list[rid]; exist {
			// set new item to docker.container structure
			d.containers[rid] = containerData{
				Id:         contSpec.ID,
				Status:     contSpec.Status,
				Created:    contSpec.Created,
				Image:      contSpec.Image,
				SizeRw:     contSpec.SizeRw,
				SizeRootFs: contSpec.SizeRootFs,
				Stats:      new(dock.Stats),
			}

		} else {
			return nil, fmt.Errorf("Docker container does not exist, container_id=", rid)
		}


		stats, err := d.client.GetContainerStats(rid, 0)
		if err != nil {
			return nil, err
		}
		*d.containers[rid].Stats = *stats
	}


	for _, mt := range mts {

		ids, err := d.getRequestedIDs(mt)
		if err != nil {
			return nil, err
		}

		for _, id := range ids {
			metricName := mt.Namespace().Strings()[3:]
			// Extract values by namespace from temporary struct and create metrics

				metric := plugin.MetricType{
					Timestamp_: time.Now(),
					Namespace_: core.NewNamespace(NS_VENDOR, NS_PLUGIN, id).AddStaticElements(metricName...),
					Data_:      ns.GetValueByNamespace(d.containers[id], metricName),
					Tags_: 		mt.Tags(),
					Config_: mt.Config(),
				}
				metrics = append(metrics, metric)
		}

	}

	if len(metrics) == 0 {
		return nil, errors.New("No metric found")
	}

	return metrics, nil
}

func (d *docker) GetMetricTypes(_ plugin.ConfigType) ([]plugin.MetricType, error) {
	//var namespaces []string
	var metricTypes []plugin.MetricType

	//d.init()

	// try to list all running containers to check docker client conn
	if _, err := d.client.ListContainersAsMap(); err != nil {
		fmt.Fprintln(os.Stderr, "The list of running containers cannot be retrived, err=%+v", err)
		return nil, err
	}

	// Generate available namespace for data container structure

	//prefix := strings.Join([]string{NS_VENDOR, NS_VENDOR, "*"}, "/")

	availableMetrics := []string{}
	// take names of available metrics based on tags for containerData type; do not add prefix (empty string)
	ns.FromCompositionTags(containerData{Stats: new(dock.Stats)}, "", &availableMetrics)

	fmt.Fprintln(os.Stderr, "Debug, len(namespaces1)=", len(availableMetrics))
	for index, ns := range availableMetrics {
		fmt.Fprintln(os.Stderr, "Debug, ns[", index, "]=",ns)
	}

	for _, metricName := range availableMetrics {

		ns := core.NewNamespace(NS_VENDOR, NS_PLUGIN).
			AddDynamicElement("docker_id", "the id of docker container").
			AddStaticElements(strings.Split(metricName, "/")...)

		metricType := plugin.MetricType{
			Namespace_: ns,
		}

		metricTypes = append(metricTypes, metricType)
	}

	/*
	//test, _ := d.client.ListContainersAsMap()
	data := containerData{id:"aa", created: 1543}
	ns.FromCompositionTags(data, prefix, &namespaces)
	fmt.Fprintln(os.Stderr, "Debug, len(namespaces)=", len(namespaces))
	for nr, ns := range namespaces {
		fmt.Fprintln(os.Stderr, "Debug, iza ns[", nr, "]=", ns)
	}
*/
	/*
	// list of metrics
	for _, statName := range availableStats {

		ns := core.NewNamespace(NS_VENDOR, NS_PLUGIN).
			AddDynamicElement("docker_id", "id of docker container").
			AddStaticElements(statName...)

		metricType := plugin.MetricType{
			Namespace_: ns,
		}

		metricTypes = append(metricTypes, metricType)
	}*/


	return metricTypes, nil

	/*


		for _, cont := range containers {
			//todo obsługa błedu
			dockerShortID, _ := getShortId(cont.Id)

			d.containers[dockerShortID] = containerData{
				id: 		cont.Id,
				status: 	cont.Status,
				created: 	cont.Created,
				image: 		cont.Image,
				sizeRw: 	cont.SizeRw,
				sizeRootFs: 	cont.SizeRootFs,
				stats: 		new(dock.Stats),
			}


			fmt.Fprint(os.Stderr, " Debug, container id=", cont.Id)
			fmt.Fprint(os.Stderr, " Debug, container data=", d.containers[cont.Id])
		}

		//todo do przerzucenia później


		cl, err := dock.NewClient(endpoint)
		if err != nil {
			fmt.Println("[ERROR] Could not create docker client!")
			return nil, err
		}

		errChan := make(chan error, 1)
		statsChan := make(chan *dock.Stats)
		done := make(chan bool)

		id := containers[0].Id
		go func() {
			//todo container id tymczasowo
			errChan <- cl.Stats(dock.StatsOptions{id, statsChan, true, done, 0})
			close(errChan)
		}()

		for {
			stats, ok := <-statsChan

			if !ok {
				break
			}

			//set stats

			fmt.Fprintf(os.Stderr, "Debug, izaPRZED zebrane statystyki memory: %+s", stats.MemoryStats)
			fmt.Fprintf(os.Stderr, "/n/n")
			fmt.Fprintf(os.Stderr, "Debug, izaPRZED zebrane statystyki cpu: %+s", stats.CPUStats)

			*d.containers[id].stats = *stats
			fmt.Fprintf(os.Stderr, "stats=", stats)
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintf(os.Stderr, "Debug, iza zebrane statystyki memory: %+s", d.containers[id].stats.MemoryStats)
			fmt.Fprintf(os.Stderr, "/n/n")
			fmt.Fprintf(os.Stderr, "Debug, iza zebrane statystyki cpu: %+s", d.containers[id].stats.CPUStats)
			//todo iza tymczasowo
			//resultStats = append(resultStats, stats)
		}
		err = <-errChan
		if err != nil {
			return nil, err
		}

	*/

	/*		//todo czy to jest potyrzebne
	// list all running containers
	_, err := dockerClient.ListContainers()

	if err != nil {
		return nil, err
	}

	for _, container := range d.containersInfo {
		// calling getStats will populate stats object
		// parsing it one will get info on available namespace
		d.getStats(container.Id)

		// marshal-unmarshal to get map with json tags as keys
		jsondata, _ := json.Marshal(d.stats)
		var jmap map[string]interface{}
		json.Unmarshal(jsondata, &jmap)

		// parse map to get namespace strings
		d.tools.Map2Namespace(jmap, container.Id[:12], &namespaces)
	}

	// wildcard for container ID
	if len(d.containersInfo) > 0 {
		jsondata, _ := json.Marshal(d.stats)
		var jmap map[string]interface{}
		json.Unmarshal(jsondata, &jmap)
		d.tools.Map2Namespace(jmap, "*", &namespaces)
	}

	for _, namespace := range namespaces {
		// construct full namespace
		fullNs := filepath.Join(NS_VENDOR, NS_PLUGIN, namespace)
		metricTypes = append(metricTypes, plugin.MetricType{Namespace_: core.NewNamespace(strings.Split(fullNs, "/")...)})
	}
	*/

	return metricTypes, nil
}

func (d *docker) GetConfigPolicy() (*cpolicy.ConfigPolicy, error) {
	return cpolicy.New(), nil
}
