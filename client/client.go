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

	"github.com/fsouza/go-dockerclient"
	"github.com/opencontainers/runc/libcontainer/cgroups"
)

const endpoint string = "unix:///var/run/docker.sock"


type DockerClientInterface interface {
	ListContainersAsMap() (map[string]docker.APIContainers, error)
	GetContainerStats(string, time.Duration) (*docker.Stats, error)
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

func (dc *dockerClient) FindCgroupMountpoint(subsystem string) (string, error) {
	return cgroups.FindCgroupMountpoint(subsystem)
}

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

	for _, cont := range containerList {
		shortID, _ := GetShortId(cont.ID)
		containers[shortID] = cont
	}

	if len(containers) == 0 {
		return nil, errors.New("No docker conatiner found")
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

