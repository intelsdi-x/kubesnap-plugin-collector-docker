// Provides Network Stats
package network

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/intelsdi-x/kubesnap-plugin-collector-docker/wrapper"
	"github.com/intelsdi-x/snap-plugin-utilities/ns"
)

const networkInterfacesDir = "/sys/class/net"

var networkMetrics = getListOfNetworkMetrics()

func getListOfNetworkMetrics() []string {
	metrics := []string{}
	ns.FromCompositionTags(wrapper.NetworkInterface{}, "", &metrics)
	return metrics
}

func NetworkStatsFromProc(rootFs string, pid int) (ifaceStats []wrapper.NetworkInterface, errout error) {

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

func NetworkStatsFromRoot() (ifaceStats []wrapper.NetworkInterface, _ error) {
	devNames, err := listRootNetworkDevices()
	if err != nil {
		return nil, err
	}
	ifaceStats = []wrapper.NetworkInterface{}
	for _, name := range devNames {
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

func listRootNetworkDevices() (devNames []string, _ error) {
	entries, err := ioutil.ReadDir(networkInterfacesDir)
	if err != nil {
		return nil, err
	}
	devNames = []string{}
	for _, e := range entries {
		if e.Mode()&os.ModeSymlink == os.ModeSymlink {
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

func interfaceStatsFromDir(ifaceName string) (*wrapper.NetworkInterface, error) {
	stats := wrapper.NetworkInterface{Name: ifaceName}
	statsValues := map[string]uint64{}
	for _, metric := range networkMetrics {
		if metric == "name" {
			continue
		}
		val, err := readUintFromFile(filepath.Join(networkInterfacesDir, ifaceName, "statistics", metric), 64)
		if err != nil {
			return nil, fmt.Errorf("couldn't read interface statistics %s/%s: %v", ifaceName, metric, err)
		}
		statsValues[metric] = val
	}
	SetIfaceStatsFromMap(&stats, statsValues)
	return &stats, nil
}

func SetIfaceStatsFromMap(stats *wrapper.NetworkInterface, values map[string]uint64) {
	stats.RxBytes = values["rx_bytes"]
	stats.RxErrors = values["rx_errors"]
	stats.RxPackets = values["rx_packets"]
	stats.RxDropped = values["rx_dropped"]
	stats.TxBytes = values["tx_bytes"]
	stats.TxErrors = values["tx_errors"]
	stats.TxPackets = values["tx_packets"]
	stats.TxDropped = values["tx_dropped"]
}

func SetMapFromIfaceStats(values map[string]uint64, stats *wrapper.NetworkInterface) {
	values["rx_bytes"] = stats.RxBytes
	values["rx_errors"] = stats.RxErrors
	values["rx_packets"] = stats.RxPackets
	values["rx_dropped"] = stats.RxDropped
	values["tx_bytes"] = stats.TxBytes
	values["tx_errors"] = stats.TxErrors
	values["tx_packets"] = stats.TxPackets
	values["tx_dropped"] = stats.TxDropped
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

func readUintFromFile(path string, bits int) (uint64, error) {
	if valb, err := ioutil.ReadFile(path); err != nil {
		return 0, err
	} else {
		var val uint64
		val, err = strconv.ParseUint(strings.TrimSpace(string(valb)), 10, bits)
		return val, err
	}
}
