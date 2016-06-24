// Provides Filesystem Stats
package fs

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/pkg/mount"
	"github.com/fsouza/go-dockerclient"
	"github.com/intelsdi-x/kubesnap-plugin-collector-docker/wrapper"
	"github.com/intelsdi-x/kubesnap-plugin-collector-docker/mounts"
	zfs "github.com/mistifyio/go-zfs"
	"github.com/intelsdi-x/kubesnap-plugin-collector-docker/config"
)

const (
	LabelSystemRoot   = "root"
	LabelDockerImages = "docker-images"
	LabelRktImages    = "rkt-images"
)
const (
	devicemapperStorageDriver = "devicemapper"
	aufsStorageDriver         = "aufs"
	overlayStorageDriver      = "overlay"
	zfsStorageDriver          = "zfs"

	// The read write layers exist here.
	aufsRWLayer = "diff"
	// Path to the directory where docker stores log files if the json logging driver is enabled.
	pathToContainersDir = "containers"

	storageDir = "/var/lib/docker"

	userLayerFirstVersionMaj = 1
	userLayerFirstVersionMin = 10
	userLayerIdFile = "mount-id"
)

var Col collector

//var root, cont sync.Once

func init() {
	Col.DiskUsage = map[string]uint64{}
	Col.Mut = &sync.Mutex{}

	storagePaths := []string{
		"/var/lib/docker",
		"/var/lib/docker/aufs/diff",
		"/var/lib/docker/overlay",
		"/var/lib/docker/zfs",
		"/var/lib/docker/containers",
	}

	Col.worker(false, "root", storagePaths[0])
	Col.worker(true, "containers", storagePaths[1:]...)
	//for _, path := range storagePaths {
	//	fmt.Fprintf(os.Stderr, "Starting worker for %s\n", path)
	//	if path == "/var/lib/docker" {
	//		Col.worker(path, false)
	//	} else {
	//		Col.worker(path, true)
	//	}
	//}
}

type collector struct {
	Mut       *sync.Mutex
	DiskUsage map[string]uint64
}

func (c *collector) worker(forSubDirs bool, id string, paths ...string) {
	//fmt.Fprintf(os.Stderr, "WORKER %s, started \n", id)
	go func(forSubDirs bool, id string, paths ...string) {
		dirs := []string{}
		for _, p := range paths {
			if forSubDirs {
				subdirs, _ := ioutil.ReadDir(p)
				for _, sd := range subdirs {
					dirs = append(dirs, path.Join(p, sd.Name()))
				}
			} else {
				dirs = append(dirs, paths...)
			}
		}

		if len(dirs) > 0 {
			//fmt.Fprintf(os.Stderr, "WORKER %s, main loop started", id)
			for {
				for _, d := range dirs {
					size, err := diskUsage(d)
					if err != nil {
						fmt.Fprintf(os.Stderr, "WORKER %s, ERROR {%s} for %s\n", id, err, d)
						break
					}
					c.Mut.Lock()
					c.DiskUsage[d] = size
					c.Mut.Unlock()
					//fmt.Fprintf(os.Stderr, "WORKER %s, disk usge %s = %d\n", id, d, size)
				}
				time.Sleep(30 * time.Second)
			}
		} else {
			fmt.Fprintf(os.Stderr, "WORKER %s, ERROR no storage points to collect", id)
		}
	}(forSubDirs, id, paths...)
}

func diskUsage(dir string) (uint64, error) {
	out, _ := exec.Command("du", "-s", dir).Output()
	val := strings.Fields(string(out))[0]
	size, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		return 0, err
	}

	return size, nil
}

type partition struct {
	mountpoint string
	major      uint
	minor      uint
	fsType     string
	blockSize  uint
}

type RealFsInfo struct {
	// Map from block device path to partition information.
	partitions map[string]partition
	// Map from label to block device path.
	// Labels are intent-specific tags that are auto-detected.
	labels map[string]string

	dmsetup dmsetupClient
}

type Context struct {
	// docker root directory.
	Docker  DockerContext
	RktPath string
}

type DockerContext struct {
	Root         string
	Driver       string
	DriverStatus map[string]string
}

func GetFsStats(container *docker.Container) (map[string]wrapper.FilesystemInterface, error) {
	fmt.Fprintln(os.Stderr, "Debug, GetFsStats START")
	var (
		baseUsage           uint64
		logUsage            uint64
		rootFsStorageDir    = storageDir
		logsFilesStorageDir string
	)

	fsStats := map[string]wrapper.FilesystemInterface{}

	if container.ID != "" {
		getUserLayerId := func(storageDir, storageDriver, containerId string) (string, error) {
			dockerVersion := config.DockerVersion
			if dockerVersion[0] <= userLayerFirstVersionMaj && dockerVersion[1] < userLayerFirstVersionMin {
				return containerId, nil
			}
			switch storageDriver {
			case aufsStorageDriver:
				fallthrough
			case overlayStorageDriver:
				idFilePath := filepath.Join(storageDir, "image", storageDriver, "layerdb", "mounts", containerId, userLayerIdFile)
				idBytes, err := ioutil.ReadFile(idFilePath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to read id of user-layer for container  %v from under path  %v\n", containerId, idFilePath)
					return "", err
				}
				return string(idBytes), nil
			default:
				fmt.Fprintf(os.Stderr, "Unsupported storage driver; dont know how to determine id of user layer for container %v \n", containerId)
				return "", fmt.Errorf("Unsupported storage driver; dont know how to determine id of user layer for container %v \n", containerId)
			}
		}
		userLayerId, err := getUserLayerId(storageDir, container.Driver, container.ID)
		if err != nil {
			userLayerId = container.ID
		}

		switch container.Driver {
		case aufsStorageDriver:
			// `/var/lib/docker/aufs/diff/<docker_id>`
			rootFsStorageDir = filepath.Join(storageDir, string(aufsStorageDriver), aufsRWLayer, userLayerId)
		case overlayStorageDriver:
			rootFsStorageDir = filepath.Join(storageDir, string(overlayStorageDriver), userLayerId)
		default:
			return nil, fmt.Errorf("Filesystem stats for storage driver %+s have not been supported yet", container.Driver)
		}

		// Path to the directory where docker stores log files, metadata and configs
		// e.g. /var/lib/docker/container/<docker_id>
		logsFilesStorageDir = filepath.Join(storageDir, pathToContainersDir, container.ID)
	}

	//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 1 (new fs info) ...")
	fsInfo, err := NewFsInfo(container.Driver)
	//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 1 (new fs info) ...done, err=", err)
	if err != nil {
		return nil, err
	}

	//todo remove it
	//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 2 check os.Stat(", rootFsStorageDir, ")=", debug_err)

	if _, err := os.Stat(rootFsStorageDir); err == nil {

		//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 2.1 (GetDirFsDevice)...")
		deviceInfo, err := fsInfo.GetDirFsDevice(rootFsStorageDir)
		fmt.Fprintln(os.Stderr, "Debug, Iza - for id=%v", container.ID, ", deviceInfo = %v", deviceInfo)
		//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 2.1 (GetDirFsDevice)...done, err=", err)
		if err != nil {
			return nil, err
		}

		//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 2.2 (GetGlobalFsInfo)...")

		filesystems, err := fsInfo.GetGlobalFsInfo()
		//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 2.2 (GetGlobalFsInfo)...done")

		if err != nil {
			return nil, fmt.Errorf("Cannot get global filesystem info, err=", err)
		}

		//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 2.3 (range over fs.Device)...done")

		//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 2.4 (GetDirUsage)...")
		baseUsage, err = fsInfo.GetDirUsage(rootFsStorageDir, time.Second)
		//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 2.4 (GetDirUsage)...done")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot get usage for dir=`%s`, err=%s", rootFsStorageDir, err)
		}

		if _, err := os.Stat(logsFilesStorageDir); err == nil {
			//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 3 (GetDirUsage)...")
			logUsage, err = fsInfo.GetDirUsage(logsFilesStorageDir, time.Second)
			//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 3 (GetDirUsage)...done, err=", err)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot get usage for dir=`%s`, err=%s", logsFilesStorageDir, err)
			}

			baseUsage += logUsage
		}

		//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 2.3 (range over fs.Device)...")

		for _, fs := range filesystems {
			fmt.Fprintln(os.Stderr, "Debug - Iza, GetFsStats for id=%v", container.ID, " for fs.Device=%v", fs.Device)
			// todo change it, workaround to get fs metrics for host for all devices
			if container.ID == "" {
				fmt.Fprintln(os.Stderr, "Debug, Iza - use workaround")
				deviceInfo.Device = fs.Device
			}

			if fs.Device == deviceInfo.Device {
				//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 2.3.1 - fs device has been found!!")
				stats := wrapper.FilesystemInterface{
					Device:          fs.Device,
					Type:            fs.Type.String(),
					Available:       fs.Available,
					Limit:           fs.Capacity,
					Usage:           fs.Capacity - fs.Free,
					BaseUsage:       baseUsage,
					InodesFree:      fs.InodesFree,
					ReadsCompleted:  fs.DiskStats.ReadsCompleted,
					ReadsMerged:     fs.DiskStats.ReadsMerged,
					SectorsRead:     fs.DiskStats.SectorsRead,
					ReadTime:        fs.DiskStats.ReadTime,
					WritesCompleted: fs.DiskStats.WritesCompleted,
					WritesMerged:    fs.DiskStats.WritesMerged,
					SectorsWritten:  fs.DiskStats.SectorsWritten,
					WriteTime:       fs.DiskStats.WriteTime,
					IoInProgress:    fs.DiskStats.IoInProgress,
					IoTime:          fs.DiskStats.IoTime,
					WeightedIoTime:  fs.DiskStats.WeightedIoTime,
				}
				if devName := getDeviceName(fs.Device); len(devName) > 0 {
					fmt.Fprintln(os.Stderr, "Debug - Iza, Adding fs stats to map; fsStats[", devName, "]")
					fsStats[devName] = stats
				} else {
					fmt.Fprintf(os.Stderr, "Unknown device name")
					fsStats["unknown"] = stats
				}

			}
		}
	} else {
		fmt.Fprintln(os.Stderr, "Os.Stat failed: %v; no fs stats will be available for container %v", err, container.ID)
	}

	/*
		//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 4 (set base usage)...")
		fsStats.BaseUsage = baseUsage
		//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 4 (set base usage)...done")
		//filesystem total usage equals baseUsage+extraUsage(logs, configs, etc.)
		//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 5 (set extra usage)...")
		fsStats.Usage = baseUsage + extraUsage
		//fmt.Fprintln(os.Stderr, "Debug, GetFsStats, phase 5 (set extra usage)...done")

	*/
	//fmt.Fprintln(os.Stderr, "Debug, GetFsStats END")
	return fsStats, nil
}

func NewFsInfo(storageDriver string) (FsInfo, error) {
	mounts, err := mount.GetMounts()
	if err != nil {
		return nil, err
	}
	fsInfo := &RealFsInfo{
		partitions: make(map[string]partition, 0),
		labels:     make(map[string]string, 0),
		dmsetup:    &defaultDmsetupClient{},
	}

	fsInfo.addSystemRootLabel(mounts)
	//fsInfo.addDockerImagesLabel(context, mounts)

	//fsInfo.addRktImagesLabel(context, mounts)

	supportedFsType := map[string]bool{
		// all ext systems are checked through prefix.
		"btrfs": true,
		"xfs":   true,
		"zfs":   true,
	}
	for _, mount := range mounts {
		var Fstype string
		if !strings.HasPrefix(mount.Fstype, "ext") && !supportedFsType[mount.Fstype] {
			continue
		}
		// Avoid bind mounts.
		if _, ok := fsInfo.partitions[mount.Source]; ok {
			continue
		}
		if mount.Fstype == "zfs" {
			Fstype = mount.Fstype
		}
		fsInfo.partitions[mount.Source] = partition{
			fsType:     Fstype,
			mountpoint: mount.Mountpoint,
			major:      uint(mount.Major),
			minor:      uint(mount.Minor),
		}
	}

	return fsInfo, nil
}

// getDockerDeviceMapperInfo returns information about the devicemapper device and "partition" if
// docker is using devicemapper for its storage driver. If a loopback device is being used, don't
// return any information or error, as we want to report based on the actual partition where the
// loopback file resides, inside of the loopback file itself.
func (self *RealFsInfo) getDockerDeviceMapperInfo(context DockerContext) (string, *partition, error) {
	if context.Driver != DeviceMapper.String() {
		return "", nil, nil
	}

	dataLoopFile := context.DriverStatus["Data loop file"]
	if len(dataLoopFile) > 0 {
		return "", nil, nil
	}

	dev, major, minor, blockSize, err := dockerDMDevice(context.DriverStatus, self.dmsetup)
	if err != nil {
		return "", nil, err
	}

	return dev, &partition{
		fsType:    DeviceMapper.String(),
		major:     major,
		minor:     minor,
		blockSize: blockSize,
	}, nil
}

// addSystemRootLabel attempts to determine which device contains the mount for /.
func (self *RealFsInfo) addSystemRootLabel(mounts []*mount.Info) {
	for _, m := range mounts {
		if m.Mountpoint == "/" {
			self.partitions[m.Source] = partition{
				fsType:     m.Fstype,
				mountpoint: m.Mountpoint,
				major:      uint(m.Major),
				minor:      uint(m.Minor),
			}
			self.labels[LabelSystemRoot] = m.Source
			return
		}
	}
}

/*
// addDockerImagesLabel attempts to determine which device contains the mount for docker images.
func (self *RealFsInfo) addDockerImagesLabel(context Context, mounts []*mount.Info) {
	dockerDev, dockerPartition, err := self.getDockerDeviceMapperInfo(context.Docker)
	if err != nil {
		glog.Warningf("Could not get Docker devicemapper device: %v", err)
	}
	if len(dockerDev) > 0 && dockerPartition != nil {
		self.partitions[dockerDev] = *dockerPartition
		self.labels[LabelDockerImages] = dockerDev
	} else {
		self.updateContainerImagesPath(LabelDockerImages, mounts, getDockerImagePaths(context))
	}
}

func (self *RealFsInfo) addRktImagesLabel(context Context, mounts []*mount.Info) {
	if context.RktPath != "" {
		rktPath := context.RktPath
		rktImagesPaths := map[string]struct{}{
			"/": {},
		}
		for rktPath != "/" && rktPath != "." {
			rktImagesPaths[rktPath] = struct{}{}
			rktPath = filepath.Dir(rktPath)
		}
		self.updateContainerImagesPath(LabelRktImages, mounts, rktImagesPaths)
	}
}
*/

// Generate a list of possible mount points for docker image management from the docker root directory.
// Right now, we look for each type of supported graph driver directories, but we can do better by parsing
// some of the context from `docker info`.
func getDockerImagePaths(context Context) map[string]struct{} {
	dockerImagePaths := map[string]struct{}{
		"/": {},
	}

	// TODO(rjnagal): Detect docker root and graphdriver directories from docker info.
	dockerRoot := context.Docker.Root
	for _, dir := range []string{"devicemapper", "btrfs", "aufs", "overlay", "zfs"} {
		dockerImagePaths[path.Join(dockerRoot, dir)] = struct{}{}
	}
	for dockerRoot != "/" && dockerRoot != "." {
		dockerImagePaths[dockerRoot] = struct{}{}
		dockerRoot = filepath.Dir(dockerRoot)
	}
	return dockerImagePaths
}

// This method compares the mountpoints with possible container image mount points. If a match is found,
// the label is added to the partition.
func (self *RealFsInfo) updateContainerImagesPath(label string, mounts []*mount.Info, containerImagePaths map[string]struct{}) {
	var useMount *mount.Info
	for _, m := range mounts {
		if _, ok := containerImagePaths[m.Mountpoint]; ok {
			if useMount == nil || (len(useMount.Mountpoint) < len(m.Mountpoint)) {
				useMount = m
			}
		}
	}
	if useMount != nil {
		self.partitions[useMount.Source] = partition{
			fsType:     useMount.Fstype,
			mountpoint: useMount.Mountpoint,
			major:      uint(useMount.Major),
			minor:      uint(useMount.Minor),
		}
		self.labels[label] = useMount.Source
	}
}

func (self *RealFsInfo) GetDeviceForLabel(label string) (string, error) {
	dev, ok := self.labels[label]
	if !ok {
		return "", fmt.Errorf("non-existent label %q", label)
	}
	return dev, nil
}

func (self *RealFsInfo) GetLabelsForDevice(device string) ([]string, error) {
	labels := []string{}
	for label, dev := range self.labels {
		if dev == device {
			labels = append(labels, label)
		}
	}
	return labels, nil
}

func (self *RealFsInfo) GetMountpointForDevice(dev string) (string, error) {
	p, ok := self.partitions[dev]
	if !ok {
		return "", fmt.Errorf("no partition info for device %q", dev)
	}
	return p.mountpoint, nil
}

func (self *RealFsInfo) GetFsInfoForPath(mountSet map[string]struct{}) ([]Fs, error) {
	filesystems := make([]Fs, 0)
	deviceSet := make(map[string]struct{})

	diskStatsMap, err := getDiskStatsMap(filepath.Join(mounts.ProcfsMountPoint, "diskstats"))
	if err != nil {
		return nil, err
	}
	for device, partition := range self.partitions {
		_, hasMount := mountSet[partition.mountpoint]
		_, hasDevice := deviceSet[device]
		if mountSet == nil || (hasMount && !hasDevice) {
			var (
				err error
				fs  Fs
			)
			switch partition.fsType {
			case DeviceMapper.String():
				fs.Capacity, fs.Free, fs.Available, err = getDMStats(device, partition.blockSize)
				fs.Type = DeviceMapper
			case ZFS.String():
				fs.Capacity, fs.Free, fs.Available, err = getZfstats(device)
				fs.Type = ZFS
			default:
				fs.Capacity, fs.Free, fs.Available, fs.Inodes, fs.InodesFree, err = getVfsStats(partition.mountpoint)
				fs.Type = VFS
			}
			if err != nil {
				return nil, err
			} else {
				deviceSet[device] = struct{}{}
				fs.DeviceInfo = DeviceInfo{
					Device: device,
					Major:  uint(partition.major),
					Minor:  uint(partition.minor),
				}
				fmt.Fprintln(os.Stderr, "Debug, Iza in GetFsInfoForPath, for device=%v", device)
				fs.DiskStats = diskStatsMap[device]
				if _, exist := diskStatsMap[device];  !exist {
					fmt.Fprintln(os.Stderr, "Debug, Iza in GetFsInfoForPath, stats for device=%v", device, " NOT exist!")
				}
				filesystems = append(filesystems, fs)
			}
		}
	}

	fmt.Fprintln(os.Stderr, "Debug, Iza in GetFsInfoForPath, returned filesystems count=%v", len(filesystems))

	for _, fs:= range filesystems {
		fmt.Fprintln(os.Stderr, "Debug, Iza in GetFsInfoForPath, returned filesystem=%v", fs.Device)
	}

	return filesystems, nil
}

var partitionRegex = regexp.MustCompile(`^(?:(?:s|xv)d[a-z]+\d*|dm-\d+)$`)

func getDiskStatsMap(diskStatsFile string) (map[string]DiskStats, error) {
	fmt.Fprintln(os.Stderr, "Debug iza, getDiskStatsMap from file %v", diskStatsFile)
	diskStatsMap := make(map[string]DiskStats)
	file, err := os.Open(diskStatsFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Cannot collect filesystem statistics - file %s is not available", diskStatsFile)
			return diskStatsMap, nil
		}
		return nil, err
	}

	defer file.Close()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		words := strings.Fields(line)
		if !partitionRegex.MatchString(words[2]) {
			continue
		}
		// 8      50 sdd2 40 0 280 223 7 0 22 108 0 330 330
		deviceName := path.Join("/dev", words[2])
		wordLength := len(words)
		offset := 3
		var stats = make([]uint64, wordLength-offset)
		if len(stats) < 11 {
			return nil, fmt.Errorf("could not parse all 11 columns of %s", filepath.Join(mounts.ProcfsMountPoint, "diskstats"))
		}
		var error error
		for i := offset; i < wordLength; i++ {
			stats[i-offset], error = strconv.ParseUint(words[i], 10, 64)
			if error != nil {
				return nil, error
			}
		}
		diskStats := DiskStats{
			ReadsCompleted:  stats[0],
			ReadsMerged:     stats[1],
			SectorsRead:     stats[2],
			ReadTime:        stats[3],
			WritesCompleted: stats[4],
			WritesMerged:    stats[5],
			SectorsWritten:  stats[6],
			WriteTime:       stats[7],
			IoInProgress:    stats[8],
			IoTime:          stats[9],
			WeightedIoTime:  stats[10],
		}
		diskStatsMap[deviceName] = diskStats
	}

	//todo remove it
	for devName, stats := range diskStatsMap {
		fmt.Fprintln(os.Stderr, "Debug, Iza - devName=%v", devName, "; stats=%v", stats)
	}

	return diskStatsMap, nil
}

func (self *RealFsInfo) GetGlobalFsInfo() ([]Fs, error) {
	return self.GetFsInfoForPath(nil)
}

func major(devNumber uint64) uint {
	return uint((devNumber >> 8) & 0xfff)
}

func minor(devNumber uint64) uint {
	return uint((devNumber & 0xff) | ((devNumber >> 12) & 0xfff00))
}

func (self *RealFsInfo) GetDirFsDevice(dir string) (*DeviceInfo, error) {
	buf := new(syscall.Stat_t)
	err := syscall.Stat(dir, buf)

	if err != nil {
		return nil, fmt.Errorf("stat failed on %s with error: %s", dir, err)
	}
	major := major(buf.Dev)
	minor := minor(buf.Dev)
	for device, partition := range self.partitions {
		if partition.major == major && partition.minor == minor {
			return &DeviceInfo{device, major, minor}, nil
		}
	}
	return nil, fmt.Errorf("could not find device with major: %d, minor: %d in cached partitions map", major, minor)
}

func (self *RealFsInfo) GetDirUsage(dir string, timeout time.Duration) (uint64, error) {
	//fmt.Fprintf(os.Stderr, "DEBUG, GetDirUsage(%s)\n", dir)
	Col.Mut.Lock()
	size, ok := Col.DiskUsage[dir]
	Col.Mut.Unlock()
	if !ok {
		return 0, fmt.Errorf("Disk usage not found for %s", dir)
	}
	//fmt.Fprintf(os.Stderr, "DEBUG, GetDirUsage(%s)=%d\n", dir, size)
	return size * 1024, nil
}

func getVfsStats(path string) (total uint64, free uint64, avail uint64, inodes uint64, inodesFree uint64, err error) {
	var s syscall.Statfs_t
	if err = syscall.Statfs(path, &s); err != nil {
		return 0, 0, 0, 0, 0, err
	}
	total = uint64(s.Frsize) * s.Blocks
	free = uint64(s.Frsize) * s.Bfree
	avail = uint64(s.Frsize) * s.Bavail
	inodes = uint64(s.Files)
	inodesFree = uint64(s.Ffree)
	return total, free, avail, inodes, inodesFree, nil
}

// dmsetupClient knows to to interact with dmsetup to retrieve information about devicemapper.
type dmsetupClient interface {
	table(poolName string) ([]byte, error)
	//TODO add status(poolName string) ([]byte, error) and use it in getDMStats so we can unit test
}

// defaultDmsetupClient implements the standard behavior for interacting with dmsetup.
type defaultDmsetupClient struct{}

var _ dmsetupClient = &defaultDmsetupClient{}

func (*defaultDmsetupClient) table(poolName string) ([]byte, error) {
	return exec.Command("dmsetup", "table", poolName).Output()
}

// Devicemapper thin provisioning is detailed at
// https://www.kernel.org/doc/Documentation/device-mapper/thin-provisioning.txt
func dockerDMDevice(driverStatus map[string]string, dmsetup dmsetupClient) (string, uint, uint, uint, error) {
	poolName, ok := driverStatus["Pool Name"]
	if !ok || len(poolName) == 0 {
		return "", 0, 0, 0, fmt.Errorf("Could not get dm pool name")
	}

	out, err := dmsetup.table(poolName)
	if err != nil {
		return "", 0, 0, 0, err
	}

	major, minor, dataBlkSize, err := parseDMTable(string(out))
	if err != nil {
		return "", 0, 0, 0, err
	}

	return poolName, major, minor, dataBlkSize, nil
}

func parseDMTable(dmTable string) (uint, uint, uint, error) {
	dmTable = strings.Replace(dmTable, ":", " ", -1)
	dmFields := strings.Fields(dmTable)

	if len(dmFields) < 8 {
		return 0, 0, 0, fmt.Errorf("Invalid dmsetup status output: %s", dmTable)
	}

	major, err := strconv.ParseUint(dmFields[5], 10, 32)
	if err != nil {
		return 0, 0, 0, err
	}
	minor, err := strconv.ParseUint(dmFields[6], 10, 32)
	if err != nil {
		return 0, 0, 0, err
	}
	dataBlkSize, err := strconv.ParseUint(dmFields[7], 10, 32)
	if err != nil {
		return 0, 0, 0, err
	}

	return uint(major), uint(minor), uint(dataBlkSize), nil
}

func getDMStats(poolName string, dataBlkSize uint) (uint64, uint64, uint64, error) {
	out, err := exec.Command("dmsetup", "status", poolName).Output()
	if err != nil {
		return 0, 0, 0, err
	}

	used, total, err := parseDMStatus(string(out))
	if err != nil {
		return 0, 0, 0, err
	}

	used *= 512 * uint64(dataBlkSize)
	total *= 512 * uint64(dataBlkSize)
	free := total - used

	return total, free, free, nil
}

func parseDMStatus(dmStatus string) (uint64, uint64, error) {
	dmStatus = strings.Replace(dmStatus, "/", " ", -1)
	dmFields := strings.Fields(dmStatus)

	if len(dmFields) < 8 {
		return 0, 0, fmt.Errorf("Invalid dmsetup status output: %s", dmStatus)
	}

	used, err := strconv.ParseUint(dmFields[6], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	total, err := strconv.ParseUint(dmFields[7], 10, 64)
	if err != nil {
		return 0, 0, err
	}

	return used, total, nil
}

// getZfstats returns ZFS mount stats using zfsutils
func getZfstats(poolName string) (uint64, uint64, uint64, error) {
	dataset, err := zfs.GetDataset(poolName)
	if err != nil {
		return 0, 0, 0, err
	}

	total := dataset.Used + dataset.Avail + dataset.Usedbydataset

	return total, dataset.Avail, dataset.Avail, nil
}

func getDeviceName(device string) string {
	deviceNs := strings.Split(device, "/")
	return deviceNs[len(deviceNs)-1]
}
