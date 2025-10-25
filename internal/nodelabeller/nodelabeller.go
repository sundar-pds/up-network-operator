/*
Copyright (c) 2025 Advanced Micro Devices, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the \"License\");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an \"AS IS\" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nodelabellerinternal

import (
	"os"
	"strconv"

	v1 "k8s.io/api/core/v1"

	protos "github.com/ROCm/common-infra-operator/pkg/protos"
	amdv1alpha1 "github.com/ROCm/network-operator/api/v1alpha1"
)

const (
	defaultNodeLabellerUbiImage = "docker.io/rocm/k8s-network-node-labeller:v1.0.0"
	defaultInitContainerImage   = "busybox:1.36"
	nodeLabellerSAName          = "amd-network-operator-node-labeller"
	NodeLabellerNameSuffix      = "node-labeller"
)

func GenerateCommonNodeLabellerSpec(nwConfig *amdv1alpha1.NetworkConfig) *protos.NodeLabellerSpec {
	var nlOut protos.NodeLabellerSpec
	specIn := &nwConfig.Spec.DevicePlugin
	simEnabled, _ := strconv.ParseBool(os.Getenv("SIM_ENABLE"))

	nlOut.Name = nwConfig.Name
	nlOut.Namespace = nwConfig.Namespace
	nlOut.Enable = specIn.EnableNodeLabeller
	nlOut.ServiceAccountName = nodeLabellerSAName
	nlOut.Tolerations = specIn.NodeLabellerTolerations
	nlOut.UpgradePolicy = (*protos.DaemonSetUpgradeSpec)(specIn.UpgradePolicy.DeepCopy())
	nlOut.Selector = nwConfig.Spec.Selector

	nlOut.InitContainers = make([]protos.InitContainerSpec, 1)
	nlOut.InitContainers[0].IsPrivileged = true
	nlOut.InitContainers[0].DefaultImage = defaultInitContainerImage
	nlOut.InitContainers[0].Image = nwConfig.Spec.CommonConfig.InitContainerImage
	if simEnabled {
		nlOut.InitContainers[0].Command = []string{}
	} else {
		nlOut.InitContainers[0].Command = []string{
			"sh", "-c",
			`while [ ! -d /sys/class/infiniband ] || 
			       [ ! -d /sys/class/infiniband_verbs ] || 
			       [ ! -d /sys/module/ionic/drivers ]; do 
		        echo "amd ionic driver is not loaded " 
			    sleep 2 
			done`,
		}
	}
	nlOut.InitContainers[0].VolumeMounts = []v1.VolumeMount{
		{
			Name:      "sys-volume",
			MountPath: "/sys",
		},
	}

	// We use Ubi based images for both vanilla k8s and openshift.
	nlOut.MainContainer.DefaultImage = defaultNodeLabellerUbiImage
	nlOut.MainContainer.DefaultUbiImage = defaultNodeLabellerUbiImage

	nlOut.MainContainer.Image = specIn.NodeLabellerImage
	nlOut.MainContainer.ImagePullPolicy = specIn.NodeLabellerImagePullPolicy
	nlOut.MainContainer.ImageRegistrySecret = specIn.ImageRegistrySecret
	nlOut.MainContainer.IsPrivileged = true

	/* GSMTODO
	blackListFileName := defaultBlacklistFileName
	if nl.isOpenShift {
		blackListFileName = openShiftBlacklistFileName
	}
	if nwConfig.Spec.Driver.Blacklist != nil && *nwConfig.Spec.Driver.Blacklist {
		// if users want to apply the blacklist, init container will add the amdnetwork to the blacklist
		initContainerCommand = []string{"sh", "-c", fmt.Sprintf("echo \"# added by network operator \nblacklist amdnetwork\" > /host-etc/modprobe.d/%v; while [ ! -d /host-sys/class/kfd ] || [ ! -d /host-sys/module/amdnetwork/drivers/ ]; do echo \"amdnetwork driver is not loaded \"; sleep 2 ;done", blackListFileName)}
	} else {
		// if users disabled the KMM driver, or disabled the blacklist
		// init container will remove any hanging amdnetwork blacklist entry from the list
		initContainerCommand = []string{"sh", "-c", fmt.Sprintf("rm -f /host-etc/modprobe.d/%v; while [ ! -d /host-sys/class/kfd ] || [ ! -d /host-sys/module/amdnetwork/drivers/ ]; do echo \"amdnetwork driver is not loaded \"; sleep 2 ;done", blackListFileName)}
	}
	*/

	hostPathDirectory := v1.HostPathDirectory
	hostPathFileOrCreate := v1.HostPathFileOrCreate
	hostPathDirectoryOrCreate := v1.HostPathDirectoryOrCreate

	nlOut.MainContainer.Envs = []v1.EnvVar{
		{
			Name: "DS_NODE_NAME",
			ValueFrom: &v1.EnvVarSource{
				FieldRef: &v1.ObjectFieldSelector{
					FieldPath: "spec.nodeName",
				},
			},
		},
	}
	simEnvvars := []v1.EnvVar{
		{
			Name:  "SIM_ENABLE",
			Value: "1",
		},
	}
	if simEnabled {
		nlOut.MainContainer.Envs = append(nlOut.MainContainer.Envs, simEnvvars...)
	}

	nlOut.MainContainer.VolumeMounts = []v1.VolumeMount{
		{
			Name:      "dev-volume",
			MountPath: "/dev",
		},
		{
			Name:      "sys-volume",
			MountPath: "/sys",
		},
		{
			Name:      "lib-modules",
			MountPath: "/lib/modules",
		},
	}
	nonSimMounts := []v1.VolumeMount{
		{
			Name:      "nicctl",
			MountPath: "/usr/sbin/nicctl",
		},
		{
			Name:      "opt-amd",
			MountPath: "/opt/amd",
		},
	}

	nlOut.Volumes = []v1.Volume{
		{
			Name: "dev-volume",
			VolumeSource: v1.VolumeSource{
				HostPath: &v1.HostPathVolumeSource{
					Path: "/dev",
					Type: &hostPathDirectory,
				},
			},
		},
		{
			Name: "sys-volume",
			VolumeSource: v1.VolumeSource{
				HostPath: &v1.HostPathVolumeSource{
					Path: "/sys",
					Type: &hostPathDirectory,
				},
			},
		},
		{
			Name: "lib-modules",
			VolumeSource: v1.VolumeSource{
				HostPath: &v1.HostPathVolumeSource{
					Path: "/lib/modules",
					Type: &hostPathDirectory,
				},
			},
		},
	}
	nonSimVolumes := []v1.Volume{
		{
			Name: "nicctl",
			VolumeSource: v1.VolumeSource{
				HostPath: &v1.HostPathVolumeSource{
					Path: "/usr/sbin/nicctl",
					Type: &hostPathFileOrCreate,
				},
			},
		},
		{
			Name: "opt-amd",
			VolumeSource: v1.VolumeSource{
				HostPath: &v1.HostPathVolumeSource{
					Path: "/opt/amd",
					Type: &hostPathDirectoryOrCreate,
				},
			},
		},
	}
	if !simEnabled {
		nlOut.MainContainer.VolumeMounts = append(nlOut.MainContainer.VolumeMounts, nonSimMounts...)
		nlOut.Volumes = append(nlOut.Volumes, nonSimVolumes...)
	}

	return &nlOut
}
