/*
Copyright (c) Advanced Micro Devices, Inc. All rights reserved.

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

package e2e

/*
Copyright (c) Advanced Micro Devices, Inc. All rights reserved.

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

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/stretchr/testify/assert"
	. "gopkg.in/check.v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ROCm/network-operator/api/v1alpha1"
	utils "github.com/ROCm/network-operator/internal"
)

const (
	releaseName              = "amd-network-operator"
	defaultNetworkConfigName = "test-networkconfig"
	defaultNetworkConfig     = `../config/yamls/networkconfig.yaml`

	maxRetries = 20
	retryDelay = 5 * time.Second
)

func (s *E2ESuite) installHelmChart(c *C, expectErr bool, extraArgs []string) {
	helmChartPath, ok := os.LookupEnv("NETWORK_OPERATOR_CHART")
	if !ok {
		c.Fatalf("failed to get helm chart path from env NETWORK_OPERATOR_CHART")
	}
	args := []string{"install", releaseName, "-n", s.ns, helmChartPath}
	args = append(args, extraArgs...)
	cmd := exec.Command("helm", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	logger.Infof("Running command %+v", cmd.String())
	if err := cmd.Run(); err != nil && !expectErr {
		c.Fatalf("failed to install helm chart err %+v %+v", err, stderr.String())
	}
}

func (s *E2ESuite) uninstallHelmChart(c *C, expectErr bool, extraArgs []string) {
	args := []string{"delete", releaseName, "-n", s.ns}
	args = append(args, extraArgs...)
	cmd := exec.Command("helm", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	logger.Infof("Running command %+v", cmd.String())
	if err := cmd.Run(); err != nil && !expectErr {
		c.Fatalf("failed to uninstall helm chart err %+v %+v", err, stderr.String())
	}
}

func (s *E2ESuite) upgradeHelmChart(c *C, expectErr bool, extraArgs []string) {
	helmChartPath, ok := os.LookupEnv("NETWORK_OPERATOR_CHART")
	if !ok {
		c.Fatalf("failed to get helm chart path from env NETWORK_OPERATOR_CHART")
	}
	args := []string{"upgrade", releaseName, "-n", s.ns, helmChartPath}
	args = append(args, extraArgs...)
	cmd := exec.Command("helm", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	logger.Infof("Running command %+v", cmd.String())
	if err := cmd.Run(); err != nil && !expectErr {
		c.Fatalf("failed to upgrade helm chart err %+v %+v", err, stderr.String())
	}
}

func (s *E2ESuite) verifyNetworkConfig(c *C, testName string, expect bool,
	expectSpec *v1alpha1.NetworkConfigSpec,
	verifyFunc func(expect, actual *v1alpha1.NetworkConfigSpec) bool) {
	netCfgList, err := s.dClient.NetworkConfigs(s.ns).List(v1.ListOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		assert.NoError(c, err, fmt.Sprintf("test %v error listing NetworkConfig", testName))
	}
	if !expect && err != nil {
		// default CR was removed and even CRD was removed
		return
	}
	if !expect && err == nil && netCfgList != nil && len(netCfgList.Items) == 0 {
		// default CR was removed but CRD was not removed yet
		return
	}
	if expect && err == nil && netCfgList != nil {
		// make sure only one default CR exists
		assert.True(c, len(netCfgList.Items) == 1,
			"test %v expect only one default NetworkConfig but got %+v %+v",
			testName, len(netCfgList.Items), netCfgList.Items)
		// verify metadata
		assert.True(c, netCfgList.Items[0].Name == defaultNetworkConfigName,
			"test %v expect default NetworkConfig name to be %v but got %v",
			testName, defaultNetworkConfigName, netCfgList.Items[0].Name)
		assert.True(c, netCfgList.Items[0].Namespace == s.ns,
			"test %v expect default NetworkConfig namespace to be %v but got %v",
			testName, s.ns, netCfgList.Items[0].Namespace)
		// verify spec
		if expectSpec != nil && verifyFunc != nil {
			assert.True(c, verifyFunc(expectSpec, &netCfgList.Items[0].Spec),
				fmt.Sprintf("test %v expect %+v got %+v", testName, expectSpec, &netCfgList.Items[0].Spec))
		}
		return
	}
	c.Fatalf("test %v unexpected default CR, expect %+v list error %+v netCfgList %+v",
		testName, expect, err, netCfgList)
}

func (s *E2ESuite) createCR(c *C, configYaml string) {
	args := []string{"apply", "-f", configYaml}
	cmd := exec.Command("kubectl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	logger.Infof("Running command %+v", cmd.String())
	if err := cmd.Run(); err != nil {
		c.Fatalf("failed to create CR err: %+v, %+v", err, stderr.String())
	}
}

func (s *E2ESuite) verifyPods(c *C) {
	if s.simEnable {
		// some of the operands run only when nicctl is there
		logger.Infof("simEnable is true, skipping pod verification")
		return
	}

	var stdout, stderr bytes.Buffer
	args := []string{"get", "pods", "-n", s.ns, "-l", fmt.Sprintf("%s=%s", utils.CRNameLabel, defaultNetworkConfigName), "-o", "jsonpath={range .items[*]}{.metadata.name} {.status.phase},{end}"}

	// check all the pods from the network config name
	for i := 0; i < maxRetries; i++ {
		cmd := exec.Command("kubectl", args...)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		logger.Infof("Running command %+v", cmd.String())
		if err := cmd.Run(); err != nil {
			c.Errorf("failed to get pods err: %+v, %+v", err, stderr.String())
		}
		podStatus := stdout.String()
		if podStatus == "" {
			c.Errorf("expect some pods to be created for network config %s but got none, retrying %d/%d after %v",
				defaultNetworkConfigName, i+1, maxRetries, retryDelay)
			time.Sleep(retryDelay)
		} else {
			logger.Infof("got pods for network config %s: %s", defaultNetworkConfigName, podStatus)
			break
		}
		if i == maxRetries-1 {
			// last retry and still no pods, fail the test
			c.Fatalf("expect some pods to be created for network config %s but got none", defaultNetworkConfigName)
		}
		stderr.Reset()
		stdout.Reset()
	}

	stderr.Reset()
	stdout.Reset()

	// check if any pod is not in Running status
	for i := 0; i < maxRetries; i++ {
		cmd := exec.Command("kubectl", append(args, "--field-selector=status.phase!=Running")...)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		logger.Infof("Running command %+v", cmd.String())
		if err := cmd.Run(); err != nil {
			c.Errorf("failed to get pods err: %+v, %+v", err, stderr.String())
		}
		podStatus := stdout.String()
		if podStatus != "" {
			c.Errorf("expect all pods in Running status but got %+v, retrying %d/%d after %v",
				podStatus, i+1, maxRetries, retryDelay)
			time.Sleep(retryDelay)
		} else {
			// all pods are in Running status
			logger.Infof("all pods are in Running status for network config %s", defaultNetworkConfigName)
			return
		}
		if i == maxRetries-1 {
			// last retry and still not all pods are in Running status, fail the test
			c.Fatalf("expect all pods in Running status but got %+v", podStatus)
		}
		stderr.Reset()
		stdout.Reset()
	}
}

// basic test: install network operator, create CR and verify the pods are runing, uninstall network operator and ensure CR is removed
func (s *E2ESuite) TestHelmInstallUnInstall(c *C) {
	s.installHelmChart(c, false, nil)
	// create CR
	s.createCR(c, defaultNetworkConfig)
	s.verifyNetworkConfig(c, "TestHelmInstallUnInstall", true, nil, nil)
	// wait for the pods/operands to get created
	logger.Infof("wait 30s for the operands to be created")
	time.Sleep(30 * time.Second)
	// verify that the pods are running for the CR
	s.verifyPods(c)
	// uninstall network operator
	s.uninstallHelmChart(c, false, nil)
	// verify CR was removed
	s.verifyNetworkConfig(c, "TestHelmInstallUnInstall", false, nil, nil)
}

// tests helm upgrade
func (s *E2ESuite) TestHelmUpgrade(c *C) {
	s.installHelmChart(c, false, []string{})
	s.verifyNetworkConfig(c, "TestHelmUpgrade", false, nil, nil)
	s.createCR(c, defaultNetworkConfig)
	s.verifyNetworkConfig(c, "TestHelmUpgrade", true, nil, nil)
	logger.Infof("wait 30s for the operands to be created")
	time.Sleep(30 * time.Second)
	s.verifyPods(c)
	s.upgradeHelmChart(c, false, nil)
	// verify that existing CR is not affected by upgrade
	s.verifyNetworkConfig(c, "TestHelmUpgrade", true, nil, nil)
	s.verifyPods(c)
	s.uninstallHelmChart(c, false, nil)
	// verify CR was removed
	s.verifyNetworkConfig(c, "TestHelmUpgrade", false, nil, nil)

	// install again to verify the flow works for 2nd time
	logger.Infof("installing helm chart again to verify the flow works for 2nd time")
	s.installHelmChart(c, false, nil)
	s.verifyNetworkConfig(c, "TestHelmUpgrade", false, nil, nil)
	s.createCR(c, defaultNetworkConfig)
	s.verifyNetworkConfig(c, "TestHelmUpgrade", true, nil, nil)
	logger.Infof("wait 30s for the operands to be created")
	time.Sleep(30 * time.Second)
	s.verifyPods(c)
	s.upgradeHelmChart(c, false, nil)
	s.verifyNetworkConfig(c, "TestHelmUpgrade", true, nil, nil)
	s.verifyPods(c)
	s.uninstallHelmChart(c, false, nil)
	s.verifyNetworkConfig(c, "TestHelmUpgrade", false, nil, nil)
}
