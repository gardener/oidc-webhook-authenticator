// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package suites

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/gardener/gardener/test/framework"
	"github.com/gardener/gardener/test/framework/config"
	"github.com/gardener/gardener/test/framework/reporter"

	_ "github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/test/integration/healthcheck"
	_ "github.com/gardener/oidc-webhook-authenticator/gardener-extension-shoot-oidc-service/test/integration/lifecycle"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// go test -timeout 1200s ./test/integration/suites/run_suite_test.go --kubecfg=PATH --project-namespace=PROJ-NAMESPACE --shoot-name=SHOOT_NAME
var (
	configFilePath = flag.String("config", "", "Specify the configuration file")
	esIndex        = flag.String("es-index", "gardener-testsuite", "Specify the elastic search index where the report should be ingested")
	reportFilePath = flag.String("report-file", "/tmp/shoot_res.json", "Specify the file to write the test results")
)

func TestMain(m *testing.M) {
	framework.RegisterShootFrameworkFlags()
	flag.Parse()

	if err := config.ParseConfigForFlags(*configFilePath, flag.CommandLine); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	RegisterFailHandler(Fail)

	AfterSuite(func() {
		framework.CommonAfterSuite()
	})

	os.Exit(m.Run())
}

func TestGardenerSuite(t *testing.T) {
	RunSpecsWithDefaultAndCustomReporters(t, "Shoot-oidc-service Test Suite", []Reporter{reporter.NewGardenerESReporter(*reportFilePath, *esIndex)})
}
