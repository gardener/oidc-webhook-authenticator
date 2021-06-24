// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestKapiserver(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Kapiserver Webhook Suite")
}
