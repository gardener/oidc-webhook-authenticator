# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

HELM				?= helm
HELM_CHART_DIR		?= charts/oidc-webhook-authenticator
HELM_NAMESPACE		?= oidc-webhook-authenticator
HELM_RELEASE_NAME	?= oidc-webhook-authenticator
HELM_OUTPUT_DIR		?= helm-templates

helm-clean: ## Clean up templated helm chart
	@rm -rf $(HELM_OUTPUT_DIR)

helm-lint: ## Run helm lint against helm chart.
	@$(HELM) lint $(HELM_CHART_DIR)

helm-install: ## Run helm upgrade --install.
	$(HELM) upgrade --install $(HELM_RELEASE_NAME) --namespace $(HELM_NAMESPACE) $(HELM_CHART_DIR)

helm-uninstall: ## Run helm uninstall.
	$(HELM) uninstall --namespace $(HELM_NAMESPACE) $(HELM_RELEASE_NAME)

helm-template: helm-clean ## Run helm template
	@mkdir -p $(HELM_OUTPUT_DIR)
	@$(HELM) template $(HELM_RELEASE_NAME) $(HELM_CHART_DIR) --namespace $(HELM_NAMESPACE) --output-dir $(HELM_OUTPUT_DIR)
