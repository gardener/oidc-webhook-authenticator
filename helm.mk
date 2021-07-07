HELM				?= helm3 # expected to be helm v3
HELM_CHART_DIR		?= helm/oidc-webhook-authenticator
HELM_NAMESPACE		?= oidc-webhook-authenticator-system
HELM_RELEASE_NAME	?= oidc-wh
HELM_OUTPUT_DIR		?= tmp

helm-clean: ## Clean up templated helm chart
	@rm -Rf $(HELM_OUTPUT_DIR)

helm-lint: ## Run helm lint against helm chart.
	@$(HELM) lint $(HELM_CHART_DIR)

helm-install: ## Run helm upgrade --install.
	$(HELM) upgrade --install $(HELM_RELEASE_NAME) --namespace $(HELM_NAMESPACE) $(HELM_CHART_DIR)

helm-uninstall: ## Run helm uninstall.
	$(HELM) uninstall --namespace $(HELM_NAMESPACE) $(HELM_RELEASE_NAME)

helm-package: ## Run helm package
	$(HELM) package --dependency-update $(HELM_CHART_DIR)

helm-template: helm-clean ## Run helm template
	@mkdir -p $(HELM_OUTPUT_DIR)
	@$(HELM) template $(HELM_RELEASE_NAME) $(HELM_CHART_DIR) --namespace $(HELM_NAMESPACE) --output-dir $(HELM_OUTPUT_DIR)

