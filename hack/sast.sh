#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

root_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"

gosec_report="false"
gosec_report_parse_flags=""

parse_flags() {
  while test $# -gt 1; do
    case "$1" in
      --gosec-report)
        shift; gosec_report="$1"
        ;;
      *)
        echo "Unknown argument: $1"
        exit 1
        ;;
    esac
    shift
  done
}

parse_flags "$@"

echo "> Running gosec"
gosec --version
if [[ "$gosec_report" != "false" ]]; then
  echo "Exporting report to $root_dir/gosec-report.sarif"
  gosec_report_parse_flags="-track-suppressions -fmt=sarif -out=gosec-report.sarif -stdout"
fi

gosec  $gosec_report_parse_flags ./...
