#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${repo_root}/build"
output_dir=""
info_file=""

usage() {
  cat <<'EOF'
Usage: scripts/coverage-html.sh [options]

Generate an HTML coverage report from an existing build directory that already
contains gcov data files.

Options:
  --build-dir <dir>   Build directory to scan (default: build)
  --output-dir <dir>  HTML report directory (default: <build-dir>/coverage-html)
  --info-file <file>  Intermediate lcov info file (default: <build-dir>/coverage.info)
  -h, --help          Show help

Requirements:
  - lcov
  - genhtml
  - Existing .gcno and .gcda files under the build directory

Examples:
  scripts/coverage-html.sh
  scripts/coverage-html.sh --build-dir build-gcov
  scripts/coverage-html.sh --build-dir build --output-dir build/coverage
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --build-dir)
      shift
      if [ -z "${1:-}" ]; then
        echo "Option --build-dir requires an argument." >&2
        usage >&2
        exit 2
      fi
      build_dir="$1"
      ;;
    --output-dir)
      shift
      if [ -z "${1:-}" ]; then
        echo "Option --output-dir requires an argument." >&2
        usage >&2
        exit 2
      fi
      output_dir="$1"
      ;;
    --info-file)
      shift
      if [ -z "${1:-}" ]; then
        echo "Option --info-file requires an argument." >&2
        usage >&2
        exit 2
      fi
      info_file="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

case "${build_dir}" in
  /*) ;;
  *) build_dir="${repo_root}/${build_dir}" ;;
esac

if [ -z "${output_dir}" ]; then
  output_dir="${build_dir}/coverage-html"
fi
case "${output_dir}" in
  /*) ;;
  *) output_dir="${repo_root}/${output_dir}" ;;
esac

if [ -z "${info_file}" ]; then
  info_file="${build_dir}/coverage.info"
fi
case "${info_file}" in
  /*) ;;
  *) info_file="${repo_root}/${info_file}" ;;
esac

if ! command -v lcov >/dev/null 2>&1; then
  echo "lcov not found in PATH." >&2
  exit 2
fi

if ! command -v genhtml >/dev/null 2>&1; then
  echo "genhtml not found in PATH." >&2
  exit 2
fi

if [ ! -d "${build_dir}" ]; then
  echo "Build directory not found: ${build_dir}" >&2
  exit 2
fi

if ! find "${build_dir}" -name '*.gcno' -print -quit | grep -q .; then
  echo "No .gcno files found under ${build_dir}" >&2
  echo "Build with coverage instrumentation before generating the report." >&2
  exit 2
fi

if ! find "${build_dir}" -name '*.gcda' -print -quit | grep -q .; then
  echo "No .gcda files found under ${build_dir}" >&2
  echo "Run the coverage-instrumented tests before generating the report." >&2
  exit 2
fi

tmp_info="${info_file}.tmp"

rm -rf "${output_dir}"
rm -f "${info_file}" "${tmp_info}"
mkdir -p "${output_dir}"

lcov \
  --capture \
  --directory "${build_dir}" \
  --base-directory "${repo_root}" \
  --output-file "${info_file}"

lcov \
  --extract "${info_file}" "${repo_root}/*" \
  --output-file "${tmp_info}"

mv "${tmp_info}" "${info_file}"

genhtml \
  --prefix "${repo_root}" \
  --output-directory "${output_dir}" \
  --title "Coverage Report" \
  "${info_file}"

echo "HTML coverage report generated:"
echo "  ${output_dir}/index.html"
