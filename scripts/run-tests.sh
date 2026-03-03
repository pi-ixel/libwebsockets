#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="build"
destdir="${repo_root}/destdir"
ctest_jobs=2
ctest_filter=""

usage() {
  cat <<'EOF'
Usage: scripts/run-tests.sh [options]

Options:
  --build-dir <dir>   Existing build directory to test (default: build)
  --destdir <dir>     DESTDIR used for install before ctest (default: destdir)
  -t <n>              CTest parallel jobs (default: 2)
  -r <name>           Run a single test (ctest -R)
  -h, --help          Show help

Examples:
  scripts/run-tests.sh
  scripts/run-tests.sh --build-dir build-custom --destdir destdir-custom
  scripts/run-tests.sh -r ss-tf
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
    --destdir)
      shift
      if [ -z "${1:-}" ]; then
        echo "Option --destdir requires an argument." >&2
        usage >&2
        exit 2
      fi
      destdir="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -t)
      shift
      if [ -z "${1:-}" ]; then
        echo "Option -t requires an argument." >&2
        usage >&2
        exit 2
      fi
      ctest_jobs="$1"
      ;;
    -r)
      shift
      if [ -z "${1:-}" ]; then
        echo "Option -r requires an argument." >&2
        usage >&2
        exit 2
      fi
      ctest_filter="$1"
      ;;
    -t*)
      ctest_jobs="${1#-t}"
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

case "${destdir}" in
  /*) ;;
  *) destdir="${repo_root}/${destdir}" ;;
esac

if [ ! -d "${build_dir}" ]; then
  echo "Build directory not found: ${build_dir}" >&2
  echo "Run: scripts/build.sh [your build options]" >&2
  exit 2
fi

if [ ! -f "${build_dir}/cmake_install.cmake" ] ||
   [ ! -f "${build_dir}/CMakeFiles/libwebsockets-config.cmake" ] ||
   [ ! -f "${build_dir}/CMakeFiles/LwsCheckRequirements.cmake" ]; then
  echo "Build directory is missing install metadata: ${build_dir}" >&2
  echo "Run: scripts/build.sh [your build options]" >&2
  exit 2
fi

rm -rf "${destdir}"
DESTDIR="${destdir}" cmake --install "${build_dir}"

pushd "${build_dir}" >/dev/null
export LD_LIBRARY_PATH="${destdir}/usr/local/share/libwebsockets-test-server/plugins"
if [ -n "${ctest_filter}" ]; then
  ctest -j"${ctest_jobs}" -R "${ctest_filter}" --output-on-failure
else
  ctest -j"${ctest_jobs}" --output-on-failure
fi
popd >/dev/null
