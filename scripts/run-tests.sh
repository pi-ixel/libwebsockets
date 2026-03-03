#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="build"
jobs=""
ctest_jobs=2
no_internet=0
cmake_args=(-DLWS_WITH_MINIMAL_EXAMPLES=1)
tls_choice=""
do_build=0
config_requested=0
ctest_filter=""

if command -v getconf >/dev/null 2>&1; then
  jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
elif command -v sysctl >/dev/null 2>&1; then
  jobs="$(sysctl -n hw.ncpu 2>/dev/null || true)"
fi
if [ -z "${jobs}" ]; then
  jobs=4
fi

usage() {
  cat <<'EOF'
Usage: scripts/run-tests.sh [debug] [tls] [options]

TLS options (choose one):
  openssl | mbedtls | wolfssl | libressl | boringssl | awslc

Options:
  -t <n>              CTest parallel jobs (default: 2)
  -N, --no-internet   Disable internet-dependent tests
  -I, --internet      Enable internet-dependent tests (default)
  -b, --build          Configure and build before tests (cleans build dir)
  -r <name>           Run a single test (ctest -R)
  -h, --help          Show help

Examples:
  scripts/run-tests.sh
  scripts/run-tests.sh --build
  scripts/run-tests.sh debug --build
  scripts/run-tests.sh mbedtls --no-internet --build
  scripts/run-tests.sh -r ss-tf
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    debug)
      cmake_args+=("-DCMAKE_BUILD_TYPE=DEBUG")
      config_requested=1
      ;;
    openssl|mbedtls|wolfssl|libressl|boringssl|awslc)
      if [ -n "${tls_choice}" ] && [ "${tls_choice}" != "$1" ]; then
        echo "Only one TLS option is allowed: already set to '${tls_choice}'" >&2
        exit 2
      fi
      tls_choice="$1"
      config_requested=1
      ;;
    -N|--no-internet)
      no_internet=1
      config_requested=1
      ;;
    -I|--internet)
      no_internet=0
      ;;
    -b|--build)
      do_build=1
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

case "${tls_choice}" in
  "") ;; # default OpenSSL
  openssl) ;;
  mbedtls) cmake_args+=("-DLWS_WITH_MBEDTLS=1") ;;
  wolfssl) cmake_args+=("-DLWS_WITH_WOLFSSL=1") ;;
  libressl) cmake_args+=("-DLWS_WITH_LIBRESSL=1") ;;
  boringssl) cmake_args+=("-DLWS_WITH_BORINGSSL=1") ;;
  awslc) cmake_args+=("-DLWS_WITH_AWSLC=1") ;;
esac

if [ "${no_internet}" -eq 1 ]; then
  cmake_args+=(-DLWS_CTEST_INTERNET_AVAILABLE=0)
fi

if [ "${do_build}" -eq 0 ] && [ "${config_requested}" -eq 1 ]; then
  echo "Build options require --build." >&2
  exit 2
fi

if [ "${do_build}" -eq 1 ]; then
  rm -rf "${repo_root}/${build_dir}"
  if [ ${#cmake_args[@]} -gt 0 ]; then
    cmake -S "${repo_root}" -B "${repo_root}/${build_dir}" "${cmake_args[@]}"
  else
    cmake -S "${repo_root}" -B "${repo_root}/${build_dir}"
  fi
  cmake --build "${repo_root}/${build_dir}" -- -j"${jobs}"
else
  if [ ! -d "${repo_root}/${build_dir}" ]; then
    echo "Build directory not found: ${repo_root}/${build_dir}" >&2
    echo "Run: scripts/run-tests.sh --build" >&2
    exit 2
  fi
fi

destdir="${repo_root}/destdir"
rm -rf "${destdir}"
DESTDIR="${destdir}" cmake --install "${repo_root}/${build_dir}"

pushd "${repo_root}/${build_dir}" >/dev/null
export LD_LIBRARY_PATH="${destdir}/usr/local/share/libwebsockets-test-server/plugins"
if [ -n "${ctest_filter}" ]; then
  ctest -j"${ctest_jobs}" -R "${ctest_filter}" --output-on-failure
else
  ctest -j"${ctest_jobs}" --output-on-failure
fi
popd >/dev/null
