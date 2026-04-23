#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir=""
destdir_dir=""
jobs=""
cmake_args=()
tls_choice=""
profile="fulltests"
run_ctest=0
prefix=""

if command -v getconf >/dev/null 2>&1; then
  jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
elif command -v sysctl >/dev/null 2>&1; then
  jobs="$(sysctl -n hw.ncpu 2>/dev/null || true)"
fi
if [ -z "${jobs}" ]; then
  jobs=4
fi
jobs="${JOBS:-${jobs}}"

usage() {
  cat <<'EOF'
Usage: scripts/build.sh [debug] [asan] [tls] [profile] [run-tests] [--prefix <name>] [options]

TLS options (choose one, default: openssl):
  openssl | mbedtls | wolfssl | libressl | boringssl | awslc | openhitls

Build profile (choose one, default: fulltests):
  fulltests | minimal

Execution options:
  asan             Enable AddressSanitizer for build configuration
  gcov             Enable code coverage analysis
  run-tests        Install into DESTDIR and run ctest after building

Options:
  --prefix <name>  Use build-<name> and destdir-<name>
  -h, --help       Show help

Notes:
  This script owns configure/build decisions.
  The configure step is always refreshed so changed CMake options take effect.
  Default output directories are build and destdir.
  The openhitls minimal profile enables DTLS, JOSE, COSE, GENCRYPTO, and TLS_SESSIONS.
  Use scripts/run-tests.sh to install and run tests from an existing build directory.

Environment variables:
  BUILD_DIR              Override build directory
  DESTDIR_DIR            Override DESTDIR used by run-tests
  JOBS                   Override parallel build jobs
  OPENSSL_ROOT_DIR       OpenSSL installation prefix for CMake discovery
  OPENSSL_EXECUTABLE     OpenSSL executable used for cert generation
  LWS_OPENSSL_INCLUDE_DIRS  OpenSSL include dirs (semicolon-separated)
  LWS_OPENSSL_LIBRARIES     OpenSSL libraries (semicolon-separated)
  OPENHITLS_INCLUDE_DIRS  OpenHITLS include dirs (semicolon-separated)
  OPENHITLS_LIBRARIES     OpenHITLS libraries (semicolon-separated)

Examples:
  scripts/build.sh
  scripts/build.sh debug
  scripts/build.sh asan
  scripts/build.sh openssl
  scripts/build.sh debug asan mbedtls
  scripts/build.sh debug mbedtls
  scripts/build.sh openhitls fulltests asan
  scripts/build.sh openhitls fulltests asan --prefix hitls-asan
  scripts/build.sh --prefix hitls-asan openhitls fulltests asan
  BUILD_DIR=custom-build scripts/build.sh openhitls fulltests --prefix hitls
EOF
}

validate_prefix() {
  local value="$1"

  if [ -z "${value}" ] || [[ "${value}" == *"/"* ]] || [[ "${value}" == *".."* ]] || [[ "${value}" =~ [[:space:]] ]] || [[ ! "${value}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "Invalid prefix: ${value}" >&2
    usage >&2
    exit 2
  fi
}

while [ "$#" -gt 0 ]; do
  case "${1}" in
    debug)
      cmake_args+=("-DCMAKE_BUILD_TYPE=DEBUG")
      ;;
    asan)
      cmake_args+=("-DLWS_WITH_ASAN=1")
      ;;
    gcov)
      cmake_args+=("-DLWS_WITH_GCOV=1")
      ;;
    openssl|mbedtls|wolfssl|libressl|boringssl|awslc|openhitls)
      if [ -n "${tls_choice}" ] && [ "${tls_choice}" != "${1}" ]; then
        echo "Only one TLS option is allowed: already set to '${tls_choice}'" >&2
        exit 2
      fi
      tls_choice="${1}"
      ;;
    fulltests|minimal)
      profile="${1}"
      ;;
    run-tests)
      run_ctest=1
      ;;
    --prefix)
      shift
      if [ -z "${1:-}" ]; then
        echo "Option --prefix requires an argument." >&2
        usage >&2
        exit 2
      fi
      validate_prefix "${1}"
      prefix="${1}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: ${1}" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ -z "${build_dir}" ]; then
  if [ -n "${prefix}" ]; then
    build_dir="build-${prefix}"
  else
    build_dir="build"
  fi
fi

if [ -z "${destdir_dir}" ]; then
  if [ -n "${prefix}" ]; then
    destdir_dir="destdir-${prefix}"
  else
    destdir_dir="destdir"
  fi
fi

build_dir="${BUILD_DIR:-${build_dir}}"
destdir_dir="${DESTDIR_DIR:-${destdir_dir}}"

case "${tls_choice}" in
  "")
    if [ -n "${OPENSSL_ROOT_DIR:-}" ]; then
      cmake_args+=("-DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}")
    fi
    if [ -n "${OPENSSL_EXECUTABLE:-}" ]; then
      cmake_args+=("-DOPENSSL_EXECUTABLE=${OPENSSL_EXECUTABLE}")
    fi
    if [ -n "${LWS_OPENSSL_INCLUDE_DIRS:-}" ]; then
      cmake_args+=("-DLWS_OPENSSL_INCLUDE_DIRS=${LWS_OPENSSL_INCLUDE_DIRS}")
    fi
    if [ -n "${LWS_OPENSSL_LIBRARIES:-}" ]; then
      cmake_args+=("-DLWS_OPENSSL_LIBRARIES=${LWS_OPENSSL_LIBRARIES}")
    fi
    ;;
  openssl)
    if [ -n "${OPENSSL_ROOT_DIR:-}" ]; then
      cmake_args+=("-DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}")
    fi
    if [ -n "${OPENSSL_EXECUTABLE:-}" ]; then
      cmake_args+=("-DOPENSSL_EXECUTABLE=${OPENSSL_EXECUTABLE}")
    fi
    if [ -n "${LWS_OPENSSL_INCLUDE_DIRS:-}" ]; then
      cmake_args+=("-DLWS_OPENSSL_INCLUDE_DIRS=${LWS_OPENSSL_INCLUDE_DIRS}")
    fi
    if [ -n "${LWS_OPENSSL_LIBRARIES:-}" ]; then
      cmake_args+=("-DLWS_OPENSSL_LIBRARIES=${LWS_OPENSSL_LIBRARIES}")
    fi
    ;;
  mbedtls) cmake_args+=("-DLWS_WITH_MBEDTLS=1") ;;
  wolfssl) cmake_args+=("-DLWS_WITH_WOLFSSL=1") ;;
  libressl) cmake_args+=("-DLWS_WITH_LIBRESSL=1") ;;
  boringssl) cmake_args+=("-DLWS_WITH_BORINGSSL=1") ;;
  awslc) cmake_args+=("-DLWS_WITH_AWSLC=1") ;;
  openhitls)
    cmake_args+=("-DLWS_WITH_OPENHITLS=1")
    if [ -n "${OPENHITLS_INCLUDE_DIRS:-}" ]; then
      cmake_args+=("-DOPENHITLS_INCLUDE_DIRS=${OPENHITLS_INCLUDE_DIRS}")
    fi
    if [ -n "${OPENHITLS_LIBRARIES:-}" ]; then
      cmake_args+=("-DOPENHITLS_LIBRARIES=${OPENHITLS_LIBRARIES}")
    fi
    ;;
esac

if [ "${profile}" = "fulltests" ]; then
  cmake_args+=(
    "-DLWS_HAVE_PTHREAD_H=1"
    "-DLWS_WITH_MINIMAL_EXAMPLES=1"
    "-DLWS_WITHOUT_TESTAPPS=0"
    "-DLWS_WITHOUT_TEST_SERVER=0"
    "-DLWS_WITH_SECURE_STREAMS=1"
    "-DLWS_WITH_HTTP2=1"
    "-DLWS_CTEST_INTERNET_AVAILABLE=1"
    "-DLWS_WITH_GENCRYPTO=1"
    "-DLWS_WITH_JOSE=1"
    "-DLWS_WITH_COSE=1"
    "-DLWS_ROLE_MQTT=1"
    "-DLWS_WITH_EVENT_LIBS=1"
    "-DLWS_WITH_LIBUV=1"
    "-DLWS_WITH_HTTP_PROXY=1"
    "-DLWS_ROLE_RAW_PROXY=1"
    "-DLWS_WITH_PLUGINS=1"
    "-DLWS_WITH_PLUGINS_API=1"
    "-DLWS_WITH_PLUGINS_BUILTIN=1"
    "-DLWS_WITH_SQLITE3=1"
    "-DLWS_WITH_STRUCT_JSON=1"
    "-DLWS_WITH_STRUCT_SQLITE3=1"
    "-DLWS_WITH_SYS_ASYNC_DNS=1"
    "-DLWS_WITH_SYS_FAULT_INJECTION=1"
    "-DLWS_WITH_UDP=1"
    "-DLWS_WITH_SECURE_STREAMS_PROXY_API=1"
    "-DLWS_WITH_SECURE_STREAMS_CPP=1"
    "-DLWS_WITH_LWS_DSH=1"
    "-DLWS_WITH_FTS=1"
    "-DLWS_WITH_CBOR=1"
    "-DLWS_WITH_SELFTESTS=1"
    "-DLWS_WITH_TLS_JIT_TRUST=1"
  )
fi
if [ "${profile}" = "minimal" ]; then
  cmake_args+=(
    "-DLWS_HAVE_PTHREAD_H=1"
    "-DLWS_WITH_MINIMAL_EXAMPLES=1"
    "-DLWS_WITHOUT_TESTAPPS=0"
    "-DLWS_WITH_HTTP2=1"
    "-DLWS_CTEST_INTERNET_AVAILABLE=0"
    "-DLWS_WITH_GENCRYPTO=1"
    "-DLWS_WITH_TLS_SESSIONS=1"
    "-DLWS_ROLE_MQTT=1"
    "-DLWS_WITH_EVENT_LIBS=1"
    "-DLWS_WITH_LIBUV=1"
    "-DLWS_WITH_PLUGINS=1"
    "-DLWS_WITH_PLUGINS_API=1"
    "-DLWS_WITH_PLUGINS_BUILTIN=1"
    "-DLWS_WITH_SQLITE3=1"
    "-DLWS_WITH_STRUCT_JSON=1"
    "-DLWS_WITH_STRUCT_SQLITE3=1"
    "-DLWS_WITH_SYS_FAULT_INJECTION=1"
    "-DLWS_WITH_UDP=1"
    "-DLWS_WITH_LWS_DSH=1"
    "-DLWS_WITH_FTS=1"
    "-DLWS_WITH_CBOR=1"
    "-DLWS_WITH_SELFTESTS=1"
    "-DLWS_WITH_TLS_JIT_TRUST=1"
  )
  cmake_args+=(
    "-DLWS_WITH_JOSE=1"
    "-DLWS_WITH_COSE=1"
  )
  if [ "${tls_choice}" = "openhitls" ]; then
    cmake_args+=(
      "-DLWS_WITH_DTLS=1"
    )
  fi
fi
configure_args=()
if cmake --help 2>/dev/null | grep -q -- '--fresh'; then
  configure_args+=(--fresh)
else
  rm -f "${repo_root}/${build_dir}/CMakeCache.txt"
  rm -rf "${repo_root}/${build_dir}/CMakeFiles"
fi

if [ ${#cmake_args[@]} -gt 0 ]; then
  cmake "${configure_args[@]}" -S "${repo_root}" -B "${repo_root}/${build_dir}" "${cmake_args[@]}"
else
  cmake "${configure_args[@]}" -S "${repo_root}" -B "${repo_root}/${build_dir}"
fi
cmake --build "${repo_root}/${build_dir}" -- -j"${jobs}"

if [ "${run_ctest}" -eq 1 ]; then
  bash "${repo_root}/scripts/run-tests.sh" \
    --build-dir "${repo_root}/${build_dir}" \
    --destdir "${repo_root}/${destdir_dir}" \
    -t "${jobs}"
fi
