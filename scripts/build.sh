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
Usage: scripts/build.sh [debug] [tls] [profile] [run-tests] [options]

TLS options (choose one, default: openssl):
  openssl | mbedtls | wolfssl | libressl | boringssl | awslc | openhitls

Build profile (choose one, default: fulltests):
  fulltests | minimal

Execution options:
  run-tests   Install into DESTDIR and run ctest after building

Options:
  -h, --help  Show help

Environment variables:
  BUILD_DIR              Override build directory
  DESTDIR_DIR            Override DESTDIR used by run-tests
  JOBS                   Override parallel build jobs
  OPENHITLS_INCLUDE_DIRS  OpenHITLS include dirs (semicolon-separated)
  OPENHITLS_LIBRARIES     OpenHITLS libraries (semicolon-separated)

Examples:
  scripts/build.sh
  scripts/build.sh debug
  scripts/build.sh openssl
  scripts/build.sh debug mbedtls
  scripts/build.sh openhitls fulltests
  scripts/build.sh openhitls minimal
  scripts/build.sh openhitls fulltests run-tests
  OPENHITLS_INCLUDE_DIRS=/path/include OPENHITLS_LIBRARIES=/path/lib/libopenhitls.so \\
    scripts/build.sh openhitls
EOF
}

for arg in "$@"; do
  case "${arg}" in
    debug)
      cmake_args+=("-DCMAKE_BUILD_TYPE=DEBUG")
      ;;
    openssl|mbedtls|wolfssl|libressl|boringssl|awslc|openhitls)
      if [ -n "${tls_choice}" ] && [ "${tls_choice}" != "${arg}" ]; then
        echo "Only one TLS option is allowed: already set to '${tls_choice}'" >&2
        exit 2
      fi
      tls_choice="${arg}"
      ;;
    fulltests|minimal)
      profile="${arg}"
      ;;
    run-tests)
      run_ctest=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: ${arg}" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -z "${build_dir}" ]; then
  if [ "${profile}" = "fulltests" ] && [ "${tls_choice}" = "openhitls" ]; then
    build_dir="build-176-hitls"
  else
    build_dir="build"
  fi
fi

if [ -z "${destdir_dir}" ]; then
  if [ "${profile}" = "fulltests" ] && [ "${tls_choice}" = "openhitls" ]; then
    destdir_dir="destdir-176-hitls"
  else
    destdir_dir="destdir"
  fi
fi

build_dir="${BUILD_DIR:-${build_dir}}"
destdir_dir="${DESTDIR_DIR:-${destdir_dir}}"

case "${tls_choice}" in
  "") ;;
  openssl) ;;
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

if [ ${#cmake_args[@]} -gt 0 ]; then
  cmake -S "${repo_root}" -B "${repo_root}/${build_dir}" "${cmake_args[@]}"
else
  cmake -S "${repo_root}" -B "${repo_root}/${build_dir}"
fi
cmake --build "${repo_root}/${build_dir}" -- -j"${jobs}"

if [ "${run_ctest}" -eq 1 ]; then
  rm -rf "${repo_root}/${destdir_dir}"
  make -C "${repo_root}/${build_dir}" -j"${jobs}" \
    DESTDIR="${repo_root}/${destdir_dir}" install
  LD_LIBRARY_PATH="${repo_root}/${destdir_dir}/usr/local/share/libwebsockets-test-server/plugins" \
    ctest --test-dir "${repo_root}/${build_dir}" -j"${jobs}" --output-on-failure
fi
