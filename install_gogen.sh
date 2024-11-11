#!/bin/sh
set -e

DISABLE_SSL=""
for arg in "$@"; do
  if [ "${arg}" = "-k" ]; then
    DISABLE_SSL=yes
    break
  fi
done

curl ${DISABLE_SSL:+-k} -sSL https://raw.githubusercontent.com/idelchi/scripts/refs/heads/dev/install.sh | INSTALLER_TOOL="gogen" sh -s -- "$@"

# Arguments passed by calling script
TOOL=${INSTALLER_TOOL:-"example"}
OWNER=${INSTALLER_OWNER:-"idelchi"}
VERSION=${INSTALLER_VERSION}
PREFIX=$(printf "%s" "${TOOL}" | tr 'a-z' 'A-Z' | tr -c 'A-Z' '_')

# Allow setting via environment variables, will be overridden by flags
eval BINARY=\${${PREFIX}_BINARY:-\"${TOOL}\"}
eval VERSION=\${${PREFIX}_VERSION:-\"${VERSION}\"}
eval OUTPUT_DIR=\${${PREFIX}_OUTPUT_DIR:-\"./bin\"}
eval DEBUG=\${${PREFIX}_DEBUG:-0}
eval DRY_RUN=\${${PREFIX}_DRY_RUN:-0}
eval ARCH=\${${PREFIX}_ARCH}
eval OS=\${${PREFIX}_OS}
eval DISABLE_SSL=\${${PREFIX}_DISABLE_SSL}
eval TOKEN=\${${PREFIX}_GITHUB_TOKEN}

# Output formatting
format_message() {
    local color="${1}"
    local message="${2}"
    local prefix="${3}"

    # Only use colors if output is a terminal
    if [ -t 1 ]; then
        case "${color}" in
            red)    printf '\033[0;31m%s\033[0m\n' "${prefix}${message}" >&2 ;;
            yellow) printf '\033[0;33m%s\033[0m\n' "${prefix}${message}" >&2 ;;
            green)  printf '\033[0;32m%s\033[0m\n' "${prefix}${message}" ;;
            *)      printf '%s\n' "${prefix}${message}" ;;
        esac
    else
        printf '%s\n' "${prefix}${message}"
    fi
}

debug() {
    if [ "${DEBUG}" -eq 1 ]; then
        format_message "yellow" "$*" "DEBUG: "
    fi
}

warning() {
    format_message "red" "$*" "Warning: "
}

info() {
    format_message "" "$*"
}

success() {
    format_message "green" "$*"
}

# Check if a command exists
need_cmd() {
    if ! command -v "${1}" >/dev/null 2>&1; then
        warning "Required command '${1}' not found"
        exit 1
    fi
    debug "Found required command: ${1}"
}

options() {
    # Define column widths
    local flag_width=8
    local env_width=40
    local default_width=28

    # Print header with printf
    printf "%-${flag_width}s %-${env_width}s %-${default_width}s %s\n" \
        "Flag" "Env" "Default" "Description"
    printf "%s\n" "-----------------------------------------------------------------------------------------------------"

    # Print each row with printf
    printf "%-${flag_width}s %-${env_width}s %-${default_width}s %s\n" \
        "-b" "${PREFIX}_BINARY" "\"${BINARY}\"" "Binary name to install"
    printf "%-${flag_width}s %-${env_width}s %-${default_width}s %s\n" \
        "-d" "${PREFIX}_OUTPUT_DIR" "\"${OUTPUT_DIR}\"" "Output directory"
    printf "%-${flag_width}s %-${env_width}s %-${default_width}s %s\n" \
        "-v" "${PREFIX}_VERSION" "<detected>" "Version to install"
    printf "%-${flag_width}s %-${env_width}s %-${default_width}s %s\n" \
        "-o" "${PREFIX}_OS" "<detected>" "Operating system"
    printf "%-${flag_width}s %-${env_width}s %-${default_width}s %s\n" \
        "-a" "${PREFIX}_ARCH" "<detected>" "Architecture"
    printf "%-${flag_width}s %-${env_width}s %-${default_width}s %s\n" \
        "-x" "${PREFIX}_DEBUG" "false" "Enable debug output"
    printf "%-${flag_width}s %-${env_width}s %-${default_width}s %s\n" \
        "-n" "${PREFIX}_DRY_RUN" "false" "Dry run mode"
    printf "%-${flag_width}s %-${env_width}s %-${default_width}s %s\n" \
        "-k" "${PREFIX}_DISABLE_SSL" "false" "Disable SSL certificate verification"
    printf "%-${flag_width}s %-${env_width}s %-${default_width}s %s\n" \
        "-t" "${PREFIX}_GITHUB_TOKEN" "" "GitHub token for API calls"
    printf "%-${flag_width}s %-${env_width}s %-${default_width}s %s\n" \
        "-h" "" "false" "Show this help message"

    cat <<EOF

Flags take precedence over environment variables when both are set.

Example:

    ${PREFIX}_VERSION="v1.0" ./install.sh -o /usr/local/bin

Set \`-a\` or \`${PREFIX}_ARCH\` to download a specific architecture binary.
This can be useful for edge-cases such as running a 32-bit userland on a 64-bit system.

Version will be retrieved from the latest release if not specified. This requires 'jq' to be installed.
If not available, 'jq' will be downloaded for the current OS and architecture and removed after use.
EOF
}

usage() {
    cat <<EOF
Usage: ${0} [OPTIONS]
Installs '${BINARY}' binary by downloading from GitHub releases.

Options:
EOF
options
exit 1
}

# Download and setup JQ binary if not installed
get_jq() {
    if command -v "jq" >/dev/null 2>&1; then
        return 0
    fi

    JQ_VERSION="1.7.1"

    JQ_OS="${OS}"
    JQ_ARCH="${ARCH}"
    JQ_EXTENSION=""

    # Set JQ_ARCH based on ARCH
    case "${ARCH}" in
        armv*) JQ_ARCH="armhf" ;;
    esac

    # Set extension for Windows
    case "${OS}" in
        windows) JQ_EXTENSION=".exe" ;;
    esac

    # Set name for darwin
    case "${OS}" in
        darwin) JQ_OS="macos" ;;
    esac

    echo "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-${JQ_OS}-${JQ_ARCH}${JQ_EXTENSION}"
}

print_error() {
    warning "   - Is the tool name '${TOOL}' correct?"
    warning "   - Does it have a release?"
    warning "   - Is the version '${VERSION}' correct?"
    warning "Check at 'https://github.com/${OWNER}/${TOOL}/releases'"

    exit 1
}

# Get the latest release tag
get_latest_release() {
    local jq_url
    local tmp

    jq_url=$(get_jq)

    # Check if TOKEN is set. If so, add CURL_ARGS=--header "Authorization: Bearer ${TOKEN}"
    CURL_ARGS=""
    if [ -n "${TOKEN}" ]; then
        CURL_ARGS="-H 'Authorization: Bearer ${TOKEN}'"
    fi

    success $jq_url
    if [ -z "${jq_url}" ]; then
        # System jq is available
        CURL_CMD="curl ${DISABLE_SSL:+-k} ${CURL_ARGS} -s --location 'https://api.github.com/repos/${OWNER}/${TOOL}/releases/latest'"
        VERSION=$(eval "${CURL_CMD}" | jq -r '.tag_name')
    else
        warning "Required command 'jq' not found, downloading it from '${jq_url}'"
        # Need to download jq
        tmp=$(mktemp -d)
        trap 'rm -rf "${tmp}"' EXIT

        code=$(curl ${DISABLE_SSL:+-k} -s -w '%{http_code}' -L -o "${tmp}/jq" "${jq_url}")

        if [ "${code}" != "200" ]; then
            warning "Failed to download '${jq_url}': ${code}"
            warning "Either pass the desired version manually with '-v' or install jq manually"
            rm -rf "${tmp}"

            exit 1
        fi
        chmod +x "${tmp}/jq"
        CURL_CMD="curl ${DISABLE_SSL:+-k} ${CURL_ARGS} -s --location 'https://api.github.com/repos/${OWNER}/${TOOL}/releases/latest'"
        VERSION=$(eval "${CURL_CMD}" | "${tmp}/jq" -r '.tag_name')
        rm -rf "${tmp}"
    fi

    # Check ${VERSION} for null
    if [ "${VERSION}" = "null" ]; then
        warning "Failed to get latest version for '${TOOL}'"
        print_error
    fi

    success "Latest version detected as: ${VERSION}"
}

# Detect architecture with userland check
detect_arch() {
    local arch machine_arch

    machine_arch=$(uname -m)
    debug "Raw architecture: ${machine_arch}"

    case "${machine_arch}" in
        x86_64|amd64)
            # Check for 32-bit userland on 64-bit system only on Linux
            if [ "${OS}" = "linux" ] && command -v getconf >/dev/null 2>&1; then
                if [ "$(getconf LONG_BIT)" = "32" ]; then
                    warning "32-bit userland detected on 64-bit Linux system. Using 32-bit binary."
                    arch="x86"
                else
                    arch="amd64"
                fi
            else
                arch="amd64"
            fi
            ;;
        aarch64|arm64)
            # Check for 32-bit userland on 64-bit system only on Linux
            if [ "${OS}" = "linux" ] && command -v getconf >/dev/null 2>&1; then
                if [ "$(getconf LONG_BIT)" = "32" ]; then
                    warning "32-bit userland detected on 64-bit Linux system. Using armv7 binary."
                    arch="armv7"
                else
                    arch="arm64"
                fi
            else
                arch="arm64"
            fi
            ;;
        arm*)
            arch=${machine_arch%l}
            ;;
        i386|i686)
            arch="x86"
            ;;
        *)
            arch="${machine_arch}"
            ;;
    esac

    debug "Detected architecture: ${arch}"
    ARCH="${arch}"
}

# Detect OS
detect_os() {
    local os
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    debug "Raw OS: ${os}"

    case "${os}" in
        darwin)
            OS="darwin"
            ;;
        linux)
            OS="linux"
            ;;
        msys*|mingw*|cygwin*|windows*)
            OS="windows"
            ;;
        *)
            OS="${os}"
            ;;
    esac

    debug "Detected OS: ${OS}"
}

# Verify the platform is supported
verify_platform() {
    local supported="darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 linux_armv6 linux_armv7 linux_x86 windows_amd64"
    local platform="${OS}_${ARCH}"
    debug "Checking platform: ${platform}"

    if ! printf '%s' "${supported}" | grep -q -w "${platform}"; then
        warning "Platform '${platform}' is not supported"
        warning "Supported platforms: ${supported}"
        exit 1
    fi

    debug "Platform '${platform}' is supported"
}

# Parse arguments
parse_args() {
    while getopts ":b:v:d:a:t:o:xnkhp" opt; do
        case "${opt}" in
            b) BINARY="${OPTARG}" ;;
            v) VERSION="${OPTARG}" ;;
            d) OUTPUT_DIR="${OPTARG}" ;;
            a) ARCH="${OPTARG}" ;;
            o) OS="${OPTARG}" ;;
            x) DEBUG=1 ;;
            n) DRY_RUN=1 ;;
            k) DISABLE_SSL=1 ;;
            t) TOKEN="${OPTARG}" ;;
            p) options; exit 0 ;;
            h) usage ;;
            :) warning "Option -${OPTARG} requires an argument"; usage ;;
            *) warning "Invalid option: -${OPTARG}"; usage ;;
        esac
    done
}

check_url() {
    local url="${1}"
    if curl -I --silent -f "${URL}" > /dev/null; then
        debug "URL '${url}' is reachable"
    else
        warning "URL '${url}' is not reachable"
        print_error

        exit 1
    fi
}

# Main installation function
install() {
    local FORMAT="$1"
    local tmp code

    # Construct the download URL
    local BASE_URL BINARY_NAME URL
    BASE_URL="https://github.com/${OWNER}/${BINARY}/releases/download"
    BINARY_NAME="${BINARY}_${OS}_${ARCH}.${FORMAT}"
    URL="${BASE_URL}/${VERSION}/${BINARY_NAME}"

    success "Selecting '${VERSION}': '${BINARY_NAME}'"

    check_url "${URL}"

    debug "Starting download process..."

    if [ "${DRY_RUN}" -eq 1 ]; then
        info "Would download from: '${URL}'"
        info "Would install to: '${OUTPUT_DIR}'"
        exit 0
    fi

    # Create output directory if it doesn't exist
    mkdir -p "${OUTPUT_DIR}"

    tmp=$(mktemp)
    trap 'rm -f "${tmp}"' EXIT

    # Download and extract/install
    success "Downloading '${BINARY_NAME}' from '${URL}'"

    code=$(curl ${DISABLE_SSL:+-k} -s -w '%{http_code}' -L -o "${tmp}" "${URL}")

    if [ "${code}" != "200" ]; then
        warning "Failed to download ${URL}: ${code}"
        exit 1
    fi

    if [ "${FORMAT}" = "tar.gz" ]; then
        tar -C "${OUTPUT_DIR}" -xzf "${tmp}"
    else
        unzip -qq -o -d "${OUTPUT_DIR}" "${tmp}"
    fi

    success "'${BINARY}' installed to '${OUTPUT_DIR}'"

    rm -f "${tmp}"
}

check_requirements() {
    REQUIRED_COMMANDS="
        curl
        uname
        mktemp
        mkdir
        grep
        tr
        sed
        basename
        dirname"

    for cmd in $REQUIRED_COMMANDS; do
        need_cmd "$cmd"
    done
}

check_default() {
    # If `TOOL` is example, exit with an error
    if [ "${TOOL}" = "example" ]; then
        warning "Please set the INSTALLER_TOOL environment variable to the desired tool name"
        exit 1
    fi
}

main() {
    # Parse arguments
    parse_args "$@"

    # Check for required commands
    check_requirements

    # Check for default values
    check_default

    # Only detect OS if not manually specified
    [ -z "${OS}" ] && detect_os
    # Only detect arch if not manually specified
    [ -z "${ARCH}" ] && detect_arch
    verify_platform

    # If `VERSION` is not set, get the latest release
    if [ -z "${VERSION}" ]; then
        get_latest_release
    fi

    # Set the format based on the OS
    FORMAT="tar.gz"
    if [ "${OS}" = "windows" ]; then
        FORMAT="zip"
    fi

    # Check for required commands
    [ "${FORMAT}" = "tar.gz" ] && need_cmd tar
    [ "${FORMAT}" = "zip" ] && need_cmd unzip

    # Install the binary
    install "${FORMAT}"
}

main "$@"
