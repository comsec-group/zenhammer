#!/usr/bin/env bash
#
# Download raw data on recent Blacksmith runs from the S3 bucket and immediately
# flatten the directory structure, such that all files are placed in the current
# working directory. Ensure the filenames contain the DIMM ID and timestamp.

set -euo pipefail

declare -rA log_colors=(
    ["reset"]="$(tput sgr0)"
    ["fail"]="$(tput setaf 1)"
    ["info"]="$(tput setaf 6)"
)

declare -rA log_prefixes=(
    ["error"]="[*]"
    ["info"]="[>]"
)

function log() {
    local lvl="${1}"
    local msg="${2}"

    echo "${log_colors[${lvl}]}${log_prefixes[${lvl}]} ${msg}${log_colors[reset]}" >&2
}

function download() {
    log info "querying S3 bucket for runs between Feb 1 and Feb 4..."

    # Get list of all files in the Blacksmith bucket
    readonly aws="$(aws s3 ls --recursive s3://blacksmith-evaluation/)" || {
        log error "failed to access the AWS S3 bucket!"
        exit 1
    }

    # Filter raw_data.json files for runs between Feb 1 and Feb 4
    readonly files="$(echo "${aws}" | grep -P '\/2021020[1-4].+raw_data.json')"
    readonly file_count="$(wc -l <<<"${files}")"
    log info "querying S3 bucket for runs between Feb 1 and Feb 4... found ${file_count} files"

    echo "Ready to download ${file_count} files. Proceed?"
    select yn in "Yes" "No"; do
        case $yn in
        Yes) break ;;
        No) exit ;;
        esac
    done

    count=1
    # Strip file size/date modified from file list.
    readonly filenames="$(sed -nr 's/.*(DIMM.*?).json/\1.json/p' <<<"${files}")"
    for file in ${filenames}; do
        # Extract DIMM ID from file name:
        #   DIMM_15/20210203093518_ee-tik-cn004/raw_data.json -> 15
        dimm="$(sed -nr 's/DIMM_([0-9]+)\/(.*?)/\1/p' <<<"${file}")"

        # Zero-prefix DIMM ID
        dimm="$(printf %03d "${dimm}")"

        # Format the target file name and flatten the directory structure. All
        # in all, we transform
        #   DIMM_15/20210203093518_ee-tik-cn004/raw_data.json
        # into
        #   DIMM_015.20210203093518_ee-tik-cn004.raw_data.json
        target="DIMM_${dimm}.$(sed -nr 's/(.*?)\/(.*?)\/(.*?)/\2.\3/p' <<<"${file}")"

        log info "downloading (${count}/${file_count}) -> ${target}..."
        aws s3 cp "s3://blacksmith-evaluation/${file}" "${target}" || {
            log error "failed to download from the AWS S3 bucket!"
            exit 1
        }
        ((count++))
    done
}

download
