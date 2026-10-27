# Only an administrator-approved commit is executable; GitHub HEAD is not approval.
readonly OFFICIAL_REPOSITORY="https://github.com/valtteri-cybersecurity/mysql_siem.git"

release_git() {
    env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_OBJECT_DIRECTORY \
        -u GIT_ALTERNATE_OBJECT_DIRECTORIES -u GIT_CONFIG_PARAMETERS -u GIT_TEMPLATE_DIR \
        -u GIT_EXEC_PATH -u GIT_SSL_NO_VERIFY -u GIT_SSL_CAINFO -u GIT_SSL_CAPATH \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 \
        GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false \
        git -c core.hooksPath=/dev/null -c protocol.allow=never \
            -c protocol.https.allow=always -c http.sslVerify=true "$@"
}

verify_release_checkout() {
    local checkout="$1" approved="$2" origin revision changes
    origin="$(release_git -C "$checkout" remote get-url origin)" || return 1
    revision="$(release_git -C "$checkout" rev-parse --verify 'HEAD^{commit}')" || return 1
    changes="$(release_git -C "$checkout" status --porcelain --untracked-files=all)" || return 1
    [[ "$origin" == "$OFFICIAL_REPOSITORY" && "$revision" == "$approved" && -z "$changes" ]]
}

bootstrap_latest_release() {
    local download checkout revision status
    local -a operation_arguments=()
    [[ "${INSTALL_REVISION:-}" =~ ^[0-9a-f]{40}$ ]] ||
        die "An explicitly approved commit is required: use --revision with its full 40-character lowercase SHA. GitHub main is not an approved release."
    case "${INSTALL_OPERATION:-reset}" in
        upgrade) operation_arguments=(--upgrade) ;;
        reset) operation_arguments=(--reset) ;;
        *) die "Invalid installation operation." ;;
    esac
    command -v git >/dev/null || die "Git is required to download the official release. Install git and retry."
    if [[ "${SIEM_BOOTSTRAP_CHECKOUT:-}" == "$SOURCE_DIR" ]]; then
        [[ "$(stat -c '%u:%a' "${SOURCE_DIR%/*}")" == 0:700 ]] || die "Unsafe downloaded checkout directory."
        [[ "${SIEM_BOOTSTRAP_COMMIT:-}" == "$INSTALL_REVISION" ]] || die "Downloaded release approval changed during handoff."
        verify_release_checkout "$SOURCE_DIR" "$INSTALL_REVISION" || die "Downloaded release verification failed."
        log "Installing approved official commit $INSTALL_REVISION."
        return
    fi
    log "Approved official commit: $INSTALL_REVISION. Approval is supplied by the administrator; no signed-release policy is available."
    download="$(mktemp -d /tmp/mysql_siem-download-XXXXXXXX)" || die "Cannot prepare GitHub download."
    chmod 700 "$download"
    checkout="$download/project"
    if ! release_git init --quiet --template= "$checkout" ||
            ! release_git -C "$checkout" remote add origin "$OFFICIAL_REPOSITORY" ||
            ! release_git -C "$checkout" fetch --quiet --no-tags --depth 1 origin "$INSTALL_REVISION"; then
        rm -rf -- "$download"
        die "GitHub download failed; no installed version or database was changed."
    fi
    revision="$(release_git -C "$checkout" rev-parse --verify 'FETCH_HEAD^{commit}')" || {
        rm -rf -- "$download"; die "Cannot verify the downloaded commit.";
    }
    if [[ "$revision" != "$INSTALL_REVISION" ]] ||
            ! release_git -C "$checkout" checkout --quiet --detach "$INSTALL_REVISION" ||
            ! verify_release_checkout "$checkout" "$INSTALL_REVISION"; then
        rm -rf -- "$download"
        die "Official checkout verification failed."
    fi
    if [[ ! -f "$checkout/install.sh" || -L "$checkout/install.sh" ||
          ! -f "$checkout/config/install_bootstrap.sh" || -L "$checkout/config/install_bootstrap.sh" ]]; then
        rm -rf -- "$download"
        die "Approved commit does not contain the required installer."
    fi
    status=0
    SIEM_BOOTSTRAP_CHECKOUT="$checkout" SIEM_BOOTSTRAP_COMMIT="$revision" \
        SIEM_BOOTSTRAP_SETTINGS="$SOURCE_DIR" SIEM_BOOTSTRAP_CONFIRMED="$checkout" \
        /bin/bash "$checkout/install.sh" --role server "${operation_arguments[@]}" --revision "$revision" || status=$?
    rm -rf -- "$download"
    exit "$status"
}
