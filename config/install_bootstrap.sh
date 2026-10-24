# Download a clean, pinned checkout. Never update the user's working tree.
readonly OFFICIAL_REPOSITORY="https://github.com/valtteri-cybersecurity/mysql_siem.git"
readonly OFFICIAL_BRANCH="main"

release_git() {
    env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_OBJECT_DIRECTORY \
        -u GIT_ALTERNATE_OBJECT_DIRECTORIES -u GIT_CONFIG_PARAMETERS \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 \
        git -c core.hooksPath=/dev/null -c protocol.file.allow=never "$@"
}

bootstrap_latest_release() {
    local download checkout revision origin status
    command -v git >/dev/null || die "Git is required to download the official release. Install git and retry."
    if [[ "${SIEM_BOOTSTRAP_CHECKOUT:-}" == "$SOURCE_DIR" ]]; then
        [[ "$(stat -c '%u:%a' "${SOURCE_DIR%/*}")" == 0:700 ]] || die "Unsafe downloaded checkout directory."
        origin="$(release_git -C "$SOURCE_DIR" remote get-url origin)" || die "Cannot verify downloaded repository."
        revision="$(release_git -C "$SOURCE_DIR" rev-parse HEAD)" || die "Cannot verify downloaded revision."
        [[ "$origin" == "$OFFICIAL_REPOSITORY" && "$revision" == "${SIEM_BOOTSTRAP_COMMIT:-}" &&
           "$revision" =~ ^[0-9a-f]{40}$ ]] || die "Downloaded release verification failed."
        log "Installing official $OFFICIAL_BRANCH commit $revision."
        return
    fi
    download="$(mktemp -d /tmp/mysql_siem-download-XXXXXXXX)" || die "Cannot prepare GitHub download."
    chmod 700 "$download"
    checkout="$download/project"
    if ! release_git clone --quiet --depth 1 --single-branch --branch "$OFFICIAL_BRANCH" \
            --no-checkout -- "$OFFICIAL_REPOSITORY" "$checkout"; then
        rm -rf -- "$download"
        die "GitHub download failed; no installed version or database was changed."
    fi
    origin="$(release_git -C "$checkout" remote get-url origin)" || { rm -rf -- "$download"; die "Cannot verify repository origin."; }
    revision="$(release_git -C "$checkout" rev-parse "refs/remotes/origin/$OFFICIAL_BRANCH")" || { rm -rf -- "$download"; die "Cannot resolve official branch."; }
    if [[ "$origin" != "$OFFICIAL_REPOSITORY" || ! "$revision" =~ ^[0-9a-f]{40}$ ]] ||
            ! release_git -C "$checkout" checkout --quiet --detach "$revision"; then
        rm -rf -- "$download"
        die "Official checkout verification failed."
    fi
    if [[ ! -f "$checkout/install.sh" || -L "$checkout/install.sh" ||
          ! -f "$checkout/config/install_bootstrap.sh" || -L "$checkout/config/install_bootstrap.sh" ]]; then
        rm -rf -- "$download"
        die "Official branch does not contain the new installer; publish this change before using it."
    fi
    status=0
    SIEM_BOOTSTRAP_CHECKOUT="$checkout" SIEM_BOOTSTRAP_COMMIT="$revision" \
        SIEM_BOOTSTRAP_SETTINGS="$SOURCE_DIR" SIEM_BOOTSTRAP_CONFIRMED="$checkout" \
        /bin/bash "$checkout/install.sh" --role server || status=$?
    rm -rf -- "$download"
    exit "$status"
}
