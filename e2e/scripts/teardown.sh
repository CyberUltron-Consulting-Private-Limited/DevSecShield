#!/usr/bin/env bash
# teardown.sh - remove everything a dss-e2e run created, and nothing else. One command.
#
#   docker compose -p dss-e2e -f e2e/compose/docker-compose.e2e.yml --profile seed down -v --remove-orphans
#
# This is the ONLY place in e2e/ that runs `down -v` (it is a throw-away project; production stages
# forbid it). Guards, in order:
#   1. the project name must be exactly "dss-e2e" and the compose file the one in this tree;
#   2. every container / volume / network that belongs to the compose project must carry the label
#      com.dss-e2e=1, otherwise nothing is removed;
#   3. after `down`, any leftover object labelled com.dss-e2e=1 is removed by id (never by pattern);
#   4. the daemon's containers / volumes / networks are diffed against preflight's "before" snapshot:
#      a NON-dss-e2e object that vanished is a failure (exit 3); one that merely appeared or changed
#      status is reported only (the daemon is shared with other work).
# Never run: docker system|image|volume|buildx prune. Images are removed only with --purge-images,
# and only the three dss-e2e/*:local tags.
#
# Usage: teardown.sh [--purge-images] [--keep-work]
#   --purge-images  also `docker rmi` dss-e2e/{backend,frontend,aibom-scan}:local
#   --keep-work     keep e2e/.work (scan trees, scan outputs, seed.json) for debugging
# Removes: e2e/.work, e2e/compose/.env.e2e, e2e/test-results. Never touches the evidence directory.
# Logs:    <evidence>/logs/90-teardown.txt, docker-{ps,volume,network}-after.txt
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

PURGE_IMAGES=0
KEEP_WORK=0
while (($#)); do
  case "$1" in
    --purge-images)
      PURGE_IMAGES=1
      shift
      ;;
    --keep-work)
      KEEP_WORK=1
      shift
      ;;
    -h | --help)
      sed -n '2,26p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

label_of() { # <kind> <id>
  case "$1" in
    container) docker inspect -f '{{index .Config.Labels "com.dss-e2e"}}' "$2" 2>/dev/null ;;
    volume) docker volume inspect -f '{{index .Labels "com.dss-e2e"}}' "$2" 2>/dev/null ;;
    network) docker network inspect -f '{{index .Labels "com.dss-e2e"}}' "$2" 2>/dev/null ;;
  esac
}

# Everything the compose project owns must be ours (labelled) or we refuse to delete anything.
guard_project_objects() {
  local bad=0 id
  while IFS= read -r id; do
    [[ -n "${id}" ]] || continue
    if [[ "$(label_of container "${id}")" != "1" ]]; then
      warn "container $(docker inspect -f '{{.Name}}' "${id}") is in project ${E2E_PROJECT} but lacks ${E2E_LABEL}"
      bad=1
    fi
  done < <(docker ps -aq --filter "label=com.docker.compose.project=${E2E_PROJECT}")
  while IFS= read -r id; do
    [[ -n "${id}" ]] || continue
    if [[ "$(label_of volume "${id}")" != "1" ]]; then
      warn "volume ${id} is in project ${E2E_PROJECT} but lacks ${E2E_LABEL}"
      bad=1
    fi
  done < <(docker volume ls -q --filter "label=com.docker.compose.project=${E2E_PROJECT}")
  while IFS= read -r id; do
    [[ -n "${id}" ]] || continue
    if [[ "$(label_of network "${id}")" != "1" ]]; then
      warn "network ${id} is in project ${E2E_PROJECT} but lacks ${E2E_LABEL}"
      bad=1
    fi
  done < <(docker network ls -q --filter "label=com.docker.compose.project=${E2E_PROJECT}")
  ((bad == 0)) || die "refusing to tear down: unlabelled objects in project ${E2E_PROJECT} (nothing was removed)"
  log "guard OK: every object of project ${E2E_PROJECT} carries ${E2E_LABEL}"
}

remove_labelled_stragglers() {
  local id
  while IFS= read -r id; do
    [[ -n "${id}" ]] || continue
    log "removing leftover labelled container $(docker inspect -f '{{.Name}}' "${id}")"
    docker rm -f "${id}" >/dev/null
  done < <(docker ps -aq --filter "label=${E2E_LABEL}")
  while IFS= read -r id; do
    [[ -n "${id}" ]] || continue
    log "removing leftover labelled volume ${id}"
    docker volume rm "${id}" >/dev/null
  done < <(docker volume ls -q --filter "label=${E2E_LABEL}")
  while IFS= read -r id; do
    [[ -n "${id}" ]] || continue
    log "removing leftover labelled network ${id}"
    docker network rm "${id}" >/dev/null
  done < <(docker network ls -q --filter "label=${E2E_LABEL}")
}

residue() {
  {
    docker ps -aq --filter "label=${E2E_LABEL}"
    docker ps -aq --filter "label=com.docker.compose.project=${E2E_PROJECT}"
    docker volume ls -q --filter "label=${E2E_LABEL}"
    docker network ls -q --filter "label=${E2E_LABEL}"
  } | sort -u
}

# Compare the daemon against preflight's "before" snapshot, ignoring dss-e2e objects.
# Sets COMPARED=1 when every snapshot pair existed (so the final message can say what was proven).
COMPARED=0
diff_foreign_objects() {
  local logs status=0 kind noun before after vanished appeared missing=0
  logs="$(dirname "$(e2e_log_file x)")"
  for kind in ps volume network; do
    noun=${kind}
    [[ "${kind}" == ps ]] && noun=container
    before="${logs}/docker-${kind}-before.txt"
    after="${logs}/docker-${kind}-after.txt"
    if [[ ! -f "${before}" ]]; then
      warn "no ${noun} 'before' snapshot (run preflight.sh first): cannot prove foreign ${noun}s are unchanged"
      missing=1
      continue
    fi
    # first column = name; drop our own objects (dss-e2e-* containers, dss-e2e_* volumes/networks)
    vanished="$(comm -23 <(cut -f1 "${before}" | grep -vE '^dss-e2e[-_]' | LC_ALL=C sort -u) <(cut -f1 "${after}" | grep -vE '^dss-e2e[-_]' | LC_ALL=C sort -u) || true)"
    appeared="$(comm -13 <(cut -f1 "${before}" | grep -vE '^dss-e2e[-_]' | LC_ALL=C sort -u) <(cut -f1 "${after}" | grep -vE '^dss-e2e[-_]' | LC_ALL=C sort -u) || true)"
    if [[ -n "${vanished}" ]]; then
      log "FAIL  foreign ${noun}(s) VANISHED since preflight: $(printf '%s' "${vanished}" | tr '\n' ' ')"
      status=3
    else
      log "OK    no foreign ${noun} vanished"
    fi
    if [[ -n "${appeared}" ]]; then
      log "INFO  foreign ${noun}(s) appeared since preflight (created by other work, not by this script): $(printf '%s' "${appeared}" | tr '\n' ' ')"
    fi
    if [[ "${kind}" == "ps" ]]; then
      local changed
      changed="$(comm -13 <(grep -vE '^dss-e2e-' "${before}" | cut -f1,2 | LC_ALL=C sort -u) <(grep -vE '^dss-e2e-' "${after}" | cut -f1,2 | LC_ALL=C sort -u) | cut -f1 | LC_ALL=C sort -u | grep -vxFf <(printf '%s\n' "${appeared}") || true)"
      [[ -z "${changed}" ]] || log "INFO  foreign container(s) now run a different image than at preflight (not our doing): $(printf '%s' "${changed}" | tr '\n' ' ')"
    fi
  done
  ((missing == 0)) && COMPARED=1
  return "${status}"
}

main() {
  banner "teardown"
  [[ "${E2E_PROJECT}" == "dss-e2e" ]] || die "project name must be exactly dss-e2e"
  [[ "${E2E_COMPOSE_FILE}" == "${E2E_ROOT}/compose/docker-compose.e2e.yml" && -f "${E2E_COMPOSE_FILE}" ]] || die "unexpected compose file: ${E2E_COMPOSE_FILE}"
  need_cmd docker
  docker info >/dev/null 2>&1 || die "docker daemon not reachable"

  guard_project_objects

  log "docker compose -p ${E2E_PROJECT} down -v --remove-orphans"
  compose --profile seed down -v --remove-orphans
  remove_labelled_stragglers

  local left
  left="$(residue)"
  [[ -z "${left}" ]] || die "objects labelled ${E2E_LABEL} or in project ${E2E_PROJECT} remain after teardown: $(printf '%s' "${left}" | tr '\n' ' ')"
  log "no dss-e2e container, volume or network remains"

  if ((PURGE_IMAGES)); then
    local img
    for img in "${E2E_IMG_BACKEND}" "${E2E_IMG_FRONTEND}" "${E2E_IMG_AIBOM}"; do
      case "${img}" in dss-e2e/*:local) ;; *) die "refusing to remove unexpected image ${img}" ;; esac
      if image_exists "${img}"; then
        docker rmi "${img}" >/dev/null
        log "removed image ${img}"
      fi
    done
  else
    log "images kept (pass --purge-images to remove the three dss-e2e/*:local tags)"
  fi

  if ((KEEP_WORK)); then
    log "kept ${E2E_WORK_DIR#"${REPO_ROOT}"/} (--keep-work)"
  else
    safe_rm_rf "${E2E_WORK_DIR}"
  fi
  safe_rm_rf "${E2E_ENV_FILE}"
  safe_rm_rf "${E2E_ROOT}/test-results"
  log "removed scratch: .work (unless kept), compose/.env.e2e, test-results"

  e2e_prepare_evidence_dirs
  snapshot_docker "$(dirname "$(e2e_log_file x)")" after
  local rc=0
  diff_foreign_objects || rc=$?
  if ((rc == 0 && COMPARED == 1)); then
    log "TEARDOWN OK: no dss-e2e object left, no foreign container / volume / network vanished"
  elif ((rc == 0)); then
    log "TEARDOWN OK: no dss-e2e object left (foreign-object comparison NOT made: no preflight snapshot)"
  else
    log "TEARDOWN FINISHED WITH FOREIGN-OBJECT CHANGES (exit ${rc}): inspect the lines above"
  fi
  return "${rc}"
}

e2e_prepare_evidence_dirs
: >"$(e2e_log_file 90-teardown.txt)"
run_logged "$(e2e_log_file 90-teardown.txt)" main
