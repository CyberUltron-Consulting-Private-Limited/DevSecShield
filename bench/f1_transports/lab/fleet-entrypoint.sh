#!/bin/sh
# Fleet lab roles (see Dockerfile.fleet). Lab only: generated keys and passwords, self-signed TLS.
set -eu
role="${ZS_ROLE:-target}"
ip="$(hostname -i | awk '{print $1}')"
tls() {  # a self-signed certificate for this container's address
  mkdir -p /etc/zs-tls && cd /etc/zs-tls
  [ -f api.crt ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -keyout api.key -out api.crt -subj "/CN=$1" -addext "subjectAltName=IP:$ip,DNS:$1" 2>/dev/null
  cd /
}
case "$role" in
  target|minion)
    if [ -n "${ZS_ROOT_PUB:-}" ]; then
      install -d -m 0700 /root/.ssh && printf '%s\n' "$ZS_ROOT_PUB" > /root/.ssh/authorized_keys
      chmod 0600 /root/.ssh/authorized_keys
    fi
    if [ "$role" = minion ]; then
      mkdir -p /etc/salt
      printf 'master: %s\nid: %s\nlog_level: warning\n' "${ZS_SALT_MASTER:?}" "$(hostname)" > /etc/salt/minion
      /opt/salt/bin/salt-minion -d
    fi
    exec /usr/local/sbin/lab-entrypoint ;;
  master)
    tls salt-api
    id zs >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin zs
    printf 'zs:%s\n' "${ZS_SALT_PASSWORD:?}" | chpasswd
    mkdir -p /etc/salt/master.d /srv/salt/zeroshield /etc/salt/ssh
    cat > /etc/salt/master.d/zs.conf <<CONF
interface: 0.0.0.0
auto_accept: True
log_level: warning
file_roots:
  base: [/srv/salt]
roster_file: /etc/salt/roster
# salt-api's ssh client ignores roster_file and searches these directories for a file named roster
rosters: [/etc/salt]
# lab only: the targets' host keys are generated at start; a customer pins them (known_hosts) instead
ignore_host_keys: True
ssh_priv: /etc/salt/ssh/id_ed25519
ssh_user: root
ssh_max_procs: ${ZS_SSH_MAX_PROCS:-50}
ssh_minion_opts: {log_level: warning}
# local_async results are read with GET /jobs/<jid>, which salt-api serves through the runner client (@jobs)
netapi_enable_clients: [local, local_async, ssh, runner]
# a pip-installed salt runs PAM in a helper process; salt resolves this path's symlinks, which would leave the
# venv (/opt/salt/bin/python -> /usr/bin/python3.11, no salt there), so it is a small script that execs the venv
auth.pam.python: /opt/salt/bin/pam-python
rest_cherrypy:
  host: 0.0.0.0
  port: 8000
  ssl_crt: /etc/zs-tls/api.crt
  ssl_key: /etc/zs-tls/api.key
  thread_pool: 30
external_auth:
  pam:
    zs:
      - cmd.script
      - state.apply
      - '@jobs'
CONF
    printf '#!/bin/sh\nexec /opt/salt/bin/python "$@"\n' > /opt/salt/bin/pam-python && chmod 0755 /opt/salt/bin/pam-python
    [ -f /etc/salt/roster ] || : > /etc/salt/roster
    /opt/salt/bin/salt-master -d
    exec /opt/salt/bin/salt-api ;;
  awx)
    tls awx
    PATH=/opt/ansible/bin:$PATH exec /opt/ansible/bin/python /opt/awx-emu/app.py ;;
  *) echo "unknown ZS_ROLE $role" >&2; exit 2 ;;
esac
