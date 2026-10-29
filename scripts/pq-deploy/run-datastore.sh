#!/usr/bin/env bash
# Datastore parity (PAR-08): run the SPIRE datastore conformance suite against
# PostgreSQL and MySQL, and verify an upgrade from the previous release schema.
#
# - SQLite conformance (includes the upstream migration dumps)
# - PostgreSQL 17 conformance via the dialect-parameterized suite
# - MySQL 8.0 and 8.4 conformance
# - Schema upgrade from SPIRE v1.15.5 (schema 25) to the current fork (27) on
#   both PostgreSQL and MySQL, comparing against a freshly-migrated database
#
# Integration evidence only. Containers bind loopback ports and are removed on
# exit.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
spire="$(cd "$here/../.." && pwd)"
spire_fork="${SPIRE_FORK:-$(cd "$spire/../spire" 2>/dev/null && pwd)}"
if [[ -z "$spire_fork" || ! -x "$spire_fork/.build/bin/spire-server" ]]; then
  echo "FAIL: build the PQ SPIRE fork first (SPIRE_FORK=<path>)" >&2
  exit 2
fi
evidence="${1:-$spire/.build/pq-datastore-evidence}"
work="${2:-$spire/.build/pq-datastore}"
pg_port="${3:-15440}"
mysql84_port="${4:-13306}"
mysql80_port="${5:-13307}"
root="$(GOTOOLCHAIN=go1.27.3 go env GOROOT)"
export PATH="$root/bin:$PATH" GOTOOLCHAIN=local
test "$(go env GOVERSION)" = "go1.27.3" || { echo "FAIL: Go 1.27.3 required" >&2; exit 2; }

cd "$spire_fork"

exec 9>/tmp/qspiffe-datastore-run.lock
flock -n 9 || { echo "FAIL: another datastore run is active" >&2; exit 2; }

mkdir -p "$work"
rm -rf "$work"
mkdir -p "$evidence/datastore" "$work/log"
pg="qspiffe-ds-pg-$$"
my84="qspiffe-ds-my84-$$"
my80="qspiffe-ds-my80-$$"
net="qspiffe-ds-$$"
cleanup() {
  docker rm -f "$pg" "$my84" "$my80" >/dev/null 2>&1
  docker network rm "$net" >/dev/null 2>&1
  if [[ -d "$work/spire-v1155" ]]; then
    git -C "$spire_fork" worktree remove --force "$work/spire-v1155" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

docker network create "$net" >/dev/null || fail "create network"

start_pg() {
  docker run -d --name "$pg" --network "$net" -p "127.0.0.1:$pg_port:5432" \
    -e POSTGRES_USER=spire -e POSTGRES_PASSWORD=test -e POSTGRES_DB=spire \
    --tmpfs /var/lib/postgresql/data \
    postgres:17-alpine -c fsync=off -c synchronous_commit=off -c full_page_writes=off >/dev/null 2>&1 || fail "start postgres"
  for _ in $(seq 1 120); do
    docker exec "$pg" pg_isready -U spire -d spire >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

start_mysql() {
  local name="$1" port="$2" image="$3"
  docker run -d --name "$name" --network "$net" -p "127.0.0.1:$port:3306" \
    -e MYSQL_USER=spire -e MYSQL_PASSWORD=test -e MYSQL_DATABASE=spire -e MYSQL_ROOT_PASSWORD=root \
    --tmpfs /var/lib/mysql \
    "$image" --innodb-flush-log-at-trx-commit=0 --innodb-doublewrite=0 --skip-log-bin >/dev/null 2>&1 || fail "start $image"
  for _ in $(seq 1 120); do
    docker exec "$name" mysql -uspire -ptest -e 'select 1' >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}

start_pg || fail "postgres not ready"
start_mysql "$my84" "$mysql84_port" mysql:8.4 || fail "mysql 8.4 not ready"
start_mysql "$my80" "$mysql80_port" mysql:8.0 || fail "mysql 8.0 not ready"
printf 'postgres:17-alpine\nmysql:8.4\nmysql:8.0\n' > "$evidence/datastore/engines.txt"

# --- conformance suite -----------------------------------------------------
go test -count=1 ./pkg/server/datastore/sqlstore > "$evidence/datastore/sqlite-conformance.log" 2>&1 \
  || fail "sqlite conformance suite"
printf 'sqlite3: PASS\n' > "$evidence/datastore/conformance.txt"

build_suite() {
  local dialect="$1" out="$2"
  go test -c -o "$out" -ldflags \
    "-X github.com/spiffe/spire/pkg/server/datastore/sqlstore.TestDialect=$dialect" \
    ./pkg/server/datastore/sqlstore || return 1
}

run_suite() {
  local name="$1" binary="$2" conn="$3"
  ( cd "$spire_fork/pkg/server/datastore/sqlstore" && \
    SQLSTORE_TEST_CONN_STRING="$conn" SQLSTORE_TEST_RO_CONN_STRING="$conn" \
    "$binary" -test.timeout 20m -test.count=1 ) > "$evidence/datastore/$name-conformance.log" 2>&1
  local rc=$?
  if (( rc == 0 )); then
    printf '%s: PASS\n' "$name" >> "$evidence/datastore/conformance.txt"
  else
    printf '%s: FAIL\n' "$name" >> "$evidence/datastore/conformance.txt"
  fi
  return "$rc"
}

build_suite postgres "$work/postgres.test" || fail "build postgres suite"
build_suite mysql "$work/mysql.test" || fail "build mysql suite"

run_suite postgres "$work/postgres.test" \
  "postgres://spire:test@127.0.0.1:$pg_port/spire?sslmode=disable" || fail "postgres conformance suite"
run_suite mysql-8.4 "$work/mysql.test" \
  "spire:test@tcp(127.0.0.1:$mysql84_port)/spire?parseTime=true" || fail "mysql 8.4 conformance suite"
run_suite mysql-8.0 "$work/mysql.test" \
  "spire:test@tcp(127.0.0.1:$mysql80_port)/spire?parseTime=true" || fail "mysql 8.0 conformance suite"

# --- cross-release schema upgrade -----------------------------------------
git -C "$spire_fork" worktree add -f "$work/spire-v1155" v1.15.5 > "$work/log/worktree.log" 2>&1 \
  || fail "create v1.15.5 worktree"
( cd "$work/spire-v1155" && go build -o "$work/spire-server-v1155" ./cmd/spire-server ) > "$work/log/old-build.log" 2>&1 \
  || fail "build v1.15.5 server"
old_bin="$work/spire-server-v1155"
new_bin="$spire_fork/.build/bin/spire-server"

run_server() {
  local bin="$1" conf="$2" socket="$3"
  "$bin" run -config "$conf" > "${conf%.conf}.log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 90); do
    "$bin" healthcheck -socketPath "$socket" >/dev/null 2>&1 && { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; return 0; }
    sleep 1
  done
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  return 1
}

write_conf() {
  local path="$1" port="$2" socket="$3" data="$4" dbtype="$5" conn="$6" strict="$7"
  mkdir -p "$data"
  cat > "$path" <<EOF
server {
    bind_address = "127.0.0.1"
    bind_port = "$port"
    socket_path = "$socket"
    trust_domain = "pq.example"
    data_dir = "$data"
    log_level = "INFO"
$([[ "$strict" == "yes" ]] && printf '    ca_key_type = "ml-dsa-65"\n    disable_jwt_svids = true\n    strict_pq = true\n')
}
plugins {
    DataStore "sql" { plugin_data { database_type = "$dbtype" connection_string = "$conn" } }
    KeyManager "memory" { plugin_data {} }
}
EOF
}

upgrade_case() {
  local name="$1" dbtype="$2" port_base="$3" conn_upgrade="$4" conn_fresh="$5" old_version_query="$6"
  local dir="$work/$name"
  mkdir -p "$dir"

  write_conf "$dir/old.conf" "$((port_base))" "$dir/old.sock" "$dir/old-data" "$dbtype" "$conn_upgrade" no
  run_server "$old_bin" "$dir/old.conf" "$dir/old.sock" || { tail -30 "$dir/old.log" >&2; fail "$name: v1.15.5 server did not start"; }
  local old_version
  old_version="$(eval "$old_version_query")"
  echo "$old_version" > "$evidence/datastore/$name-old-schema.txt"

  write_conf "$dir/new.conf" "$((port_base + 1))" "$dir/new.sock" "$dir/new-data" "$dbtype" "$conn_upgrade" yes
  run_server "$new_bin" "$dir/new.conf" "$dir/new.sock" || { tail -30 "$dir/new.log" >&2; fail "$name: current server did not start on upgraded database"; }
  local upgraded_version
  upgraded_version="$(eval "$old_version_query")"
  echo "$upgraded_version" > "$evidence/datastore/$name-upgraded-schema.txt"

  write_conf "$dir/fresh.conf" "$((port_base + 2))" "$dir/fresh.sock" "$dir/fresh-data" "$dbtype" "$conn_fresh" yes
  run_server "$new_bin" "$dir/fresh.conf" "$dir/fresh.sock" || { tail -30 "$dir/fresh.log" >&2; fail "$name: current server did not start on fresh database"; }
  local fresh_version
  fresh_version="$(eval "$old_version_query")"
  echo "$fresh_version" > "$evidence/datastore/$name-fresh-schema.txt"

  [[ -n "$old_version" && -n "$upgraded_version" && -n "$fresh_version" ]] || fail "$name: could not read schema versions"
  (( old_version < upgraded_version )) || fail "$name: upgrade did not advance schema (old=$old_version upgraded=$upgraded_version)"
  [[ "$upgraded_version" == "$fresh_version" ]] || fail "$name: upgraded schema ($upgraded_version) differs from fresh ($fresh_version)"
  printf '%s: schema %s -> %s (fresh %s), server healthy\n' "$name" "$old_version" "$upgraded_version" "$fresh_version" \
    >> "$evidence/datastore/upgrade.txt"
}

# PostgreSQL upgrade databases.
docker exec "$pg" psql -U spire -d postgres -c 'CREATE DATABASE upgrade' >/dev/null || fail "create pg upgrade db"
docker exec "$pg" psql -U spire -d postgres -c 'CREATE DATABASE fresh' >/dev/null || fail "create pg fresh db"
upgrade_case postgres postgres 18100 \
  "postgres://spire:test@127.0.0.1:$pg_port/upgrade?sslmode=disable" \
  "postgres://spire:test@127.0.0.1:$pg_port/fresh?sslmode=disable" \
  "docker exec '$pg' psql -U spire -d upgrade -tAc 'select version from migrations'"

# MySQL upgrade databases (grant the application user access).
docker exec "$my84" mysql -uroot -proot -e \
  "CREATE DATABASE upgrade_m; CREATE DATABASE fresh_m; GRANT ALL PRIVILEGES ON upgrade_m.* TO 'spire'@'%'; GRANT ALL PRIVILEGES ON fresh_m.* TO 'spire'@'%'; FLUSH PRIVILEGES;" \
  >/dev/null 2>&1 || fail "create mysql upgrade databases"
upgrade_case mysql mysql 18110 \
  "spire:test@tcp(127.0.0.1:$mysql84_port)/upgrade_m?parseTime=true" \
  "spire:test@tcp(127.0.0.1:$mysql84_port)/fresh_m?parseTime=true" \
  "docker exec '$my84' mysql -uspire -ptest -N -e 'select version from migrations' upgrade_m"

for f in "$evidence/datastore"/*.log; do
  if grep -qiE 'BEGIN (EC |RSA |ML-DSA )?PRIVATE KEY' "$f"; then
    fail "private key material found in $f"
  fi
done

echo "PASS: SQLite, PostgreSQL and MySQL conformance plus v1.15.5 schema upgrade"
