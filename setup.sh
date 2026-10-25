#!/usr/bin/env bash
# Reefed - preparação do ambiente. Rode uma vez antes do primeiro "docker compose up".
#
#   ./setup.sh            cria o que estiver faltando (.env, usuários do indexer, certificados)
#   ./setup.sh --users    só refaz o arquivo de usuários do indexer com as senhas do .env
#                         (para trocar senhas com o Reefed no ar, use make passwords)
#   ./setup.sh --force    recria usuários do indexer e certificados (não apaga o .env;
#                         troca de certificados em docs/operacao.md)
#
# Precisa só do Docker com o Compose v2. Tudo roda dentro das imagens do Wazuh.
set -euo pipefail
cd "$(dirname "$0")"

CERT_DIR=config/wazuh_indexer_ssl_certs
USERS_FILE=config/wazuh_indexer/internal_users.yml

info() { printf '\033[1;34m[reefed]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[reefed]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[reefed]\033[0m %s\n' "$*" >&2; exit 1; }

REDO_USERS=no
REDO_CERTS=no
case "${1:-}" in
  "") ;;
  --users) REDO_USERS=yes ;;
  --force) REDO_USERS=yes; REDO_CERTS=yes ;;
  *) fail "opção desconhecida: $1 (use --users ou --force)" ;;
esac

command -v docker >/dev/null 2>&1 || fail "Docker não encontrado. Instale o Docker Engine ou o Docker Desktop."
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 não encontrado (comando 'docker compose')."

# ---------------------------------------------------------------------------
# 1. vm.max_map_count (o indexer/OpenSearch pede pelo menos 262144)
if [ "$(uname -s)" = "Linux" ] && [ -r /proc/sys/vm/max_map_count ]; then
  current=$(cat /proc/sys/vm/max_map_count)
  if [ "$current" -lt 262144 ]; then
    if sysctl -w vm.max_map_count=262144 >/dev/null 2>&1; then
      info "vm.max_map_count ajustado para 262144."
      info "Para manter depois de reiniciar: echo vm.max_map_count=262144 | sudo tee /etc/sysctl.d/99-reefed.conf"
    else
      warn "vm.max_map_count está em $current e o indexer pede 262144. Rode:"
      warn "  sudo sysctl -w vm.max_map_count=262144"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2. .env com senhas aleatórias
random_alnum() {
  local value
  value=$(LC_ALL=C tr -dc 'A-Za-z0-9' < <(head -c 600 /dev/urandom))
  printf '%s' "${value:0:$1}"
}
# Senha aceita pela API do Wazuh: maiúscula, minúscula, número e símbolo.
gen_password() { printf '%s.Rf9' "$(random_alnum 24)"; }
gen_key() { random_alnum 40; }

# Valor de uma variável do .env, sem as aspas em volta (como o docker compose lê)
env_value() {
  local value
  value=$(grep -E "^$1=" .env | head -1 | cut -d= -f2- || true)
  value=${value%\"}; value=${value#\"}
  value=${value%\'}; value=${value#\'}
  printf '%s' "$value"
}

set_env() {  # set_env NOME valor  (só preenche se estiver vazio)
  local name=$1 value=$2
  if [ -z "$(env_value "$name")" ]; then
    NAME="$name" VALUE="$value" awk 'BEGIN{n=ENVIRON["NAME"]; v=ENVIRON["VALUE"]}
      $0 ~ "^"n"=" && !done {print n"="v; done=1; next} {print}' .env > .env.tmp
    cat .env.tmp > .env   # reescreve no lugar: o .env continua só com permissão do dono
    rm -f .env.tmp
  fi
}

if [ ! -f .env ]; then
  cp .env.example .env
  chmod 600 .env
  info ".env criado a partir do .env.example"
fi
set_env INDEXER_PASSWORD "$(gen_password)"
set_env DASHBOARD_PASSWORD "$(gen_password)"
set_env WAZUH_API_PASSWORD "$(gen_password)"
set_env REEFED_API_INDEXER_PASSWORD "$(gen_password)"
set_env REEFED_API_KEY "$(gen_key)"
set_env REEFED_ENROLLMENT_PASSWORD "$(gen_password)"

WAZUH_VERSION=$(env_value WAZUH_VERSION)
WAZUH_VERSION=${WAZUH_VERSION:-4.14.9}
INDEXER_IMAGE="wazuh/wazuh-indexer:$WAZUH_VERSION"
MANAGER_IMAGE="wazuh/wazuh-manager:$WAZUH_VERSION"

for image in "$INDEXER_IMAGE" "$MANAGER_IMAGE"; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    info "baixando $image"
    docker pull -q "$image" >/dev/null
  fi
done

# ---------------------------------------------------------------------------
# 3. Usuários do indexer (bcrypt das senhas do .env)
if [ ! -f "$USERS_FILE" ] || [ "$REDO_USERS" = yes ]; then
  info "gerando $USERS_FILE"
  hashes=$(docker run --rm \
    -e P1="$(env_value INDEXER_PASSWORD)" -e P2="$(env_value DASHBOARD_PASSWORD)" \
    -e P3="$(env_value REEFED_API_INDEXER_PASSWORD)" \
    --entrypoint bash "$INDEXER_IMAGE" -c '
      export JAVA_HOME=/usr/share/wazuh-indexer/jdk
      tool=/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
      for p in "$P1" "$P2" "$P3"; do bash "$tool" -p "$p" 2>/dev/null | tail -1; done')
  # shellcheck disable=SC2016  # "$2" aqui é o começo literal de um hash bcrypt
  [ "$(printf '%s\n' "$hashes" | grep -c '^\$2')" = 3 ] || fail "não consegui gerar os hashes das senhas"
  ADMIN_HASH=$(printf '%s\n' "$hashes" | sed -n 1p) \
  KIBANASERVER_HASH=$(printf '%s\n' "$hashes" | sed -n 2p) \
  REEFED_API_HASH=$(printf '%s\n' "$hashes" | sed -n 3p) \
  awk '{ gsub("__ADMIN_HASH__", ENVIRON["ADMIN_HASH"]);
         gsub("__KIBANASERVER_HASH__", ENVIRON["KIBANASERVER_HASH"]);
         gsub("__REEFED_API_HASH__", ENVIRON["REEFED_API_HASH"]); print }' \
    config/wazuh_indexer/internal_users.yml.template > "$USERS_FILE"
  chmod 644 "$USERS_FILE"
fi

# ---------------------------------------------------------------------------
# 4. Certificados TLS (ferramenta oficial do Wazuh, rodando na imagem do manager)
if [ ! -f "$CERT_DIR/root-ca.pem" ] || [ "$REDO_CERTS" = yes ]; then
  info "gerando certificados em $CERT_DIR"
  if [ -d "$CERT_DIR" ]; then
    docker run --rm -v "$PWD/$CERT_DIR:/certificates" --entrypoint bash "$MANAGER_IMAGE" \
      -c 'chmod -R u+w /certificates; rm -f /certificates/*' >/dev/null
  fi
  mkdir -p "$CERT_DIR"
  docker run --rm --entrypoint cat "$INDEXER_IMAGE" \
      /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-certs-tool.sh |
    docker run --rm -i -v "$PWD/config/certs.yml:/reefed/certs.yml:ro" -v "$PWD/$CERT_DIR:/certificates" \
      --entrypoint bash "$MANAGER_IMAGE" -c '
        set -e
        mkdir -p /tmp/certs
        cat > /tmp/certs/wazuh-certs-tool.sh
        cp /reefed/certs.yml /tmp/certs/config.yml
        cd /tmp/certs
        bash wazuh-certs-tool.sh -A > /dev/null
        cp /tmp/certs/wazuh-certificates/* /certificates/
        cp /certificates/root-ca.pem /certificates/root-ca-manager.pem
        chmod 500 /certificates
        chmod 400 /certificates/*
        chown 1000:1000 /certificates/*
        chown 999:999 /certificates/root-ca-manager.pem /certificates/wazuh.manager.pem /certificates/wazuh.manager-key.pem'
  [ -n "$(docker run --rm -v "$PWD/$CERT_DIR:/certificates:ro" --entrypoint ls "$MANAGER_IMAGE" /certificates/wazuh.indexer.pem 2>/dev/null)" ] \
    || fail "não consegui gerar os certificados"
fi

if [ "${1:-}" = --users ]; then
  info "usuários refeitos. O indexer só lê o arquivo na primeira subida; com o Reefed"
  info "no ar, aplique as senhas com: make passwords   (ou scripts/apply-passwords.sh)"
  exit 0
fi

info "pronto. Próximo passo:"
info "  make up     # sobe manager, indexer, dashboard e API do Reefed e espera ficar pronto"
info "  (sem o make: docker compose up -d --build e depois scripts/status.sh)"
