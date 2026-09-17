#!/bin/bash
# Healthcheck horário do spark-sidecar (systemd timer spark-sidecar-healthcheck.timer).
# "Offline" = não responde, ou responde mas com wallet_ready=false (o estado
# degradado visto em 2026-09-16: processo de pé, mas incapaz de gerar/pagar
# invoice — ver SESSAO do dia). Se offline, reinicia o serviço.
#
# Antes de reiniciar, espera terminar qualquer operação em andamento (/pay,
# /invoice, /transfer — contador in_flight exposto pelo próprio sidecar em
# /health) pra não abortar um pagamento real de usuário no meio. Como as
# rotas de carteira só processam com wallet_ready=true, in_flight só importa
# quando o healthcheck falha por timeout/travamento com a wallet ainda OK.
set -uo pipefail

HEALTH_URL="http://127.0.0.1:8791/health"
LOG_FILE="/home/felipe/Bots/BTCfaucet/spark_sidecar_healthcheck.log"
CURL_TIMEOUT_S=5
MAX_WAIT_S=600
POLL_INTERVAL_S=5

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S %z') $1" >> "$LOG_FILE"
}

check_health() {
    curl -sf -m "$CURL_TIMEOUT_S" "$HEALTH_URL" 2>/dev/null
}

resp="$(check_health)"
if [ -n "$resp" ] && [ "$(echo "$resp" | jq -r '.ok // false')" = "true" ] && [ "$(echo "$resp" | jq -r '.wallet_ready // false')" = "true" ]; then
    log "OK ($resp)"
    exit 0
fi

log "OFFLINE/degradado ($resp) — verificando interação em andamento antes de reiniciar."

waited=0
while [ "$waited" -lt "$MAX_WAIT_S" ]; do
    resp="$(check_health)"
    in_flight="$(echo "$resp" | jq -r '.in_flight // 0' 2>/dev/null)"
    case "$in_flight" in
        ''|*[!0-9]*) in_flight=0 ;;
    esac
    if [ "$in_flight" -eq 0 ]; then
        break
    fi
    log "Interação em andamento (in_flight=$in_flight) — aguardando ${POLL_INTERVAL_S}s."
    sleep "$POLL_INTERVAL_S"
    waited=$((waited + POLL_INTERVAL_S))
done
if [ "$waited" -ge "$MAX_WAIT_S" ]; then
    log "Limite de espera (${MAX_WAIT_S}s) atingido com interação ainda em andamento — reiniciando mesmo assim."
fi

log "Reiniciando spark-sidecar."
/usr/bin/systemctl restart spark-sidecar
sleep 8
resp="$(check_health)"
log "Pós-restart: $resp"
