// Sidecar HTTP interno pra carteira Spark dedicada do BTCfaucet.
//
// Por quê existe: não há SDK Python oficial da Spark, só @buildonspark/spark-sdk
// (JS/TS). O main.py (FastAPI) fala com este processo por HTTP em 127.0.0.1,
// exatamente como já fala com o LNbits hoje — só troca o backend de pagamento.
//
// Segurança:
// - Bind só em 127.0.0.1 (nunca exposto externamente, nem pelo nginx).
// - Exige header X-Sidecar-Token == SPARK_SIDECAR_TOKEN (.env) — defesa extra
//   caso algum outro processo no mesmo host tente falar com a porta.
// - A mnemonic/passphrase da carteira nunca saem daqui; os endpoints só
//   devolvem resultado de operação (status, preimage, saldo), nunca segredo.
//
// Idempotência: /pay recebe um claim_id e deriva um transferId determinístico
// (UUIDv5) a partir dele. Se o main.py retentar a mesma chamada (timeout,
// cancelamento, restart), o SDK reenvia o MESMO transferId — o backend da
// Spark reconhece a duplicata e não paga duas vezes. Resolve a mesma classe
// de bug do double-claim que corrigimos no lado do LNbits, só que na raiz.

import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import dotenv from 'dotenv';
import bip39 from 'bip39';
import { UUID } from 'uuidv7';

// Lê o MESMO .env do main.py (não um .env próprio) — os segredos da carteira
// só existem em um lugar. Caminho absoluto (não depende do cwd de onde o
// systemd/node é chamado).
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ENV_PATH = path.resolve(__dirname, '../../.env');
dotenv.config({ path: ENV_PATH });
const ENV_PATH_NOTE = ENV_PATH;

const MNEMONIC = process.env.SPARK_FAUCET_WALLET_MNEMONIC;
const PASSPHRASE = process.env.SPARK_FAUCET_WALLET_PASSPHRASE || '';
const SIDECAR_TOKEN = process.env.SPARK_SIDECAR_TOKEN;
const PORT = Number(process.env.SPARK_SIDECAR_PORT || 8791);
const HOST = '127.0.0.1'; // NUNCA mudar pra 0.0.0.0 — carteira com fundos reais.

if (!MNEMONIC) {
  throw new Error(`SPARK_FAUCET_WALLET_MNEMONIC ausente (${ENV_PATH_NOTE})`);
}
if (!SIDECAR_TOKEN) {
  throw new Error('SPARK_SIDECAR_TOKEN ausente — gere com: openssl rand -hex 32');
}

// UUIDv5 determinístico (RFC 4122) a partir de claim_id — sem depender do
// pacote `uuid`, só crypto nativo. Namespace fixo e privado deste projeto.
const NAMESPACE = 'a17f0b1e-6b8b-4e27-9f0a-btcfaucet-spark-sidecar';
function transferIdForClaim(claimId) {
  const hash = createHash('sha1').update(NAMESPACE).update(String(claimId)).digest();
  hash[6] = (hash[6] & 0x0f) | 0x50; // versão 5
  hash[8] = (hash[8] & 0x3f) | 0x80; // variante RFC4122
  const hex = hash.subarray(0, 16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

let wallet = null;
let walletReady = false;
let walletInitError = null;
let walletAddress = null;

async function initWallet() {
  const { SparkWallet } = await import('@buildonspark/spark-sdk');
  const seed = bip39.mnemonicToSeedSync(MNEMONIC, PASSPHRASE);
  const { wallet: w } = await SparkWallet.initialize({
    mnemonicOrSeed: seed,
    options: { network: 'MAINNET' },
  });
  wallet = w;
  walletAddress = await wallet.getSparkAddress();
  walletReady = true;
  console.log(JSON.stringify({ event: 'wallet_ready', address: walletAddress }));
}

// Consulta watch-only (SparkReadonlyClient.createPublic) — só o endereço
// PÚBLICO da carteira, nenhuma chave envolvida. Por isso este endpoint não
// exige X-Sidecar-Token: não há nada sensível em expor o saldo de um endereço
// que já é público por natureza (qualquer client Spark consegue consultar o
// mesmo dado sem passar por aqui).
async function handleBalancePublic() {
  const { SparkReadonlyClient } = await import('@buildonspark/spark-sdk');
  const client = SparkReadonlyClient.createPublic({ network: 'MAINNET' });
  const sats = await client.getAvailableBalance(walletAddress);
  return { address: walletAddress, balance_sats: Number(sats) };
}

// Status LightningSendRequestStatus que contam como sucesso definitivo.
const SUCCESS_STATUSES = new Set(['LIGHTNING_PAYMENT_SUCCEEDED', 'PREIMAGE_PROVIDED', 'TRANSFER_COMPLETED']);
// Status que contam como falha definitiva (seguro tentar de novo com claim_id novo).
const FAILURE_STATUSES = new Set([
  'USER_TRANSFER_VALIDATION_FAILED', 'LIGHTNING_PAYMENT_FAILED',
  'PREIMAGE_PROVIDING_FAILED', 'TRANSFER_FAILED', 'USER_SWAP_RETURN_FAILED',
]);
// Qualquer outro status (CREATED, LIGHTNING_PAYMENT_INITIATED, PENDING_USER_SWAP_RETURN,
// USER_SWAP_RETURNED, REQUEST_VALIDATED, FUTURE_VALUE) = incerto — tratar como
// 'pending' (orphan no main.py), nunca como failed.

// CurrencyAmount.originalValue vem na unidade de CurrencyAmount.originalUnit
// (SATOSHI ou MILLISATOSHI, geralmente) — [FIX] presumir sats direto deu um
// fee_sats 1000x maior que o real (3000 ao invés de 3), confirmado comparando
// com a queda de saldo observada num pagamento de teste real.
function toSats(currencyAmount) {
  if (!currencyAmount || typeof currencyAmount.originalValue !== 'number') return null;
  const { originalValue, originalUnit } = currencyAmount;
  if (originalUnit === 'MILLISATOSHI') return originalValue / 1000;
  if (originalUnit === 'SATOSHI') return originalValue;
  if (originalUnit === 'BITCOIN') return originalValue * 100_000_000;
  return null; // moeda fiat (USD/MXN/...) ou unidade desconhecida — não converte
}

function classifyResult(result) {
  // WalletTransfer (pagamento resolvido internamente via Spark, sem passar
  // pela rede Lightning) não tem o enum LightningSendRequestStatus — a
  // própria promise só resolve nesse formato quando o transfer já completou.
  if (!result || typeof result.status !== 'string') {
    return { status: 'paid', preimage: result?.preimage ?? null, fee_sats: null, request_id: result?.id ?? null };
  }
  if (SUCCESS_STATUSES.has(result.status)) {
    // [FIX] O preimage vem em LightningSendRequest.paymentPreimage — testei
    // result.transfer?.preimage antes (campo errado, sempre veio null nos
    // dois pagamentos reais de teste).
    return { status: 'paid', preimage: result.paymentPreimage ?? null, fee_sats: toSats(result.fee), request_id: result.id };
  }
  if (FAILURE_STATUSES.has(result.status)) {
    return { status: 'failed', reason: result.status, request_id: result.id };
  }
  return { status: 'pending', reason: result.status, request_id: result.id };
}

// [FIX] Observado em produção: depois de rodar um tempo, uma chamada à
// wallet (createLightningInvoice) travou indefinidamente — nunca resolveu
// nem rejeitou, sem log nenhum da SDK, até o timeout de 15s do main.py
// estourar (httpx.TimeoutException tem str() vazio, então nem o log do lado
// Python mostrava a causa). Provável conexão interna (streaming/gRPC) da SDK
// que ficou obsoleta sem reconectar. Isso NÃO cancela a chamada de verdade
// (a Promise original continua rodando) — só evita que o handler HTTP fique
// pendurado pra sempre; se acontecer, os logs abaixo dizem claramente que o
// sidecar precisa ser reiniciado, em vez de falhar silencioso feito antes.
function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label}: sem resposta em ${ms}ms — sidecar pode precisar de restart`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function handleInvoice(body) {
  const { amount_sats, description_hash, memo, expiry_seconds } = body;
  if (!amount_sats || Number(amount_sats) < 1) {
    return { httpStatus: 400, body: { error: 'amount_sats obrigatório e >= 1' } };
  }
  if (description_hash && memo) {
    return { httpStatus: 400, body: { error: 'description_hash e memo são mutuamente exclusivos' } };
  }
  try {
    const result = await withTimeout(wallet.createLightningInvoice({
      amountSats: Number(amount_sats),
      ...(description_hash ? { descriptionHash: description_hash } : {}),
      ...(memo ? { memo } : {}),
      ...(expiry_seconds ? { expirySeconds: Number(expiry_seconds) } : {}),
    }), 12_000, 'createLightningInvoice');
    return {
      httpStatus: 200,
      body: {
        bolt11: result.invoice.encodedInvoice,
        payment_hash: result.invoice.paymentHash,
        expires_at: result.invoice.expiresAt,
      },
    };
  } catch (err) {
    console.error(JSON.stringify({ event: 'invoice_error', error: String(err?.message || err) }));
    return { httpStatus: 502, body: { error: String(err?.message || err) } };
  }
}

async function handleTransfer(body) {
  // Transferência Spark-nativa (spark1... -> spark1...), sem passar pela rede
  // Lightning — sem fee de roteamento, mas também sem o parâmetro transferId
  // idempotente que o payLightningInvoice tem. Uso manual/pontual por ora,
  // main.py não chama isto (o faucet só paga LN Address hoje).
  const { receiver_spark_address, amount_sats } = body;
  if (!receiver_spark_address || !amount_sats || Number(amount_sats) < 1) {
    return { httpStatus: 400, body: { error: 'receiver_spark_address e amount_sats (>=1) são obrigatórios' } };
  }
  try {
    const result = await withTimeout(wallet.transfer({
      receiverSparkAddress: receiver_spark_address,
      amountSats: Number(amount_sats),
    }), 15_000, 'transfer');
    console.log(JSON.stringify({ event: 'transfer_result', receiver_spark_address, amount_sats, id: result?.id }));
    return { httpStatus: 200, body: { status: 'paid', transfer_id: result?.id ?? null } };
  } catch (err) {
    console.error(JSON.stringify({ event: 'transfer_error', receiver_spark_address, amount_sats, error: String(err?.message || err) }));
    return { httpStatus: 502, body: { status: 'unknown', error: String(err?.message || err) } };
  }
}

async function handlePay(body) {
  const { claim_id, invoice, max_fee_sats, amount_sats_to_send } = body;
  if (!claim_id || !invoice || !max_fee_sats) {
    return { httpStatus: 400, body: { error: 'claim_id, invoice e max_fee_sats são obrigatórios' } };
  }
  const transferId = transferIdForClaim(claim_id);
  try {
    // [FIX] payLightningInvoice exige uma INSTÂNCIA de UUID (checa
    // `instanceof`, não formato de string) — passar a string crua falha com
    // "Transfer ID must be a UUID" mesmo sendo um UUID sintaticamente válido.
    // A classe vem do pacote uuidv7 (dependência do próprio spark-sdk).
    // Timeout generoso (45s): pagamentos legítimos podem levar um tempo
    // (routing real). Um timeout aqui cai no catch abaixo, que já trata
    // como 'pending' — seguro, nunca marca como failed indevidamente.
    const payParams = {
      invoice,
      maxFeeSats: Number(max_fee_sats),
      transferId: UUID.parse(transferId),
      ...(amount_sats_to_send ? { amountSatsToSend: Number(amount_sats_to_send) } : {}),
    };
    let result = await withTimeout(wallet.payLightningInvoice(payParams), 20_000, 'payLightningInvoice');
    let classified = classifyResult(result);

    // [FIX] payLightningInvoice frequentemente resolve a Promise ainda em
    // LIGHTNING_PAYMENT_INITIATED (não terminal) — sem isto, o main.py via
    // isso como incerto e marcava 'orphan'/503 pro usuário mesmo quando o
    // pagamento confirmava poucos segundos depois (visto em produção:
    // dinheiro saiu certo, mas o site mostrou "serviço indisponível").
    // Reconsulta com o MESMO transferId (idempotente — nunca reenvia) até
    // sair de 'pending' ou esgotar o orçamento de tempo. Orçado pra caber
    // dentro do timeout de 90s que o main.py dá pra chamada HTTP inteira.
    for (let attempt = 0; classified.status === 'pending' && attempt < 5; attempt++) {
      await new Promise((r) => setTimeout(r, 2_000));
      result = await withTimeout(wallet.payLightningInvoice(payParams), 8_000, 'payLightningInvoice (poll)');
      classified = classifyResult(result);
    }

    console.log(JSON.stringify({ event: 'pay_result', claim_id, transferId, ...classified }));
    return { httpStatus: 200, body: { transfer_id: transferId, ...classified } };
  } catch (err) {
    // Erro na chamada (rede, cancelamento, etc.) NÃO prova que o pagamento
    // falhou — o transferId é idempotente, então a única ação seguindo é
    // reportar 'pending' e deixar o main.py decidir retentar (mesma
    // claim_id -> mesmo transferId -> SDK/backend dedup) ou aguardar.
    console.error(JSON.stringify({ event: 'pay_error', claim_id, transferId, error: String(err?.message || err) }));
    return { httpStatus: 200, body: { transfer_id: transferId, status: 'pending', reason: String(err?.message || err) } };
  }
}

const server = createServer(async (req, res) => {
  const send = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  };

  if (req.url === '/health' && req.method === 'GET') {
    return send(200, { ok: true, wallet_ready: walletReady, wallet_init_error: walletInitError });
  }

  // Sem auth — watch-only via endereço público, nada sensível.
  if (req.url === '/balance-public' && req.method === 'GET') {
    if (!walletReady) return send(503, { error: 'wallet não inicializada' });
    try {
      return send(200, await handleBalancePublic());
    } catch (err) {
      return send(502, { error: String(err?.message || err) });
    }
  }

  const token = req.headers['x-sidecar-token'];
  if (token !== SIDECAR_TOKEN) {
    return send(401, { error: 'unauthorized' });
  }
  if (!walletReady) {
    return send(503, { error: 'wallet não inicializada', detail: walletInitError });
  }

  if (req.url === '/balance' && req.method === 'GET') {
    try {
      const balance = await wallet.getBalance();
      const sats = Number(balance?.satsBalance?.available ?? balance?.balance ?? 0);
      return send(200, { balance_sats: sats });
    } catch (err) {
      return send(502, { error: String(err?.message || err) });
    }
  }

  if (req.url === '/pay' && req.method === 'POST') {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', async () => {
      let body;
      try {
        body = JSON.parse(raw);
      } catch {
        return send(400, { error: 'JSON inválido' });
      }
      const result = await handlePay(body);
      return send(result.httpStatus, result.body);
    });
    return;
  }

  if (req.url === '/invoice' && req.method === 'POST') {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', async () => {
      let body;
      try {
        body = JSON.parse(raw);
      } catch {
        return send(400, { error: 'JSON inválido' });
      }
      const result = await handleInvoice(body);
      return send(result.httpStatus, result.body);
    });
    return;
  }

  if (req.url === '/transfer' && req.method === 'POST') {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', async () => {
      let body;
      try {
        body = JSON.parse(raw);
      } catch {
        return send(400, { error: 'JSON inválido' });
      }
      const result = await handleTransfer(body);
      return send(result.httpStatus, result.body);
    });
    return;
  }

  return send(404, { error: 'not found' });
});

// [FIX] Causa raiz do travamento (2026-09-14, ver SESSAO_BTCFAUCET_...): a
// conexão interna da SDK (streaming/gRPC) morre depois de alguns minutos
// ociosa — sem keep-alive nem timeout próprio, a chamada seguinte trava pra
// sempre em vez de reconectar ou falhar. withTimeout() só evita o handler
// HTTP ficar pendurado; isto aqui é a correção de verdade: uma operação leve
// periódica que ou (a) mantém a conexão viva de fato, ou (b) detecta que
// travou e reinicia o PRÓPRIO processo — o systemd (Restart=on-failure)
// reergue sozinho em segundos, sem precisar de intervenção manual.
function startHeartbeat() {
  setInterval(async () => {
    if (!walletReady) return;
    try {
      await withTimeout(wallet.getBalance(), 8_000, 'heartbeat');
    } catch (err) {
      console.error(JSON.stringify({ event: 'heartbeat_failed_restarting', error: String(err?.message || err) }));
      process.exit(1);
    }
  }, 60_000);
}

initWallet()
  .then(() => {
    server.listen(PORT, HOST, () => {
      console.log(JSON.stringify({ event: 'listening', host: HOST, port: PORT }));
    });
    startHeartbeat();
  })
  .catch((err) => {
    walletInitError = String(err?.message || err);
    console.error(JSON.stringify({ event: 'wallet_init_failed', error: walletInitError }));
    // Sobe o servidor mesmo assim (só /health responde) pra facilitar diagnóstico
    // via systemd/monitor, em vez do processo simplesmente morrer sem log claro.
    server.listen(PORT, HOST, () => {
      console.log(JSON.stringify({ event: 'listening_degraded', host: HOST, port: PORT }));
    });
  });

process.on('SIGTERM', () => { server.close(() => process.exit(0)); });
process.on('SIGINT', () => { server.close(() => process.exit(0)); });
