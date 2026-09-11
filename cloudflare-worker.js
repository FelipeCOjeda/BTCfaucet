/**
 * Cloudflare Worker — bitcoinfaucet.st
 *
 * O que faz:
 * 1. Bloqueia prefixos IPv6 de VPN/bot farm conhecidos
 * 2. Injeta CF-JA3-Hash no header para o backend rastrear cliente TLS
 * 3. Passa CF-Connecting-IP corretamente
 *
 * Deploy:
 *   1. Cloudflare Dashboard → Workers & Pages → Create Worker
 *   2. Cole este código
 *   3. Em Settings → Triggers → adicione a rota: bitcoinfaucet.st/*
 */

// ── Prefixos IPv6 bloqueados ──────────────────────────────────────────────────
const BLOCKED_IPV6_PREFIXES = [
  "2a09:bac1",   // PureVPN / HostPalm
  "2a09:bac5",   // PureVPN / HostPalm
  "2804:18",     // Claro BR — bot farm miner0x
];

// ── Países bloqueados (já deve estar no WAF, mas segunda camada) ──────────────
const BLOCKED_COUNTRIES = ["BD", "ID", "PK", "NG", "VN", "KH", "MM"];

// ── Rotas que aplicam verificação anti-abuse ──────────────────────────────────
const PROTECTED_PATHS = ["/api/claim", "/api/check"];

function isIPv6PrefixBlocked(ip) {
  if (!ip || !ip.includes(":")) return false;
  return BLOCKED_IPV6_PREFIXES.some(prefix =>
    ip.toLowerCase().startsWith(prefix.toLowerCase())
  );
}

function isCountryBlocked(country) {
  if (!country) return false;
  return BLOCKED_COUNTRIES.includes(country.toUpperCase());
}

export default {
  async fetch(request, env, ctx) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const ip     = request.headers.get("CF-Connecting-IP") || "";
    const country = request.cf?.country || "";
    // NUNCA usar request.headers.get("CF-JA3") como fallback — é o header como o
    // cliente mandou, então é forjável (qualquer um manda "CF-JA3: <qualquer coisa>"
    // e o valor passaria confiável pro backend). A única fonte confiável é o campo
    // nativo do Cloudflare abaixo (não vem do request, é metadata da conexão TLS
    // resolvida pelo edge — indisponível em planos sem Bot Management/TLS Fingerprinting,
    // nesse caso ja3 fica vazio mesmo, o que é o comportamento seguro).
    const ja3    = request.cf?.tlsClientHello?.ja3 || "";

    // ── Verificações apenas nas rotas protegidas ──────────────────────────────
    if (PROTECTED_PATHS.some(p => path.startsWith(p))) {

      // Bloquear IPv6 de VPN/bot farm
      if (isIPv6PrefixBlocked(ip)) {
        return new Response(
          JSON.stringify({ detail: "Acesso bloqueado." }),
          {
            status: 403,
            headers: { "Content-Type": "application/json" }
          }
        );
      }

      // Bloquear países na lista
      if (isCountryBlocked(country)) {
        return new Response(
          JSON.stringify({ detail: "Service not available in your region." }),
          {
            status: 403,
            headers: { "Content-Type": "application/json" }
          }
        );
      }
    }

    // ── Injetar headers para o backend ────────────────────────────────────────
    const newHeaders = new Headers(request.headers);

    // Sempre limpar primeiro qualquer CF-JA3/CF-JA3-Hash que o CLIENTE tenha mandado
    // — sem isso, quando `ja3` está vazio (plano sem Bot Management) o header forjado
    // do cliente passaria intocado pro backend, já que newHeaders começa como cópia
    // do request original.
    newHeaders.delete("CF-JA3-Hash");
    newHeaders.delete("CF-JA3");

    // JA3 hash (TLS fingerprint) — backend usa para rastrear cliente. Só setado
    // quando vem de fonte confiável (request.cf.tlsClientHello, nunca de header).
    if (ja3) {
      newHeaders.set("CF-JA3-Hash", ja3);
    }

    // Garantir que CF-Connecting-IP está presente
    if (ip) {
      newHeaders.set("CF-Connecting-IP", ip);
    }

    // País do visitante (útil para logs)
    if (country) {
      newHeaders.set("CF-IPCountry", country);
    }

    // ASN (útil para análise)
    const asn = request.cf?.asn;
    if (asn) {
      newHeaders.set("CF-ASN", String(asn));
    }

    // ── Passar request para o origin ─────────────────────────────────────────
    const modifiedRequest = new Request(request, { headers: newHeaders });
    return fetch(modifiedRequest);
  }
};
