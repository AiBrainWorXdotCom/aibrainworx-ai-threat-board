/**
 * Frontend OPSEC, indicator defanging, display redaction, and client-side
 * Markdown sanitization utilities (defense-in-depth alongside backend guards).
 */

const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;

export function defangIp(ip: string): string {
  const trimmed = ip.trim();
  if (!trimmed) return '';
  if (trimmed.includes(':')) {
    return trimmed.replace(/:/g, '[:]');
  }
  const lastDot = trimmed.lastIndexOf('.');
  if (lastDot > 0) {
    return `${trimmed.slice(0, lastDot)}[.]${trimmed.slice(lastDot + 1)}`;
  }
  return trimmed.replace(/\./g, '[.]');
}

export function defangUrl(rawUrl: string): string {
  const trimmed = rawUrl.trim();
  if (!trimmed) return '';
  let prefix = '';
  let rest = trimmed;
  if (/^https:\/\//i.test(trimmed)) {
    prefix = 'hxxps://';
    rest = trimmed.slice(8);
  } else if (/^http:\/\//i.test(trimmed)) {
    prefix = 'hxxp://';
    rest = trimmed.slice(7);
  }
  const slashIdx = rest.indexOf('/');
  if (slashIdx >= 0) {
    const host = rest.slice(0, slashIdx).replace(/\./g, '[.]');
    return `${prefix}${host}${rest.slice(slashIdx)}`;
  }
  return `${prefix}${rest.replace(/\./g, '[.]')}`;
}

export function redactIp(ip: string): string {
  const trimmed = ip.trim();
  if (!trimmed) return '[REDACTED-IP]';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
    const parts = trimmed.split('.');
    return `${parts[0]}.${parts[1]}.xxx.xxx`;
  }
  if (trimmed.includes(':')) {
    const parts = trimmed.split(':').filter(Boolean);
    return `${parts[0] || 'xxxx'}:${parts[1] || 'xxxx'}:xxxx::xxxx`;
  }
  return '[REDACTED-IP]';
}

export function redactHostname(host: string): string {
  const trimmed = host.trim();
  if (!trimmed) return '';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed) || trimmed.includes(':')) {
    return redactIp(trimmed);
  }
  const dot = trimmed.indexOf('.');
  if (dot > 1) {
    return `••••${trimmed.slice(dot)}`;
  }
  return '••••';
}

export function redactUrl(rawUrl: string, opsec: boolean): string {
  if (!opsec) return rawUrl;
  try {
    const u = new URL(rawUrl);
    const scheme = u.protocol === 'https:' ? 'hxxps:' : u.protocol === 'http:' ? 'hxxp:' : u.protocol;
    return `${scheme}//${redactHostname(u.hostname)}/•••`;
  } catch {
    return defangUrl(rawUrl).replace(IPV4_REGEX, (m) => redactIp(m));
  }
}

export function redactDisplayText(text: string, opsec: boolean): string {
  if (!opsec || !text) return text;
  let out = text.replace(IPV4_REGEX, (m) => redactIp(m));
  // Redact long high-entropy / explicit DNS hostnames in suspicious query callouts
  out = out.replace(
    /(Suspicious DNS query:\s*)([a-z0-9._-]+\.[a-z]{2,})/gi,
    (_m, prefix: string, host: string) => `${prefix}${redactHostname(host)}`
  );
  return out;
}

export function redactWiresharkFilter(filter: string, opsec: boolean): string {
  if (!opsec || !filter) return filter;
  let out = filter.replace(IPV4_REGEX, (m) => redactIp(m));
  out = out.replace(/"([^"]+)"/g, (_m, inner: string) => `"${redactHostname(inner)}"`);
  return out;
}

function isSafeMarkdownTarget(rawTarget: string): boolean {
  const first = rawTarget.trim().split(/\s+/)[0] ?? '';
  const unwrapped = first.startsWith('<') && first.endsWith('>') ? first.slice(1, -1).trim() : first;
  if (!unwrapped) return false;
  const lower = unwrapped.toLowerCase();
  if (lower.includes('&#') || lower.includes('&colon;') || lower.startsWith('//')) {
    return false;
  }
  return (
    lower.startsWith('https://') ||
    lower.startsWith('http://') ||
    lower.startsWith('#') ||
    lower.startsWith('/')
  );
}

/**
 * Strips all raw HTML tags, inline & reference Markdown images (`![alt](url)`, `![alt][ref]`),
 * invisible Unicode controls/bidi overrides, and dangerous URI schemes (`javascript:`, `data:`,
 * entity-encoded or reference-defined links).
 */
export function sanitizeMarkdownClient(md: string): string {
  if (!md) return '';
  // Remove invisible zero-width / bidi characters / C0-C1 controls
  // eslint-disable-next-line no-control-regex
  let out = md.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060-\u2069\u061C\uFEFF]/g, '');
  // Strip script/style/iframe/svg/object/embed blocks and ALL raw HTML tags
  out = out.replace(/<(script|style|iframe|object|embed|svg)\b[^>]*>[\s\S]*?<\/\1>/gi, '');
  out = out.replace(/<\/?[a-z][a-z0-9:-]*(?:\s+[^<>]*)?\/?>/gi, '');
  // Neutralize inline AND reference-style Markdown remote image tracking pixels
  out = out.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, (_m, alt: string) => {
    const cleanAlt = (alt || '').trim();
    return cleanAlt ? `[image blocked: ${cleanAlt}]` : '[external image blocked]';
  });
  out = out.replace(/!\[([^\]]*)\]\[[^\]]*\]/g, (_m, alt: string) => {
    const cleanAlt = (alt || '').trim();
    return cleanAlt ? `[image blocked: ${cleanAlt}]` : '[external image blocked]';
  });
  // Neutralize dangerous inline link schemes while preserving safe http(s)/relative links
  out = out.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (full, label: string, target: string) => {
    if (isSafeMarkdownTarget(target)) {
      return full;
    }
    return `${label} (unsafe-link-removed)`;
  });
  // Neutralize dangerous reference-style link definitions (`[1]: javascript:alert(1)`)
  out = out.replace(/^[ \t]{0,3}\[([^\]]+)\]:[ \t]*(\S+)(.*)$/gm, (full, id: string, target: string) => {
    if (isSafeMarkdownTarget(target)) {
      return full;
    }
    return `[${id}]: #unsafe-link-removed`;
  });
  return out;
}

export function downloadTextFile(filename: string, content: string, mime = 'text/plain;charset=utf-8'): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
