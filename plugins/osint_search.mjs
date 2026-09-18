import https from 'https';
import http from 'http';

export const declaration = {
  name: 'osint_search',
  description: 'Reconnaissance & OSINT investigation tool: Scans social media username footprints across 20+ platforms (GitHub, Reddit, Twitter/X, Telegram, TikTok, etc.) and analyzes phone numbers (E.164 normalization, telecom carrier prefix detection, country code, and OSINT dork generation).',
  parameters: {
    type: 'OBJECT',
    properties: {
      target: {
        type: 'STRING',
        description: 'Target username handle (e.g. "octocat") or phone number with/without country code (e.g. "+628123456789", "08123456789")'
      },
      type: {
        type: 'STRING',
        description: 'Search mode: "auto", "username", or "phone" (default: "auto")'
      },
      timeoutMs: {
        type: 'INTEGER',
        description: 'HTTP request timeout in milliseconds for username network probes (default: 3500)'
      }
    },
    required: ['target']
  }
};

// ── Social Media & Developer Platforms Registry ─────────────────────────────────
const PLATFORMS = [
  { name: 'GitHub',        url: 'https://github.com/{}',              checkType: 'status_200' },
  { name: 'GitLab',        url: 'https://gitlab.com/{}',              checkType: 'status_200' },
  { name: 'Reddit',        url: 'https://www.reddit.com/user/{}/',    checkType: 'status_200' },
  { name: 'Twitter/X',     url: 'https://x.com/{}',                   checkType: 'status_200' },
  { name: 'Instagram',     url: 'https://www.instagram.com/{}/',      checkType: 'status_200' },
  { name: 'TikTok',        url: 'https://www.tiktok.com/@{}',         checkType: 'status_200' },
  { name: 'Telegram',      url: 'https://t.me/{}',                    checkType: 'status_200' },
  { name: 'Pinterest',     url: 'https://www.pinterest.com/{}/',      checkType: 'status_200' },
  { name: 'Medium',        url: 'https://medium.com/@{}',             checkType: 'status_200' },
  { name: 'Dev.to',        url: 'https://dev.to/{}',                  checkType: 'status_200' },
  { name: 'Twitch',        url: 'https://www.twitch.tv/{}',           checkType: 'status_200' },
  { name: 'YouTube',       url: 'https://www.youtube.com/@{}',        checkType: 'status_200' },
  { name: 'Spotify',       url: 'https://open.spotify.com/user/{}',   checkType: 'status_200' },
  { name: 'Steam',         url: 'https://steamcommunity.com/id/{}',   checkType: 'status_200' },
  { name: 'HackerNews',    url: 'https://news.ycombinator.com/user?id={}', checkType: 'status_200' },
  { name: 'Linktree',      url: 'https://linktr.ee/{}',               checkType: 'status_200' },
  { name: 'Substack',      url: 'https://{}.substack.com',            checkType: 'status_200' },
  { name: 'Dribbble',      url: 'https://dribbble.com/{}',            checkType: 'status_200' },
  { name: 'Behance',       url: 'https://www.behance.net/{}',         checkType: 'status_200' },
  { name: 'Keybase',       url: 'https://keybase.io/{}',              checkType: 'status_200' },
  { name: 'DockerHub',     url: 'https://hub.docker.com/u/{}',        checkType: 'status_200' },
  { name: 'npm',           url: 'https://www.npmjs.com/~{}',          checkType: 'status_200' },
  { name: 'Disqus',        url: 'https://disqus.com/by/{}/',          checkType: 'status_200' }
];

// ── Country Dial Codes Dictionary ──────────────────────────────────────────────
const COUNTRY_CODES = [
  { prefix: '+62',  iso: 'ID', country: 'Indonesia', flag: '🇮🇩' },
  { prefix: '+1',   iso: 'US/CA', country: 'United States / Canada', flag: '🇺🇸' },
  { prefix: '+44',  iso: 'GB', country: 'United Kingdom', flag: '🇬🇧' },
  { prefix: '+60',  iso: 'MY', country: 'Malaysia', flag: '🇲🇾' },
  { prefix: '+65',  iso: 'SG', country: 'Singapore', flag: '🇸🇬' },
  { prefix: '+61',  iso: 'AU', country: 'Australia', flag: '🇦🇺' },
  { prefix: '+81',  iso: 'JP', country: 'Japan', flag: '🇯🇵' },
  { prefix: '+82',  iso: 'KR', country: 'South Korea', flag: '🇰🇷' },
  { prefix: '+91',  iso: 'IN', country: 'India', flag: '🇮🇳' },
  { prefix: '+49',  iso: 'DE', country: 'Germany', flag: '🇩🇪' },
  { prefix: '+33',  iso: 'FR', country: 'France', flag: '🇫🇷' },
  { prefix: '+7',   iso: 'RU/KZ', country: 'Russia / Kazakhstan', flag: '🇷🇺' },
  { prefix: '+86',  iso: 'CN', country: 'China', flag: '🇨🇳' },
  { prefix: '+971', iso: 'AE', country: 'United Arab Emirates', flag: '🇦🇪' },
  { prefix: '+966', iso: 'SA', country: 'Saudi Arabia', flag: '🇸🇦' },
  { prefix: '+55',  iso: 'BR', country: 'Brazil', flag: '🇧🇷' },
  { prefix: '+84',  iso: 'VN', country: 'Vietnam', flag: '🇻🇳' },
  { prefix: '+66',  iso: 'TH', country: 'Thailand', flag: '🇹🇭' },
  { prefix: '+63',  iso: 'PH', country: 'Philippines', flag: '🇵🇭' }
];

// ── Indonesian Telecom Carrier Prefixes ─────────────────────────────────────────
const INDONESIA_CARRIERS = [
  { prefixes: ['0811', '0812', '0813', '0821', '0822', '0823', '0851', '0852', '0853'], carrier: 'Telkomsel (Halo / SimPATI / By.U)' },
  { prefixes: ['0814', '0815', '0816', '0855', '0856', '0857', '0858'], carrier: 'Indosat Ooredoo Hutchison (IM3 / Mentari)' },
  { prefixes: ['0817', '0818', '0819', '0859', '0877', '0878'], carrier: 'XL Axiata (XL)' },
  { prefixes: ['0831', '0832', '0833', '0838'], carrier: 'XL Axiata (Axis)' },
  { prefixes: ['0895', '0896', '0897', '0898', '0899'], carrier: 'Indosat Ooredoo Hutchison (Tri / 3)' },
  { prefixes: ['0881', '0882', '0883', '0884', '0885', '0886', '0887', '0888', '0889'], carrier: 'Smartfren' }
];

/**
 * Fast HTTP status probe with timeout and redirection handling
 */
function probeUrl(targetUrl, timeoutMs = 3500) {
  return new Promise((resolve) => {
    try {
      const urlObj = new URL(targetUrl);
      const isHttps = urlObj.protocol === 'https:';
      const client = isHttps ? https : http;

      const req = client.request(
        urlObj,
        {
          method: 'GET',
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache'
          },
          timeout: timeoutMs
        },
        (res) => {
          const statusCode = res.statusCode;
          // Consume stream to free socket
          res.resume();

          if (statusCode >= 200 && statusCode < 300) {
            resolve({ exists: true, status: statusCode, error: null });
          } else if (statusCode === 404) {
            resolve({ exists: false, status: statusCode, error: null });
          } else if (statusCode === 403 || statusCode === 429) {
            resolve({ exists: 'UNKNOWN_RATE_LIMITED', status: statusCode, error: 'Rate Limited / WAF Protected' });
          } else if (statusCode >= 300 && statusCode < 400) {
            // Redirect may mean found or moved
            resolve({ exists: true, status: statusCode, error: null, redirect: res.headers.location });
          } else {
            resolve({ exists: false, status: statusCode, error: `HTTP ${statusCode}` });
          }
        }
      );

      req.on('timeout', () => {
        req.destroy();
        resolve({ exists: false, status: 0, error: 'Request Timeout' });
      });

      req.on('error', (err) => {
        resolve({ exists: false, status: 0, error: err.message });
      });

      req.end();
    } catch (err) {
      resolve({ exists: false, status: 0, error: err.message });
    }
  });
}

/**
 * Perform concurrent username OSINT search
 */
async function searchUsername(username, timeoutMs = 3500) {
  const cleanUser = username.trim().replace(/^@+/, '');
  const results = [];

  // Concurrency worker limit
  const CONCURRENCY = 6;
  const queue = [...PLATFORMS];
  const activeWorkers = [];

  async function worker() {
    while (queue.length > 0) {
      const platform = queue.shift();
      if (!platform) break;

      const profileUrl = platform.url.replace('{}', encodeURIComponent(cleanUser));
      const probe = await probeUrl(profileUrl, timeoutMs);

      results.push({
        platform: platform.name,
        profileUrl,
        exists: probe.exists === true,
        statusCode: probe.status,
        statusNote: probe.exists === true ? 'FOUND' : (probe.exists === 'UNKNOWN_RATE_LIMITED' ? 'RATE_LIMITED' : 'NOT_FOUND'),
        error: probe.error
      });
    }
  }

  for (let i = 0; i < CONCURRENCY; i++) {
    activeWorkers.push(worker());
  }
  await Promise.all(activeWorkers);

  const foundProfiles = results.filter(r => r.exists === true);
  const rateLimited = results.filter(r => r.statusNote === 'RATE_LIMITED');

  return {
    query: cleanUser,
    type: 'USERNAME_OSINT',
    timestamp: new Date().toISOString(),
    totalPlatformsChecked: results.length,
    foundCount: foundProfiles.length,
    foundProfiles: foundProfiles.map(p => ({ platform: p.platform, url: p.profileUrl })),
    dorks: {
      google: `https://www.google.com/search?q="${encodeURIComponent(cleanUser)}"`,
      googleProfiles: `https://www.google.com/search?q=site:github.com+OR+site:twitter.com+OR+site:instagram.com+OR+site:linkedin.com+"${encodeURIComponent(cleanUser)}"`,
      whatsMyName: `https://whatsmyname.app/?q=${encodeURIComponent(cleanUser)}`
    },
    rawResults: results
  };
}

/**
 * Perform Phone Number OSINT and telecom lookup
 */
function searchPhone(phoneInput) {
  const raw = String(phoneInput).trim();
  const digitsOnly = raw.replace(/\D/g, '');

  let normalizedE164 = '';
  let nationalNumber = '';
  let countryMatch = null;
  let carrierMatch = 'Unknown / International Provider';

  // Normalize Indonesia local 08xx or international 628xx
  if (digitsOnly.startsWith('62')) {
    normalizedE164 = `+${digitsOnly}`;
    nationalNumber = `0${digitsOnly.slice(2)}`;
  } else if (digitsOnly.startsWith('08')) {
    normalizedE164 = `+62${digitsOnly.slice(1)}`;
    nationalNumber = digitsOnly;
  } else if (raw.startsWith('+')) {
    normalizedE164 = `+${digitsOnly}`;
    nationalNumber = digitsOnly;
  } else {
    normalizedE164 = `+${digitsOnly}`;
    nationalNumber = digitsOnly;
  }

  // Detect Country
  for (const c of COUNTRY_CODES) {
    const rawPrefixDigits = c.prefix.replace('+', '');
    if (digitsOnly.startsWith(rawPrefixDigits) || (c.iso === 'ID' && nationalNumber.startsWith('08'))) {
      countryMatch = c;
      break;
    }
  }

  // Detect Indonesian Carrier
  if (countryMatch && countryMatch.iso === 'ID') {
    const prefix4 = nationalNumber.slice(0, 4);
    for (const car of INDONESIA_CARRIERS) {
      if (car.prefixes.includes(prefix4)) {
        carrierMatch = car.carrier;
        break;
      }
    }
  }

  const cleanInternational = normalizedE164.replace(/\D/g, '');

  return {
    query: raw,
    type: 'PHONE_OSINT',
    timestamp: new Date().toISOString(),
    parsed: {
      e164Format: normalizedE164,
      nationalFormat: nationalNumber,
      digitsOnly: cleanInternational,
      digitsCount: cleanInternational.length,
      isValidLength: cleanInternational.length >= 8 && cleanInternational.length <= 15
    },
    location: {
      country: countryMatch ? countryMatch.country : 'Unknown / Global',
      isoCode: countryMatch ? countryMatch.iso : 'N/A',
      flag: countryMatch ? countryMatch.flag : '🌐',
      dialPrefix: countryMatch ? countryMatch.prefix : 'N/A'
    },
    telecom: {
      carrier: carrierMatch,
      lineType: nationalNumber.startsWith('08') || cleanInternational.length > 9 ? 'Mobile / Cellular' : 'Landline / VoIP'
    },
    osintLinks: {
      whatsappChat: `https://wa.me/${cleanInternational}`,
      telegramChat: `https://t.me/+${cleanInternational}`,
      truecallerSearch: `https://www.truecaller.com/search/${cleanInternational}`,
      googleDork: `https://www.google.com/search?q="${encodeURIComponent(normalizedE164)}"+OR+"${encodeURIComponent(nationalNumber)}"`,
      syncMe: `https://sync.me/search/?number=${cleanInternational}`
    }
  };
}

// ── Plugin Entrypoint ─────────────────────────────────────────────────────────
export async function execute(args) {
  const target = (args.target || '').trim();
  if (!target) {
    throw new Error('Target username atau nomor telepon harus diisi.');
  }

  let mode = (args.type || 'auto').toLowerCase();
  const timeoutMs = parseInt(args.timeoutMs, 10) || 3500;

  // Auto detect mode if set to "auto"
  if (mode === 'auto') {
    const isLikelyPhone = /^(\+|08|62|\d{7,15}$)/.test(target.replace(/[\s\-()]/g, ''));
    mode = isLikelyPhone ? 'phone' : 'username';
  }

  if (mode === 'phone') {
    return searchPhone(target);
  } else {
    return await searchUsername(target, timeoutMs);
  }
}
