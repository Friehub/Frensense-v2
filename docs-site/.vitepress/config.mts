import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig, createContentLoader } from 'vitepress'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

function getWorkspaceVersion(): string {
  try {
    const cargoTomlPath = path.resolve(__dirname, '../../Cargo.toml')
    const content = fs.readFileSync(cargoTomlPath, 'utf-8')
    const match = content.match(/\[package\][\s\S]*?version\s*=\s*"([^"]+)"/)
    if (match && match[1]) {
      return match[1]
    }
  } catch {}
  return '0.7.0-preview'
}

async function getPublishedVersion(): Promise<string> {
  const fallback = getWorkspaceVersion()

  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 1500)
    const res = await fetch('https://api.github.com/repos/Friehub/frensense-v2/releases/latest', {
      headers: { 'User-Agent': 'frensense-docs-builder' },
      signal: controller.signal
    })
    clearTimeout(timer)
    if (res.ok) {
      const data = (await res.json()) as { tag_name?: string }
      if (data?.tag_name) {
        return data.tag_name.replace(/^v/, '')
      }
    }
  } catch {}

  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 1500)
    const res = await fetch('https://registry.npmjs.org/@friehub/frensense/latest', {
      signal: controller.signal
    })
    clearTimeout(timer)
    if (res.ok) {
      const data = (await res.json()) as { version?: string }
      if (data?.version) {
        return data.version
      }
    }
  } catch {}

  return fallback
}

const currentVersion = await getPublishedVersion()

// Weekly download counts for the homepage (npm + crates.io), fetched at
// build time. DownloadStrip refreshes them client-side too, so the numbers
// stay fresh between deploys; both APIs send `Access-Control-Allow-Origin: *`.
type DownloadStats = { npmWeekly?: number; cratesWeekly?: number }

async function getDownloadStats(): Promise<DownloadStats> {
  const stats: DownloadStats = {}

  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 2000)
    const res = await fetch(
      'https://api.npmjs.org/downloads/point/last-week/@friehub/frensense',
      { signal: controller.signal }
    )
    clearTimeout(timer)
    if (res.ok) {
      const data = (await res.json()) as { downloads?: number }
      if (typeof data?.downloads === 'number') stats.npmWeekly = data.downloads
    }
  } catch {}

  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 2000)
    const res = await fetch('https://crates.io/api/v1/crates/frensense/downloads', {
      headers: { 'User-Agent': 'frensense-docs-builder', Accept: 'application/json' },
      signal: controller.signal
    })
    clearTimeout(timer)
    if (res.ok) {
      const data = (await res.json()) as {
        version_downloads?: Array<{ date: string; downloads: number }>
      }
      // crates.io has no official weekly metric; sum the 7 most recent days.
      const byDate = new Map<string, number>()
      for (const d of data?.version_downloads ?? []) {
        byDate.set(d.date, (byDate.get(d.date) ?? 0) + (d.downloads || 0))
      }
      stats.cratesWeekly = [...byDate.entries()]
        .sort((a, b) => (a[0] < b[0] ? 1 : -1))
        .slice(0, 7)
        .reduce((sum, [, n]) => sum + n, 0)
    }
  } catch {}

  return stats
}

const downloadStats = await getDownloadStats()

// frensense v2 documentation site.
// Deployed at the domain root; the legacy v1 site is served under /v1/.
export default defineConfig({
  lang: 'en-US',
  title: 'Frensense',
  description:
    'Frensense v2, a compiler-mode static analysis engine that lowers every file to a program graph and reports exact source-to-sink taint paths.',
  ignoreDeadLinks: true, // v1 archive pages are copied in after the build, not known to VitePress.
  sitemap: {
    hostname: 'https://frensense.friehub.cloud'
  },
  head: [
    ['link', { rel: 'icon', type: 'image/png', href: '/favicon.png' }],
    ['meta', { property: 'og:site_name', content: 'Frensense' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:site', content: '@friehub' }],
    [
      'script',
      {},
      `
      (function() {
        if (typeof window === 'undefined') return;
        var STORAGE_KEY = 'frensense_latest_version';
        function applyVersion(v) {
          if (!v) return;
          var display = v.startsWith('v') ? v : 'v' + v;
          var targets = document.querySelectorAll('.VPNavBarMenuGroup button span, .frensense-version');
          targets.forEach(function(el) {
            if (/^v?\\d+\\.\\d+\\.\\d+/.test(el.textContent ? el.textContent.trim() : '')) {
              el.textContent = display;
            }
          });
        }
        try {
          var cached = sessionStorage.getItem(STORAGE_KEY);
          if (cached) applyVersion(cached);
        } catch (_) {}

        if (window.fetch) {
          fetch('https://api.github.com/repos/Friehub/frensense-v2/releases/latest')
            .then(function(res) { return res.ok ? res.json() : null; })
            .then(function(data) {
              if (data && data.tag_name) {
                var ver = data.tag_name;
                try { sessionStorage.setItem(STORAGE_KEY, ver); } catch (_) {}
                applyVersion(ver);
              }
            })
            .catch(function() {});
        }
        window.addEventListener('DOMContentLoaded', function() {
          try {
            var cached = sessionStorage.getItem(STORAGE_KEY);
            if (cached) applyVersion(cached);
          } catch (_) {}
        });
      })();
      `
    ]
  ],

  cleanUrls: true,

  themeConfig: {
    siteTitle: 'Frensense',

    downloadStats,

    nav: [
      { text: 'Docs', link: '/guide/', activeMatch: '/guide/' },
      { text: 'Architecture', link: '/architecture/', activeMatch: '/architecture/' },
      { text: 'Corpus', link: '/corpus/', activeMatch: '/corpus/' },
      { text: 'Bundles', link: '/bundles', activeMatch: '/bundles' },
      { text: 'Blog', link: '/blog/', activeMatch: '/blog/' },
      {
        text: 'v1 (legacy)',
        items: [
          { text: 'v1 documentation archive', link: '/v1/' },
          { text: 'v1 on GitHub (Friehub/Frensense)', link: 'https://github.com/Friehub/Frensense' }
        ]
      },
      {
        text: `v${currentVersion}`,
        items: [
          { text: 'Changelog', link: 'https://github.com/Friehub/frensense-v2/blob/main/CHANGELOG.md' },
          { text: 'crates.io', link: 'https://crates.io/crates/frensense' },
          { text: 'npm', link: 'https://www.npmjs.com/package/@friehub/frensense' },
          { text: 'GitHub Releases', link: 'https://github.com/Friehub/frensense-v2/releases' }
        ]
      }
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Getting started',
          items: [
            { text: 'Introduction', link: '/guide/' },
            { text: 'Installation', link: '/guide/installation' },
            { text: 'Your first scan', link: '/guide/first-scan' },
            { text: 'Teachable engine', link: '/guide/teachability' },
            { text: 'CLI reference', link: '/guide/cli' }
          ]
        },
        {
          text: 'Integrations',
          items: [
            { text: 'GitHub Actions', link: '/guide/github-actions' },
            { text: 'MCP server (AI agents)', link: '/guide/mcp' },
            { text: 'LSP server (editors)', link: '/guide/lsp' }
          ]
        }
      ],
      '/architecture/': [
        {
          text: 'Architecture',
          items: [
            { text: 'Overview', link: '/architecture/' },
            { text: 'The program graph', link: '/architecture/program-graph' },
            { text: 'Checkers', link: '/architecture/checkers' },
            { text: 'Knowledge bundles (.frc)', link: '/architecture/bundles' }
          ]
        }
      ],
      '/corpus/': [
        {
          text: 'Corpus',
          items: [
            { text: 'Corpus & .frc bundles', link: '/corpus/' },
            { text: 'Authoring guide', link: '/corpus/authoring' }
          ]
        }
      ],
      '/blog/': []
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/Friehub/frensense-v2' }
    ],

    search: {
      provider: 'local'
    },

    outline: { level: [2, 3] },

    footer: {
      message: 'Released under the GPL-3.0 license.',
      copyright: 'Copyright © 2026 Friehub'
    }
  },

  async transformHead(context) {
    // no-op; kept for future font/meta injection
  }
})

// Blog post list data (used by blog/index.md via data loader).
export const blogLoader = () =>
  createContentLoader('blog/*.md', {
    excerpt: true,
    render: true
  })
