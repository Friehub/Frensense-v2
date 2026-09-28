import { defineConfig } from 'vitepress'
import { createContentLoader } from 'vitepress'

// frensense v2 documentation site.
// Deployed at the domain root; the legacy v1 site is served under /v1/.
export default defineConfig({
  base: process.env.VITEPRESS_BASE || '/Frensense-v2/',
  lang: 'en-US',
  title: 'Frensense',
  description:
    'Frensense v2, a compiler-mode static analysis engine that lowers every file to a program graph and reports exact source-to-sink taint paths.',
  ignoreDeadLinks: true, // v1 archive pages are copied in after the build, not known to VitePress.
  head: [['link', { rel: 'icon', type: 'image/png', href: '/favicon.png' }]],

  cleanUrls: true,

  themeConfig: {
    siteTitle: 'Frensense',

    nav: [
      { text: 'Docs', link: '/guide/', activeMatch: '/guide/' },
      { text: 'Architecture', link: '/architecture/', activeMatch: '/architecture/' },
      { text: 'Corpus', link: '/corpus/', activeMatch: '/corpus/' },
      { text: 'Blog', link: '/blog/', activeMatch: '/blog/' },
      {
        text: 'v1 (legacy)',
        items: [
          { text: 'v1 documentation archive', link: '/v1/' },
          { text: 'v1 on GitHub (Friehub/Frensense)', link: 'https://github.com/Friehub/Frensense' }
        ]
      },
      {
        text: 'v0.7.1-preview',
        items: [
          { text: 'Changelog', link: 'https://github.com/Friehub/frensense-v2/blob/main/CHANGELOG.md' }
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
