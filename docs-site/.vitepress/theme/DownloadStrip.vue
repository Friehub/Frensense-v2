<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (c) 2024-2026 Friehub -->
<script setup lang="ts">
import { useData } from 'vitepress'
import { computed, onMounted, ref } from 'vue'

interface Stats {
  npmWeekly?: number
  cratesWeekly?: number
}

const { theme } = useData()

// Build-time counts (config.mts getDownloadStats) render immediately on
// SSR; onMounted re-fetches so the numbers stay fresh between deploys.
const buildStats = ref<Stats>({ ...((theme.value as { downloadStats?: Stats }).downloadStats ?? {}) })
const liveNpm = ref<number | null>(null)
const liveCrates = ref<number | null>(null)

const npmWeekly = computed(() => liveNpm.value ?? buildStats.value.npmWeekly ?? null)
const cratesWeekly = computed(() => liveCrates.value ?? buildStats.value.cratesWeekly ?? null)

function fmt(n: number): string {
  return n.toLocaleString('en-US')
}

async function refresh() {
  try {
    const res = await fetch(
      'https://api.npmjs.org/downloads/point/last-week/@friehub/frensense'
    )
    if (res.ok) {
      const data = (await res.json()) as { downloads?: number }
      if (typeof data?.downloads === 'number') liveNpm.value = data.downloads
    }
  } catch {}

  try {
    const res = await fetch('https://crates.io/api/v1/crates/frensense/downloads', {
      headers: { Accept: 'application/json' }
    })
    if (res.ok) {
      const data = (await res.json()) as {
        version_downloads?: Array<{ date: string; downloads: number }>
      }
      const byDate = new Map<string, number>()
      for (const d of data?.version_downloads ?? []) {
        byDate.set(d.date, (byDate.get(d.date) ?? 0) + (d.downloads || 0))
      }
      liveCrates.value = [...byDate.entries()]
        .sort((a, b) => (a[0] < b[0] ? 1 : -1))
        .slice(0, 7)
        .reduce((sum, [, n]) => sum + n, 0)
    }
  } catch {}
}

onMounted(refresh)

const copied = ref<string | null>(null)
let resetTimer: ReturnType<typeof setTimeout> | undefined

async function copy(id: string, text: string) {
  let ok = false
  try {
    await navigator.clipboard.writeText(text)
    ok = true
  } catch {
    // Clipboard API is unavailable on insecure origins and in some embedded
    // browsers; fall back to a selection copy.
    try {
      const area = document.createElement('textarea')
      area.value = text
      area.setAttribute('readonly', '')
      area.style.position = 'fixed'
      area.style.opacity = '0'
      document.body.appendChild(area)
      area.select()
      ok = document.execCommand('copy')
      document.body.removeChild(area)
    } catch {}
  }
  if (!ok) return
  copied.value = id
  clearTimeout(resetTimer)
  resetTimer = setTimeout(() => (copied.value = null), 1800)
}

// One release asset per platform, named after its Rust target. A single
// "releases" card hid the fact that the download differs by device, so each
// platform gets its own card and its own file.
interface Platform {
  id: string
  name: string
  detail: string
  asset: string
}

const RELEASES = 'https://github.com/Friehub/frensense-v2/releases'
const platforms: Platform[] = [
  {
    id: 'linux-x64',
    name: 'Linux',
    detail: 'x64 · glibc 2.39+',
    asset: 'frensense-x86_64-unknown-linux-gnu'
  },
  {
    id: 'macos-arm64',
    name: 'macOS',
    detail: 'Apple Silicon · arm64',
    asset: 'frensense-aarch64-apple-darwin'
  },
  {
    id: 'macos-x64',
    name: 'macOS',
    detail: 'Intel · x64',
    asset: 'frensense-x86_64-apple-darwin'
  },
  {
    id: 'windows-x64',
    name: 'Windows',
    detail: 'x64 · .exe',
    asset: 'frensense-x86_64-pc-windows-msvc.exe'
  }
]

function assetUrl(asset: string): string {
  return `${RELEASES}/latest/download/${asset}`
}

const CARGO_CMD = 'cargo install frensense'
const NPM_CMD = 'npm i -g @friehub/frensense'
</script>

<template>
  <div class="download-strip">
    <div class="download-strip__head">
      <h2>Download Frensense</h2>
      <p>
        One binary for the CLI, MCP server, and LSP. Pick your registry, or
        grab a prebuilt release.
      </p>
    </div>

    <div class="download-strip__grid">
      <div class="dl-card">
        <div class="dl-card__top">
          <span class="dl-card__registry">crates.io</span>
          <span v-if="cratesWeekly !== null" class="dl-card__stat">
            {{ fmt(cratesWeekly) }}<em>downloads / week</em>
          </span>
        </div>
        <div class="dl-card__cmdrow">
          <code class="dl-card__cmd">{{ CARGO_CMD }}</code>
          <button
            type="button"
            class="dl-card__copy"
            :class="{ 'dl-card__copy--done': copied === 'cargo' }"
            :aria-label="`Copy command: ${CARGO_CMD}`"
            @click="copy('cargo', CARGO_CMD)"
          >
            {{ copied === 'cargo' ? 'Copied' : 'Copy' }}
          </button>
        </div>
        <a
          class="dl-card__cta"
          href="https://crates.io/crates/frensense"
          target="_blank"
          rel="noopener"
          >View on crates.io &rarr;</a
        >
      </div>

      <div class="dl-card">
        <div class="dl-card__top">
          <span class="dl-card__registry">npm</span>
          <span v-if="npmWeekly !== null" class="dl-card__stat">
            {{ fmt(npmWeekly) }}<em>downloads / week</em>
          </span>
        </div>
        <div class="dl-card__cmdrow">
          <code class="dl-card__cmd">{{ NPM_CMD }}</code>
          <button
            type="button"
            class="dl-card__copy"
            :class="{ 'dl-card__copy--done': copied === 'npm' }"
            :aria-label="`Copy command: ${NPM_CMD}`"
            @click="copy('npm', NPM_CMD)"
          >
            {{ copied === 'npm' ? 'Copied' : 'Copy' }}
          </button>
        </div>
        <a
          class="dl-card__cta"
          href="https://www.npmjs.com/package/@friehub/frensense"
          target="_blank"
          rel="noopener"
          >View on npm &rarr;</a
        >
      </div>
    </div>

    <h3 class="download-strip__subhead">Prebuilt binaries</h3>

    <div class="download-strip__grid download-strip__grid--binaries">
      <div v-for="p in platforms" :key="p.id" class="dl-card dl-card--binary">
        <div class="dl-card__top">
          <span class="dl-card__registry">{{ p.name }}</span>
        </div>
        <p class="dl-card__platform-detail">{{ p.detail }}</p>
        <a
          class="dl-card__cta"
          :href="assetUrl(p.asset)"
          target="_blank"
          rel="noopener"
          >Download &rarr;</a
        >
      </div>
    </div>

    <p class="download-strip__note">
      The Linux build is linked against glibc from Ubuntu 24.04, so it needs
      glibc 2.39 or newer: it will not run on musl-only systems such as Alpine,
      or on older distributions. Use <code>cargo install frensense</code>
      there, or <code>npx @friehub/frensense</code> with Node installed.
    </p>

    <p class="download-strip__foot">
      Other platforms are on the
      <a :href="RELEASES" target="_blank" rel="noopener">releases page</a>. No
      install needed - run <code>npx @friehub/frensense .</code>. Every surface
      shares one engine and one finding-ID scheme. Full options in the
      <a href="/guide/installation">installation guide</a>. Building on the
      crates? Browse the
      <a href="/rustdoc/" target="_blank" rel="noopener">Rust API docs</a>.
    </p>

    <span class="visually-hidden" role="status" aria-live="polite">{{
      copied ? 'Command copied to clipboard' : ''
    }}</span>
  </div>
</template>
