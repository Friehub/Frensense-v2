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

// Install commands, shown and copied exactly as written. One list drives the
// cards, so what a card displays is always what its button copies.
const RELEASE_CMD =
  'curl -L -o frensense https://github.com/Friehub/frensense-v2/releases/latest/download/frensense-x86_64-unknown-linux-gnu && chmod +x frensense'
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
        <a
          class="dl-card__registry"
          href="https://crates.io/crates/frensense"
          target="_blank"
          rel="noopener"
          >crates.io</a
        >
        <span v-if="cratesWeekly !== null" class="dl-card__stat">
          {{ fmt(cratesWeekly) }}<em>downloads / week</em>
        </span>
        <div class="dl-card__cmdrow">
          <code class="dl-card__cmd">cargo install frensense</code>
          <button
            type="button"
            class="dl-card__copy"
            :class="{ 'dl-card__copy--done': copied === 'cargo' }"
            aria-label="Copy command: cargo install frensense"
            @click="copy('cargo', 'cargo install frensense')"
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
        <a
          class="dl-card__registry"
          href="https://www.npmjs.com/package/@friehub/frensense"
          target="_blank"
          rel="noopener"
          >npm</a
        >
        <span v-if="npmWeekly !== null" class="dl-card__stat">
          {{ fmt(npmWeekly) }}<em>downloads / week</em>
        </span>
        <div class="dl-card__cmdrow">
          <code class="dl-card__cmd">npm i -g @friehub/frensense</code>
          <button
            type="button"
            class="dl-card__copy"
            :class="{ 'dl-card__copy--done': copied === 'npm' }"
            aria-label="Copy command: npm i -g @friehub/frensense"
            @click="copy('npm', 'npm i -g @friehub/frensense')"
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

      <div class="dl-card">
        <a
          class="dl-card__registry"
          href="https://github.com/Friehub/frensense-v2/releases"
          target="_blank"
          rel="noopener"
          >GitHub Releases</a
        >
        <span class="dl-card__stat dl-card__stat--muted"
          >Prebuilt binaries<em>Linux, macOS, Windows</em></span
        >
        <div class="dl-card__cmdrow">
          <code class="dl-card__cmd">{{ RELEASE_CMD }}</code>
          <button
            type="button"
            class="dl-card__copy"
            :class="{ 'dl-card__copy--done': copied === 'release' }"
            aria-label="Copy command: download the Linux x64 binary"
            @click="copy('release', RELEASE_CMD)"
          >
            {{ copied === 'release' ? 'Copied' : 'Copy' }}
          </button>
        </div>
        <p class="dl-card__note">Linux x64 shown; other platforms are on the releases page.</p>
        <a
          class="dl-card__cta"
          href="https://github.com/Friehub/frensense-v2/releases"
          target="_blank"
          rel="noopener"
          >All releases &rarr;</a
        >
      </div>
    </div>

    <span class="visually-hidden" role="status" aria-live="polite">{{
      copied ? 'Command copied to clipboard' : ''
    }}</span>

    <p class="download-strip__foot">
      No install needed - run <code>npx @friehub/frensense .</code>.
      Every surface shares one engine and one finding-ID scheme. Full options
      in the <a href="/guide/installation">installation guide</a>. Building on
      the crates? Browse the
      <a href="/rustdoc/" target="_blank" rel="noopener">Rust API docs</a>.
    </p>
  </div>
</template>
