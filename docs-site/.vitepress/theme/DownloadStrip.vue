<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (c) 2024-2026 Friehub. All rights reserved. -->
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
      <a
        class="dl-card"
        href="https://crates.io/crates/frensense"
        target="_blank"
        rel="noopener"
      >
        <span class="dl-card__registry">crates.io</span>
        <span v-if="cratesWeekly !== null" class="dl-card__stat">
          {{ fmt(cratesWeekly) }}<em>downloads / week</em>
        </span>
        <code class="dl-card__cmd">cargo install frensense</code>
        <span class="dl-card__cta">View on crates.io &rarr;</span>
      </a>

      <a
        class="dl-card"
        href="https://www.npmjs.com/package/@friehub/frensense"
        target="_blank"
        rel="noopener"
      >
        <span class="dl-card__registry">npm</span>
        <span v-if="npmWeekly !== null" class="dl-card__stat">
          {{ fmt(npmWeekly) }}<em>downloads / week</em>
        </span>
        <code class="dl-card__cmd">npm install -g @friehub/frensense</code>
        <span class="dl-card__cta">View on npm &rarr;</span>
      </a>

      <a
        class="dl-card"
        href="https://github.com/Friehub/frensense-v2/releases"
        target="_blank"
        rel="noopener"
      >
        <span class="dl-card__registry">GitHub Releases</span>
        <span class="dl-card__stat dl-card__stat--muted"
          >SLSA L3 provenance<em>Linux, macOS, Windows</em></span
        >
        <code class="dl-card__cmd">npx @friehub/frensense .</code>
        <span class="dl-card__cta">All releases &rarr;</span>
      </a>
    </div>

    <p class="download-strip__foot">
      No install needed &mdash; run <code>npx @friehub/frensense .</code>.
      Every surface shares one engine and one finding-ID scheme. Full options
      in the <a href="/guide/installation">installation guide</a>.
    </p>
  </div>
</template>
