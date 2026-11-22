<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (c) 2024-2026 Friehub -->
<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

interface Rates {
  TP: number
  FP: number
  FN: number
  TN: number
  ERR?: number
  tpr: number
  fpr: number
  score: number
}

interface Meta {
  match?: string
  version?: string
  commit?: string
  generated_at?: string
  elapsed_s?: number
  workers?: number
  bundle?: string | null
  snapshot?: boolean
}

interface Scorecard {
  meta?: Meta
  total?: Rates
  by_cwe?: Record<string, Rates>
}

// CI publishes the slim scorecard to /benchmarks/benchmark.json. The committed
// file is only a fallback so a local preview still shows the last record.
const LIVE = '/benchmarks/benchmark.json'
const SNAPSHOT = '/data/benchmark_scorecard.json'

// Presentation labels only; every number comes from the published JSON.
const NAMES: Record<string, string> = {
  'CWE-22': 'path traversal',
  'CWE-78': 'command injection',
  'CWE-79': 'cross-site scripting',
  'CWE-89': 'SQL injection',
  'CWE-90': 'LDAP injection',
  'CWE-94': 'code injection',
  'CWE-328': 'weak hash',
  'CWE-330': 'weak randomness',
  'CWE-501': 'trust boundary',
  'CWE-502': 'deserialization',
  'CWE-601': 'open redirect',
  'CWE-611': 'XML external entities',
  'CWE-614': 'cookie flags',
  'CWE-643': 'XPath injection'
}

const data = ref<Scorecard | null>(null)
const source = ref<'loading' | 'live' | 'snapshot' | 'missing'>('loading')

async function load(url: string): Promise<Scorecard | null> {
  try {
    const res = await fetch(`${url}?t=${Date.now()}`, { cache: 'no-store' })
    if (!res.ok) return null
    return (await res.json()) as Scorecard
  } catch {
    return null
  }
}

onMounted(async () => {
  const live = await load(LIVE)
  if (live) {
    data.value = live
    source.value = 'live'
    return
  }
  const snapshot = await load(SNAPSHOT)
  if (snapshot) {
    data.value = snapshot
    source.value = 'snapshot'
    return
  }
  source.value = 'missing'
})

const total = computed(() => data.value?.total)

const rows = computed(() => {
  const byCwe = data.value?.by_cwe ?? {}
  return Object.entries(byCwe)
    .map(([cwe, r]) => ({
      cwe,
      name: NAMES[cwe] ?? '',
      cases: r.TP + r.FP + r.FN + r.TN,
      ...r
    }))
    .sort((a, b) => a.score - b.score || b.cases - a.cases || a.cwe.localeCompare(b.cwe))
})

const measuredOn = computed(() => {
  const raw = data.value?.meta?.generated_at
  if (!raw) return ''
  const d = new Date(raw)
  return Number.isNaN(d.getTime()) ? raw : d.toISOString().slice(0, 10)
})

function pct(v: number): string {
  return `${(v * 100).toFixed(1)}%`
}

function num(v: number): string {
  return v.toLocaleString('en-US')
}
</script>

<template>
  <section class="bench-score">
    <div v-if="source === 'loading'" class="bench-score__note">
      Loading the published scorecard…
    </div>

    <div v-else-if="source === 'missing'" class="bench-score__note">
      The published scorecard is not available here. Run
      <code>python3 frensense-bench/run.py --suite owasp</code> to generate one,
      or
      <a
        href="https://github.com/Friehub/frensense-v2/actions/workflows/benchmark.yml"
        >view the latest CI run</a
      >.
    </div>

    <template v-else-if="total">
      <p v-if="source === 'snapshot'" class="bench-score__note bench-score__note--warn">
        Live data could not be loaded; showing the committed snapshot.
      </p>

      <p class="bench-score__meta">
        {{ data?.meta?.version ?? 'Frensense' }}
        at <code>{{ data?.meta?.commit ?? 'unknown' }}</code>
        <template v-if="measuredOn"> · {{ measuredOn }}</template>
        <template v-if="data?.meta?.match"> · {{ data.meta.match }} matching</template>
        <template v-if="data?.meta?.bundle">
          · bundle <code>{{ data.meta.bundle }}</code>
        </template>
      </p>

      <div class="bench-score__cards">
        <div class="bench-card">
          <span class="bench-card__v">{{ pct(total.score) }}</span>
          <span class="bench-card__k">score (TPR − FPR)</span>
        </div>
        <div class="bench-card">
          <span class="bench-card__v">{{ pct(total.tpr) }}</span>
          <span class="bench-card__k">TPR</span>
        </div>
        <div class="bench-card">
          <span class="bench-card__v">{{ pct(total.fpr) }}</span>
          <span class="bench-card__k">FPR</span>
        </div>
        <div class="bench-card">
          <span class="bench-card__v">
            {{ num(total.TP) }} / {{ num(total.FP) }} / {{ num(total.FN) }} /
            {{ num(total.TN) }}
          </span>
          <span class="bench-card__k">TP / FP / FN / TN</span>
        </div>
      </div>

      <div class="bench-score__tablewrap">
        <table class="bench-table">
          <thead>
            <tr>
              <th>CWE</th>
              <th>class</th>
              <th class="num">cases</th>
              <th class="num">TP</th>
              <th class="num">FP</th>
              <th class="num">FN</th>
              <th class="num">TN</th>
              <th class="num">TPR</th>
              <th class="num">FPR</th>
              <th class="num">score</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in rows" :key="r.cwe">
              <td><code>{{ r.cwe }}</code></td>
              <td>{{ r.name }}</td>
              <td class="num">{{ num(r.cases) }}</td>
              <td class="num">{{ num(r.TP) }}</td>
              <td class="num">{{ num(r.FP) }}</td>
              <td class="num">{{ num(r.FN) }}</td>
              <td class="num">{{ num(r.TN) }}</td>
              <td class="num">{{ pct(r.tpr) }}</td>
              <td class="num">{{ pct(r.fpr) }}</td>
              <td class="num">{{ pct(r.score) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </section>
</template>

<style scoped>
.bench-score {
  margin: 1.5rem 0;
}

.bench-score__note {
  padding: 0.75rem 1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-2);
}

.bench-score__note--warn {
  border-color: var(--vp-c-warning-1);
  margin-bottom: 1rem;
}

.bench-score__meta {
  margin: 0 0 1rem;
  color: var(--vp-c-text-2);
  font-size: 0.9rem;
}

.bench-score__cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 0.75rem;
  margin-bottom: 1.25rem;
}

.bench-card {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  padding: 0.9rem 1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  background: var(--vp-c-bg-soft);
}

.bench-card__v {
  font-size: 1.45rem;
  font-weight: 700;
  color: var(--vp-c-text-1);
}

.bench-card__k {
  font-size: 0.8rem;
  color: var(--vp-c-text-2);
}

.bench-score__tablewrap {
  overflow-x: auto;
}

.bench-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}

.bench-table th,
.bench-table td {
  padding: 0.45rem 0.6rem;
  border-bottom: 1px solid var(--vp-c-divider);
  text-align: left;
  white-space: nowrap;
}

.bench-table th {
  color: var(--vp-c-text-2);
  font-weight: 600;
}

.bench-table .num {
  text-align: right;
  font-variant-numeric: tabular-nums;
}
</style>
