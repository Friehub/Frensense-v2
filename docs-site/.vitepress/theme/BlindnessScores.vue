<script setup lang="ts">
import { ref, computed } from 'vue'

interface Category { name: string; tp: number; fn: number; fp: number; tn: number; recall: number; fpr: number; score: number }
interface Score extends Category { lang: string; categories: Category[] }

const props = defineProps<{ scores: Score[] }>()
const open = ref<string | null>(null)
const all = ref<Record<string, boolean>>({})

const sources = computed(() => [...props.scores].sort((a, b) => (b.tp + b.fn + b.fp + b.tn) - (a.tp + a.fn + a.fp + a.tn)))
const pct = (x: number) => `${Math.round(x * 100)}%`
const total = (s: Category) => s.tp + s.fn + s.fp + s.tn || 1
const width = (n: number, s: Category) => `${(n / total(s)) * 100}%`
function rows(s: Score) { return all.value[s.name] ? s.categories : s.categories.slice(0, 8) }
</script>

<template>
  <div class="sc">
    <p v-if="!sources.length" class="sc-empty">No labelled results yet. They appear after a run with <code>--labelled</code>.</p>

    <div v-for="s in sources" :key="s.name" class="sc-card" :class="{ open: open === s.name }">
      <button class="sc-head" :aria-expanded="open === s.name" @click="open = open === s.name ? null : s.name">
        <span class="sc-name">{{ s.name }}<small>{{ s.lang }}</small></span>
        <span class="sc-score" :title="'Recall minus false-positive rate. 0 is a coin flip, 1 is perfect.'">
          <b>{{ s.score.toFixed(2) }}</b><small>score</small>
        </span>
        <span class="chev" aria-hidden="true"></span>
      </button>

      <div class="sc-bar" role="img" :aria-label="`${s.tp} found, ${s.fn} missed, ${s.fp} false alarms, ${s.tn} correctly left alone`">
        <i class="tp" :style="{ width: width(s.tp, s) }"></i>
        <i class="fn" :style="{ width: width(s.fn, s) }"></i>
        <i class="fp" :style="{ width: width(s.fp, s) }"></i>
        <i class="tn" :style="{ width: width(s.tn, s) }"></i>
      </div>
      <ul class="sc-legend">
        <li><i class="tp"></i><b>{{ s.tp }}</b> found</li>
        <li><i class="fn"></i><b>{{ s.fn }}</b> missed</li>
        <li><i class="fp"></i><b>{{ s.fp }}</b> false alarms</li>
        <li><i class="tn"></i><b>{{ s.tn }}</b> correctly quiet</li>
      </ul>

      <div v-if="open === s.name" class="sc-body">
        <p class="sc-note">Recall <b>{{ pct(s.recall) }}</b> · false-positive rate <b>{{ pct(s.fpr) }}</b>. Score is recall minus false-positive rate (the OWASP Benchmark's own measure), so only finding more bugs <em>without</em> more noise moves it.</p>
        <table>
          <thead><tr><th>Category</th><th>Found</th><th>Missed</th><th>False</th><th>Quiet</th><th>Score</th></tr></thead>
          <tbody>
            <tr v-for="c in rows(s)" :key="c.name">
              <td>{{ c.name }}</td><td>{{ c.tp }}</td><td :class="{ bad: c.fn }">{{ c.fn }}</td>
              <td :class="{ bad: c.fp }">{{ c.fp }}</td><td>{{ c.tn }}</td><td>{{ c.score.toFixed(2) }}</td>
            </tr>
          </tbody>
        </table>
        <button v-if="s.categories.length > 8" class="more" @click="all[s.name] = !all[s.name]">
          {{ all[s.name] ? 'Show fewer' : `Show all ${s.categories.length} categories` }}
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.sc { display: flex; flex-direction: column; gap: .75rem; }
.sc-empty { color: var(--vp-c-text-2); text-align: center; padding: 2rem 0; }
.sc-card { background: var(--vp-c-bg-elv); border: 1px solid var(--vp-c-border); border-radius: 8px; padding: .25rem 1rem 1rem; }
.sc-card.open { border-color: var(--vp-c-brand-1); }
.sc-head { display: flex; align-items: center; gap: .75rem; width: 100%; background: none; border: 0; padding: .75rem 0 .6rem; cursor: pointer; color: inherit; font: inherit; text-align: left; }
.sc-name { flex: 1; font-weight: 600; color: var(--vp-c-text-1); }
.sc-name small { margin-left: .5rem; font-weight: 400; color: var(--vp-c-text-2); }
.sc-score { display: flex; flex-direction: column; align-items: flex-end; line-height: 1.15; }
.sc-score b { font-size: 1.25rem; color: var(--vp-c-brand-1); font-variant-numeric: tabular-nums; }
.sc-score small { font-size: .7rem; color: var(--vp-c-text-2); }
.chev { width: 7px; height: 7px; border-right: 2px solid var(--vp-c-text-3); border-bottom: 2px solid var(--vp-c-text-3); transform: rotate(45deg); transition: transform .15s; margin: 0 .2rem 3px; }
.open .chev { transform: rotate(-135deg); }
.sc-bar { display: flex; height: 10px; border-radius: 5px; overflow: hidden; background: var(--vp-c-bg-soft); }
.sc-bar i { height: 100%; }
i.tp { background: var(--vp-c-brand-1); }
i.fn { background: var(--vp-c-danger-1); }
i.fp { background: var(--vp-c-warning-1); }
i.tn { background: var(--vp-c-gray-2); }
.sc-legend { display: flex; flex-wrap: wrap; gap: .25rem 1.1rem; list-style: none; margin: .6rem 0 0; padding: 0; font-size: .8rem; color: var(--vp-c-text-2); }
.sc-legend li { margin: 0; display: flex; align-items: center; gap: .35rem; }
.sc-legend i { width: 9px; height: 9px; border-radius: 2px; display: inline-block; }
.sc-legend b { color: var(--vp-c-text-1); font-variant-numeric: tabular-nums; }
.sc-body { margin-top: .9rem; border-top: 1px solid var(--vp-c-divider); padding-top: .8rem; }
.sc-note { margin: 0 0 .7rem; font-size: .85rem; color: var(--vp-c-text-2); line-height: 1.5; }
table { display: table; width: 100%; margin: 0; font-size: .82rem; border-collapse: collapse; }
th, td { padding: .35rem .5rem; border: 0; border-bottom: 1px solid var(--vp-c-divider); text-align: right; font-variant-numeric: tabular-nums; background: none !important; }
th:first-child, td:first-child { text-align: left; }
th { font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; color: var(--vp-c-text-2); }
td.bad { color: var(--vp-c-danger-1); font-weight: 600; }
.more { margin-top: .6rem; background: none; border: 0; color: var(--vp-c-brand-1); cursor: pointer; font-size: .85rem; padding: 0; }
@media (max-width: 560px) { th, td { padding: .3rem .25rem; font-size: .76rem; } }
</style>
