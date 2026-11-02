<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import BlindnessScores from './BlindnessScores.vue'
import BlindnessLeaderboard from './BlindnessLeaderboard.vue'

interface CodeLine { n: number; text: string; mark: string }
interface CodeWindow { file: string; lines: CodeLine[] }
interface Sink { id: string; sink: string; file: string; line: number }
interface Challenge {
  id: string; title: string; repo: string; lang: string; kind: string; track: string
  difficulty: 'easy' | 'medium' | 'hard'; impact: number; summary: string; hint: string
  pointer: string; repro: string; pin: { url: string; commit: string }
  fix_added: string[]; code: CodeWindow[]; sinks: Sink[]
}
interface Board { commit: string; sinks: number; solved: number | null; new: number | null; scores?: any[]; groups: Challenge[] }

const PAGE = 12
const board = ref<Board | null>(null)
const view = ref<'challenges' | 'scores' | 'leaders'>('challenges')
const loading = ref(true)
const failed = ref(false)
const query = ref('')
const type = ref<'all' | 'blind' | 'missed' | 'false'>('all')
const difficulty = ref('all')
const repo = ref('all')
const shown = ref(PAGE)
const open = ref<string | null>(null)
const copied = ref('')

async function load(url: string): Promise<Board | null> {
  try {
    const res = await fetch(url, { cache: 'no-cache' })
    if (!res.ok) return null
    const doc = await res.json()
    return Array.isArray(doc?.groups) ? doc : null
  } catch {
    return null
  }
}

onMounted(async () => {
  // CI publishes the live board next to the docs; the committed copy keeps the page useful offline and in previews.
  board.value = (await load('/blindness/board.json')) ?? (await load('/data/blindness_board.json'))
  failed.value = !board.value
  loading.value = false
})

function typeOf(c: Challenge): 'blind' | 'missed' | 'false' {
  if (c.track.startsWith('Missed')) return 'missed'
  if (c.track.startsWith('False')) return 'false'
  return 'blind'
}

const all = computed(() => board.value?.groups ?? [])
const repos = computed(() => [...new Set(all.value.map(c => c.repo))].sort())
const counts = computed(() => {
  const k = { all: all.value.length, blind: 0, missed: 0, false: 0 }
  for (const c of all.value) k[typeOf(c)]++
  return k
})

const filtered = computed(() => {
  const q = query.value.toLowerCase().trim()
  return all.value.filter(c => {
    if (type.value !== 'all' && typeOf(c) !== type.value) return false
    if (difficulty.value !== 'all' && c.difficulty !== difficulty.value) return false
    if (repo.value !== 'all' && c.repo !== repo.value) return false
    if (!q) return true
    return `${c.id} ${c.title} ${c.repo} ${c.track} ${c.sinks.map(s => s.file).join(' ')}`.toLowerCase().includes(q)
  })
})
const visible = computed(() => filtered.value.slice(0, shown.value))

watch([query, type, difficulty, repo], () => { shown.value = PAGE; open.value = null })

const typeTabs = computed(() => [
  { key: 'all', label: 'All', n: counts.value.all },
  { key: 'blind', label: 'Blind spots', n: counts.value.blind },
  { key: 'missed', label: 'Missed', n: counts.value.missed },
  { key: 'false', label: 'False alarms', n: counts.value.false },
] as const)

// Summaries come from CI data: escape first, then turn `x` spans into inline code.
function fmt(t: string) {
  const e = t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  return e.replace(/`([^`]+)`/g, '<code>$1</code>')
}

function toggle(id: string) { open.value = open.value === id ? null : id }

async function copy(text: string, key: string) {
  try {
    await navigator.clipboard.writeText(text)
    copied.value = key
    setTimeout(() => { if (copied.value === key) copied.value = '' }, 1400)
  } catch { /* clipboard blocked: the text is selectable on screen */ }
}

function pinLink(c: Challenge) {
  if (!c.pin.url) return ''
  return c.pin.url.includes('/commit/') ? c.pin.url : c.pin.commit ? `${c.pin.url}/tree/${c.pin.commit}` : c.pin.url
}
</script>

<template>
  <div class="bc">
    <p v-if="loading" class="bc-state">Loading challenges…</p>
    <p v-else-if="failed" class="bc-state">The challenge board has not been published yet. It appears after the first <code>engine-blindness</code> run on main.</p>

    <template v-else-if="board">
      <div class="bc-stats">
        <div><b>{{ counts.all }}</b><span>open challenges</span></div>
        <div><b>{{ board.sinks }}</b><span>sinks they unblock</span></div>
        <div v-if="board.solved !== null"><b class="good">{{ board.solved }}</b><span>solved last run</span></div>
        <div v-if="board.new !== null"><b>{{ board.new }}</b><span>new last run</span></div>
      </div>

      <div class="bc-views" role="tablist">
        <button :class="{ on: view === 'challenges' }" role="tab" :aria-selected="view === 'challenges'" @click="view = 'challenges'">Challenges</button>
        <button :class="{ on: view === 'scores' }" role="tab" :aria-selected="view === 'scores'" @click="view = 'scores'">Scoreboard</button>
        <button :class="{ on: view === 'leaders' }" role="tab" :aria-selected="view === 'leaders'" @click="view = 'leaders'">Leaderboard</button>
      </div>

      <BlindnessScores v-if="view === 'scores'" :scores="board.scores ?? []" />
      <BlindnessLeaderboard v-else-if="view === 'leaders'" />

      <template v-else>
      <div class="bc-tabs" role="tablist">
        <button v-for="t in typeTabs" :key="t.key" role="tab" :aria-selected="type === t.key"
                :class="{ on: type === t.key }" @click="type = t.key">
          {{ t.label }} <small>{{ t.n }}</small>
        </button>
      </div>

      <div class="bc-bar">
        <input v-model="query" type="search" placeholder="Search by repo, file, or ID" aria-label="Search challenges" />
        <select v-model="difficulty" aria-label="Difficulty">
          <option value="all">Any difficulty</option>
          <option value="easy">Easy</option>
          <option value="medium">Medium</option>
          <option value="hard">Hard</option>
        </select>
        <select v-model="repo" aria-label="Repository">
          <option value="all">All repos</option>
          <option v-for="r in repos" :key="r" :value="r">{{ r }}</option>
        </select>
      </div>

      <p v-if="!filtered.length" class="bc-state">Nothing matches. Clear a filter.</p>

      <ul class="bc-list">
        <li v-for="c in visible" :key="c.id" class="bc-item" :class="{ open: open === c.id }">
          <button class="bc-head" :aria-expanded="open === c.id" @click="toggle(c.id)">
            <span class="dot" :class="c.difficulty" :title="c.difficulty"></span>
            <span class="bc-main">
              <span class="bc-title">{{ c.title }}</span>
              <span class="bc-sub">{{ c.repo }}<template v-if="c.title !== c.track"> · {{ c.track }}</template></span>
            </span>
            <span class="bc-impact">{{ c.impact }} <small>sink{{ c.impact === 1 ? '' : 's' }}</small></span>
            <span class="chev" aria-hidden="true"></span>
          </button>

          <div v-if="open === c.id" class="bc-body">
            <p class="bc-summary" v-html="fmt(c.summary)"></p>

            <template v-if="c.code.length">
              <div class="legend"><i class="k stop"></i>engine lost the value<i class="k sink"></i>sink it blocks</div>
              <div v-for="w in c.code" :key="w.file" class="win">
                <div class="win-file">{{ w.file }}</div>
                <pre><code><span v-for="l in w.lines" :key="l.n" class="ln" :class="l.mark"><i>{{ l.n }}</i>{{ l.text }}
</span></code></pre>
              </div>
            </template>

            <template v-if="c.fix_added.length">
              <div class="label">The upstream fix added</div>
              <pre class="plain"><code>{{ c.fix_added.join('\n') }}</code></pre>
            </template>

            <div class="label">Where to start</div>
            <p class="hint">{{ c.hint }}</p>
            <div class="repro">
              <code>$ {{ c.repro }}</code>
              <button @click="copy(c.repro, c.id + 'r')">{{ copied === c.id + 'r' ? 'Copied' : 'Copy' }}</button>
            </div>

            <details v-if="c.sinks.length">
              <summary>Affected sinks ({{ c.impact }})</summary>
              <ul class="sinks">
                <li v-for="s in c.sinks" :key="s.id"><b>{{ s.sink || 'sink' }}</b><span>{{ s.file }}:{{ s.line }}</span></li>
              </ul>
              <p v-if="c.impact > c.sinks.length" class="more">and {{ c.impact - c.sinks.length }} more</p>
            </details>

            <div class="foot">
              <button class="claim" title="Paste this line into your pull request description" @click="copy('Solves: ' + c.id, c.id)">{{ copied === c.id ? 'Copied' : 'Copy claim line' }}</button>
              <code class="idtext">{{ c.id }}</code>
              <a v-if="pinLink(c)" :href="pinLink(c)" target="_blank" rel="noopener noreferrer">
                {{ c.pin.url.replace('https://github.com/', '') }}<template v-if="c.pin.commit"> @ {{ c.pin.commit.slice(0, 7) }}</template>
              </a>
            </div>
          </div>
        </li>
      </ul>

      <div v-if="filtered.length > visible.length" class="bc-more">
        <button @click="shown += PAGE">Show {{ Math.min(PAGE, filtered.length - visible.length) }} more</button>
        <span>{{ visible.length }} of {{ filtered.length }}</span>
      </div>
      </template>
    </template>
  </div>
</template>

<style scoped>
.bc { margin: 1.5rem 0 3rem; font-family: var(--vp-font-family-base); }
.bc-state { color: var(--vp-c-text-2); padding: 2rem 0; text-align: center; }

.bc-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: .75rem; margin-bottom: 1.5rem; }
.bc-stats div { background: var(--vp-c-bg-elv); border: 1px solid var(--vp-c-border); border-radius: 8px; padding: .8rem 1rem; display: flex; flex-direction: column; }
.bc-stats b { font-size: 1.5rem; line-height: 1.2; color: var(--vp-c-text-1); font-variant-numeric: tabular-nums; }
.bc-stats b.good { color: var(--vp-c-brand-1); }
.bc-stats span { font-size: .78rem; color: var(--vp-c-text-2); }

.bc-views { display: inline-flex; gap: 2px; padding: 3px; margin-bottom: 1.1rem; background: var(--vp-c-bg-soft); border-radius: 8px; max-width: 100%; }
.bc-views button { background: none; border: 0; border-radius: 6px; padding: .35rem .9rem; font-size: .88rem; font-weight: 500; color: var(--vp-c-text-2); cursor: pointer; }
.bc-views button:hover { color: var(--vp-c-text-1); }
.bc-views button.on { background: var(--vp-c-bg); color: var(--vp-c-brand-1); box-shadow: 0 1px 2px rgba(0,0,0,.15); }
.bc-tabs { display: flex; gap: .25rem; border-bottom: 1px solid var(--vp-c-divider); margin-bottom: 1rem; overflow-x: auto; }
.bc-tabs button { background: none; border: 0; border-bottom: 2px solid transparent; color: var(--vp-c-text-2); padding: .5rem .8rem; font-size: .9rem; font-weight: 500; cursor: pointer; white-space: nowrap; margin-bottom: -1px; }
.bc-tabs button:hover { color: var(--vp-c-text-1); }
.bc-tabs button.on { color: var(--vp-c-brand-1); border-bottom-color: var(--vp-c-brand-1); }
.bc-tabs small { color: var(--vp-c-text-3); margin-left: .2rem; font-variant-numeric: tabular-nums; }

.bc-bar { display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: 1rem; }
.bc-bar input, .bc-bar select { background: var(--vp-c-bg-soft); border: 1px solid var(--vp-c-border); border-radius: 6px; color: var(--vp-c-text-1); padding: .45rem .7rem; font-size: .88rem; font-family: inherit; }
.bc-bar input { flex: 1 1 220px; min-width: 0; }
.bc-bar input:focus, .bc-bar select:focus { outline: 2px solid var(--vp-c-brand-1); outline-offset: -1px; }

.bc-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: .5rem; }
.bc-item { background: var(--vp-c-bg-elv); border: 1px solid var(--vp-c-border); border-radius: 8px; overflow: hidden; }
.bc-item.open { border-color: var(--vp-c-brand-1); }
.bc-head { display: flex; align-items: center; gap: .75rem; width: 100%; background: none; border: 0; padding: .75rem 1rem; text-align: left; cursor: pointer; color: inherit; font: inherit; }
.bc-head:hover { background: var(--vp-c-bg-soft); }
.dot { width: 9px; height: 9px; border-radius: 50%; flex: none; background: var(--vp-c-text-3); }
.dot.easy { background: var(--vp-c-brand-1); }
.dot.medium { background: var(--vp-c-warning-1); }
.dot.hard { background: var(--vp-c-danger-1); }
.bc-main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
.bc-title { font-weight: 600; font-size: .95rem; color: var(--vp-c-text-1); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bc-sub { font-size: .78rem; color: var(--vp-c-text-2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bc-impact { font-weight: 600; font-variant-numeric: tabular-nums; color: var(--vp-c-text-1); white-space: nowrap; }
.bc-impact small { font-weight: 400; color: var(--vp-c-text-2); }
.chev { width: 7px; height: 7px; border-right: 2px solid var(--vp-c-text-3); border-bottom: 2px solid var(--vp-c-text-3); transform: rotate(45deg); transition: transform .15s; flex: none; margin: 0 .2rem 3px; }
.open .chev { transform: rotate(-135deg); }

.bc-body { padding: .25rem 1rem 1rem; border-top: 1px solid var(--vp-c-divider); }
.bc-summary { margin: .8rem 0; color: var(--vp-c-text-1); font-size: .92rem; line-height: 1.55; }
.label { font-size: .72rem; font-weight: 600; text-transform: uppercase; letter-spacing: .04em; color: var(--vp-c-text-2); margin: 1rem 0 .35rem; }
.hint { margin: 0 0 .6rem; font-size: .9rem; color: var(--vp-c-text-1); line-height: 1.55; }

.legend { display: flex; align-items: center; gap: .4rem; font-size: .75rem; color: var(--vp-c-text-2); margin-bottom: .4rem; }
.k { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
.k.stop { background: var(--vp-c-warning-1); }
.k.sink { background: var(--vp-c-danger-1); margin-left: .6rem; }
.win { border: 1px solid var(--vp-c-divider); border-radius: 6px; overflow: hidden; margin-bottom: .5rem; background: var(--vp-code-block-bg); }
.win-file { font: 500 .75rem var(--vp-font-family-mono); color: var(--vp-c-text-2); padding: .35rem .7rem; border-bottom: 1px solid var(--vp-c-divider); overflow-x: auto; white-space: nowrap; }
.win pre, .plain { margin: 0; overflow-x: auto; font: .8rem/1.55 var(--vp-font-family-mono); }
.win code, .plain code { display: block; padding: .4rem 0; background: none; }
.plain { background: var(--vp-code-block-bg); border: 1px solid var(--vp-c-divider); border-radius: 6px; }
.plain code { padding: .5rem .7rem; }
.ln { display: block; padding: 0 .7rem 0 0; white-space: pre; }
.ln i { display: inline-block; width: 3.2em; text-align: right; padding-right: 1em; color: var(--vp-c-text-3); font-style: normal; user-select: none; }
.ln.stop { background: color-mix(in srgb, var(--vp-c-warning-1) 18%, transparent); box-shadow: inset 3px 0 var(--vp-c-warning-1); }
.ln.sink { background: color-mix(in srgb, var(--vp-c-danger-1) 16%, transparent); box-shadow: inset 3px 0 var(--vp-c-danger-1); }

.repro { display: flex; align-items: center; gap: .5rem; background: var(--vp-code-block-bg); border: 1px solid var(--vp-c-divider); border-radius: 6px; padding: .35rem .35rem .35rem .7rem; }
.repro code { flex: 1; min-width: 0; overflow-x: auto; white-space: nowrap; font-size: .8rem; background: none; color: var(--vp-c-text-1); padding: 0; }
.repro button { background: var(--vp-c-bg-soft); border: 1px solid var(--vp-c-border); color: var(--vp-c-text-1); border-radius: 5px; padding: .2rem .6rem; font-size: .78rem; cursor: pointer; }
.repro button:hover { border-color: var(--vp-c-brand-1); color: var(--vp-c-brand-1); }

details { margin-top: .9rem; }
summary { cursor: pointer; font-size: .88rem; color: var(--vp-c-text-1); font-weight: 500; }
.sinks { list-style: none; margin: .5rem 0 0; padding: 0; max-height: 14rem; overflow-y: auto; font-size: .8rem; }
.sinks li { display: flex; justify-content: space-between; gap: 1rem; padding: .25rem 0; border-bottom: 1px solid var(--vp-c-divider); margin: 0; }
.sinks b { font-family: var(--vp-font-family-mono); font-weight: 500; }
.sinks span, .more { color: var(--vp-c-text-2); font-family: var(--vp-font-family-mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
.more { font-size: .78rem; margin: .4rem 0 0; }

.foot { display: flex; flex-wrap: wrap; align-items: center; gap: .75rem; margin-top: 1rem; font-size: .8rem; }
.idtext { font-size: .75rem; color: var(--vp-c-text-2); background: none; padding: 0; }
.claim { background: var(--vp-c-brand-1); border: 0; color: #fff; border-radius: 5px; padding: .25rem .75rem; font-size: .8rem; font-weight: 600; cursor: pointer; }
.claim:hover { background: var(--vp-c-brand-2); }

.bc-more { display: flex; align-items: center; justify-content: center; gap: 1rem; margin-top: 1.25rem; color: var(--vp-c-text-2); font-size: .85rem; }
.bc-more button { background: var(--vp-button-alt-bg); border: 1px solid var(--vp-c-border); color: var(--vp-c-text-1); border-radius: 20px; padding: .4rem 1.1rem; cursor: pointer; font-size: .88rem; }
.bc-more button:hover { border-color: var(--vp-c-brand-1); color: var(--vp-c-brand-1); }

@media (max-width: 560px) {
  .bc-head { padding: .65rem .75rem; gap: .55rem; }
  .bc-impact small { display: none; }
  .bc-body { padding: .25rem .75rem .9rem; }
}
</style>
