<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'

interface Badge { id: string; name: string; description: string; earned_at: string }
interface Contributor {
  login: string; points: number; prs: number; sinks: number; cleared: number
  badges: Badge[]; next: { id: string; name: string; missing: Record<string, number> } | null
}
interface Entry {
  id: string; pr: number; pr_url: string; pr_title: string; author: string; merged_at: string
  repo: string; difficulty: string; sinks_solved: number; cleared: boolean; points: number
}
interface Ledger { updated?: string; entries: Entry[]; contributors: Contributor[] }

const ledger = ref<Ledger | null>(null)
const loading = ref(true)
const showAll = ref(false)

async function load(url: string): Promise<Ledger | null> {
  try {
    const res = await fetch(url, { cache: 'no-cache' })
    if (!res.ok) return null
    const doc = await res.json()
    return Array.isArray(doc?.entries) ? doc : null
  } catch { return null }
}

onMounted(async () => {
  // A missing ledger is the normal state before the first merged fix: show the empty board, not an error.
  ledger.value = await load('/blindness/ledger.json')
  loading.value = false
})

const people = computed(() => ledger.value?.contributors ?? [])
const shown = computed(() => (showAll.value ? people.value : people.value.slice(0, 10)))
const recent = computed(() => [...(ledger.value?.entries ?? [])].sort((a, b) => b.merged_at.localeCompare(a.merged_at)).slice(0, 6))
const core = computed(() => people.value.filter(p => p.badges.some(b => b.id === 'core-contributor')))

const LABEL: Record<string, [string, string]> = {
  prs: ['merged fix', 'merged fixes'], points: ['point', 'points'], sinks: ['blind spot', 'blind spots'],
  cleared: ['cleared challenge', 'cleared challenges'], hard_cleared: ['hard challenge', 'hard challenges'], languages: ['language', 'languages'],
}
function nextText(p: Contributor) {
  if (!p.next) return ''
  const parts = Object.entries(p.next.missing).map(([k, v]) => `${v} more ${(LABEL[k] ?? [k, k])[v === 1 ? 0 : 1]}`)
  return `Next: ${p.next.name}, ${parts.join(' and ')}`
}
const date = (iso: string) => (iso ? iso.slice(0, 10) : '')
</script>

<template>
  <div class="lb">
    <p v-if="loading" class="lb-empty">Loading…</p>

    <div v-else-if="!people.length" class="lb-empty">
      <b>No fixes merged yet.</b>
      <span>The first merged fix for a challenge earns <em>First Light</em>. Open the Challenges tab, pick one and put <code>Solves: BG-…</code> in your pull request.</span>
    </div>

    <template v-else>
      <div v-if="core.length" class="lb-core">
        <span class="lb-core-label">Core contributors</span>
        <a v-for="p in core" :key="p.login" :href="`https://github.com/${p.login}`" target="_blank" rel="noopener noreferrer">
          <img :src="`https://github.com/${p.login}.png?size=48`" :alt="p.login" width="24" height="24" loading="lazy" />{{ p.login }}
        </a>
      </div>

      <ol class="lb-list">
        <li v-for="(p, i) in shown" :key="p.login">
          <span class="rank">{{ i + 1 }}</span>
          <img :src="`https://github.com/${p.login}.png?size=64`" :alt="''" width="32" height="32" loading="lazy" />
          <div class="who">
            <a :href="`https://github.com/${p.login}`" target="_blank" rel="noopener noreferrer">{{ p.login }}</a>
            <span class="badges">
              <span v-for="b in p.badges" :key="b.id" class="badge" :class="{ core: b.id === 'core-contributor' }"
                    :title="`${b.description} (${date(b.earned_at)})`">{{ b.name }}</span>
            </span>
            <small v-if="p.next">{{ nextText(p) }}</small>
          </div>
          <div class="nums">
            <b>{{ p.points }}</b><small>points</small>
          </div>
          <div class="nums hide-sm">
            <b>{{ p.prs }}</b><small>fix{{ p.prs === 1 ? '' : 'es' }}</small>
          </div>
        </li>
      </ol>
      <button v-if="people.length > 10" class="lb-more" @click="showAll = !showAll">{{ showAll ? 'Show top 10' : `Show all ${people.length}` }}</button>

      <h3>Recent fixes</h3>
      <ul class="lb-recent">
        <li v-for="e in recent" :key="e.id">
          <a :href="e.pr_url" target="_blank" rel="noopener noreferrer">#{{ e.pr }}</a>
          <span class="t">{{ e.pr_title }}</span>
          <span class="m">{{ e.author }} · {{ e.repo }} · {{ e.sinks_solved }} sink{{ e.sinks_solved === 1 ? '' : 's' }}<template v-if="e.cleared"> · cleared</template> · +{{ e.points }}</span>
        </li>
      </ul>
    </template>
  </div>
</template>

<style scoped>
.lb-empty { display: flex; flex-direction: column; gap: .35rem; align-items: center; text-align: center; color: var(--vp-c-text-2); padding: 2.5rem 1rem; background: var(--vp-c-bg-elv); border: 1px dashed var(--vp-c-border); border-radius: 8px; }
.lb-empty b { color: var(--vp-c-text-1); }
.lb-core { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem .9rem; padding: .7rem 1rem; margin-bottom: 1rem; background: var(--vp-c-brand-soft); border-radius: 8px; font-size: .88rem; }
.lb-core-label { font-weight: 600; color: var(--vp-c-brand-1); }
.lb-core a { display: inline-flex; align-items: center; gap: .4rem; color: var(--vp-c-text-1); text-decoration: none; font-weight: 500; }
.lb-core img, .lb-list img { border-radius: 50%; background: var(--vp-c-bg-soft); }
.lb-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: .5rem; }
.lb-list li { display: flex; align-items: center; gap: .75rem; background: var(--vp-c-bg-elv); border: 1px solid var(--vp-c-border); border-radius: 8px; padding: .65rem .9rem; margin: 0; }
.rank { width: 1.4rem; text-align: center; color: var(--vp-c-text-3); font-variant-numeric: tabular-nums; font-weight: 600; }
.who { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: .2rem; }
.who > a { font-weight: 600; color: var(--vp-c-text-1); text-decoration: none; }
.who > a:hover { color: var(--vp-c-brand-1); }
.who small { color: var(--vp-c-text-2); font-size: .75rem; }
.badges { display: flex; flex-wrap: wrap; gap: .3rem; }
.badge { font-size: .7rem; padding: .05rem .5rem; border-radius: 999px; border: 1px solid var(--vp-c-border); color: var(--vp-c-text-2); background: var(--vp-c-bg-soft); cursor: default; }
.badge.core { background: var(--vp-c-brand-1); border-color: var(--vp-c-brand-1); color: #fff; font-weight: 600; }
.nums { display: flex; flex-direction: column; align-items: flex-end; min-width: 3.2rem; line-height: 1.2; }
.nums b { font-variant-numeric: tabular-nums; color: var(--vp-c-text-1); }
.nums small { font-size: .7rem; color: var(--vp-c-text-2); }
.lb-more { margin: .75rem auto 0; display: block; background: none; border: 0; color: var(--vp-c-brand-1); cursor: pointer; font-size: .85rem; }
h3 { margin: 1.75rem 0 .5rem; border: 0; padding: 0; font-size: 1rem; }
.lb-recent { list-style: none; margin: 0; padding: 0; font-size: .85rem; }
.lb-recent li { display: grid; grid-template-columns: auto 1fr; gap: 0 .6rem; padding: .45rem 0; border-bottom: 1px solid var(--vp-c-divider); margin: 0; }
.lb-recent .t { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--vp-c-text-1); }
.lb-recent .m { grid-column: 2; color: var(--vp-c-text-2); font-size: .76rem; }
@media (max-width: 560px) { .hide-sm { display: none; } }
</style>
