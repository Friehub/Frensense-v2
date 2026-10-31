<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'

interface RepoStat {
  files_scanned?: number
  files_partial?: number
  total_sinks?: number
  unknown_sinks?: number
  blindness_rate?: number
  truncation_caps?: number
  peak_rss_mb?: number
  wall_s?: number
}

interface OverallStats {
  blindness_rate: number
  total_sinks: number
  unknown_sinks: number
  clean_sinks?: number
  sanitized_sinks?: number
  vulnerable_sinks?: number
  truncation_caps: number
  caps_breakdown?: Record<string, number>
  files_scanned: number
  files_partial: number
  peak_rss_mb?: number
  wall_s: number
}

interface CommitRecord {
  commit: string
  short_sha: string
  branch: string
  author: string
  date: string
  message: string
  overall: OverallStats
  by_repo?: Record<string, RepoStat>
}

const history = ref<CommitRecord[]>([])
const loading = ref(true)
const searchQuery = ref('')
const expandedCommit = ref<string | null>(null)

onMounted(async () => {
  try {
    const res = await fetch('/data/blindness_history.json')
    if (res.ok) {
      history.value = await res.json()
    }
  } catch (err) {
    console.error('Failed to load blindness history:', err)
  } finally {
    loading.value = false
  }
})

const filteredHistory = computed(() => {
  const q = searchQuery.value.toLowerCase().trim()
  if (!q) return [...history.value].reverse()
  return history.value.filter(item => {
    return (
      item.short_sha.toLowerCase().includes(q) ||
      item.commit.toLowerCase().includes(q) ||
      item.message.toLowerCase().includes(q) ||
      item.author.toLowerCase().includes(q) ||
      item.branch.toLowerCase().includes(q)
    )
  }).reverse()
})

const latest = computed(() => {
  if (history.value.length === 0) return null
  return history.value[history.value.length - 1]
})

function toggleExpand(sha: string) {
  expandedCommit.value = expandedCommit.value === sha ? null : sha
}

function formatDate(iso: string): string {
  if (!iso) return ''
  try {
    const d = new Date(iso)
    return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC'
  } catch {
    return iso
  }
}

function downloadCsv() {
  if (history.value.length === 0) return
  const headers = [
    'commit', 'short_sha', 'date', 'branch', 'author', 'message',
    'global_blindness_rate', 'total_sinks', 'unknown_sinks', 'clean_sinks',
    'vulnerable_sinks', 'total_caps_hit', 'peak_rss_mb', 'wall_time_s',
    'repos_scanned', 'total_files_scanned', 'partial_files'
  ]
  const rows = history.value.map(r => [
    `"${r.commit}"`,
    `"${r.short_sha}"`,
    `"${r.date}"`,
    `"${r.branch}"`,
    `"${r.author.replace(/"/g, '""')}"`,
    `"${r.message.replace(/"/g, '""')}"`,
    r.overall.blindness_rate,
    r.overall.total_sinks,
    r.overall.unknown_sinks,
    r.overall.clean_sinks ?? 0,
    r.overall.vulnerable_sinks ?? 0,
    r.overall.truncation_caps,
    r.overall.peak_rss_mb ?? '',
    r.overall.wall_s,
    Object.keys(r.by_repo ?? {}).length,
    r.overall.files_scanned,
    r.overall.files_partial,
  ])
  const csvContent = [headers.join(','), ...rows.map(row => row.join(','))].join('\n')
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'frensense_blindness_sheet.csv'
  a.click()
  URL.revokeObjectURL(url)
}

function downloadJson() {
  const blob = new Blob([JSON.stringify(history.value, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'frensense_blindness_history.json'
  a.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <div class="blindness-dashboard">
    <!-- Top KPI Cards -->
    <div v-if="latest" class="kpi-grid">
      <div class="kpi-card">
        <span class="kpi-label">Global Blindness Rate</span>
        <span class="kpi-value text-accent">{{ latest.overall.blindness_rate }}%</span>
        <span class="kpi-sub">{{ latest.overall.unknown_sinks }} of {{ latest.overall.total_sinks }} sinks blind</span>
      </div>
      <div class="kpi-card">
        <span class="kpi-label">Explored Sinks</span>
        <span class="kpi-value">{{ latest.overall.total_sinks }}</span>
        <span class="kpi-sub">Demand-driven backward paths</span>
      </div>
      <div class="kpi-card">
        <span class="kpi-label">Safety Caps Fired</span>
        <span class="kpi-value" :class="{ 'text-warn': latest.overall.truncation_caps > 0 }">
          {{ latest.overall.truncation_caps }}
        </span>
        <span class="kpi-sub">Bounded traversal terminations</span>
      </div>
      <div class="kpi-card">
        <span class="kpi-label">Peak RSS</span>
        <span class="kpi-value">{{ latest.overall.peak_rss_mb ?? '-' }} <small>MB</small></span>
        <span class="kpi-sub">Max resident memory profile</span>
      </div>
    </div>

    <!-- Actions & Filter Bar -->
    <div class="toolbar">
      <div class="search-box">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Filter by commit SHA, message, author..."
          class="search-input"
        />
      </div>
      <div class="button-group">
        <button class="btn btn-secondary" @click="downloadCsv">
          Export CSV Sheet
        </button>
        <button class="btn btn-secondary" @click="downloadJson">
          Raw JSON
        </button>
      </div>
    </div>

    <!-- Data Sheet Table -->
    <div class="table-container">
      <table class="sheet-table">
        <thead>
          <tr>
            <th style="width: 110px;">Commit</th>
            <th style="width: 140px;">Date (UTC)</th>
            <th>Commit Message</th>
            <th style="text-align: right; width: 130px;">Blindness Rate</th>
            <th style="text-align: right; width: 90px;">Caps Hit</th>
            <th style="text-align: right; width: 95px;">Peak RSS</th>
            <th style="text-align: right; width: 85px;">Time</th>
            <th style="text-align: center; width: 80px;">Details</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="item in filteredHistory" :key="item.commit">
            <tr class="table-row" :class="{ 'row-expanded': expandedCommit === item.short_sha }">
              <td>
                <a
                  :href="`https://github.com/Friehub/frensense-v2/commit/${item.commit}`"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="commit-link"
                >
                  <code>{{ item.short_sha }}</code>
                </a>
              </td>
              <td class="text-muted text-sm">{{ formatDate(item.date) }}</td>
              <td class="commit-message">
                <span class="msg-text">{{ item.message }}</span>
                <span class="branch-tag">{{ item.branch }}</span>
              </td>
              <td style="text-align: right;">
                <span class="rate-badge" :class="item.overall.blindness_rate > 15 ? 'badge-high' : 'badge-ok'">
                  {{ item.overall.blindness_rate }}%
                </span>
              </td>
              <td style="text-align: right;">
                <span class="caps-badge" :class="{ 'has-caps': item.overall.truncation_caps > 0 }">
                  {{ item.overall.truncation_caps }}
                </span>
              </td>
              <td style="text-align: right;" class="text-sm">
                {{ item.overall.peak_rss_mb ? `${item.overall.peak_rss_mb} MB` : '-' }}
              </td>
              <td style="text-align: right;" class="text-sm">{{ item.overall.wall_s }}s</td>
              <td style="text-align: center;">
                <button class="expand-btn" @click="toggleExpand(item.short_sha)">
                  {{ expandedCommit === item.short_sha ? 'Hide' : 'Inspect' }}
                </button>
              </td>
            </tr>

            <!-- Expanded Row: Repository Breakdown and Caps -->
            <tr v-if="expandedCommit === item.short_sha" class="expanded-row">
              <td colspan="8">
                <div class="detail-box">
                  <div class="detail-section">
                    <h4>Per-Repository Breakdown</h4>
                    <table class="sub-table">
                      <thead>
                        <tr>
                          <th>Repository</th>
                          <th style="text-align: right;">Scanned Files</th>
                          <th style="text-align: right;">Partial Files</th>
                          <th style="text-align: right;">Total Sinks</th>
                          <th style="text-align: right;">Unknown (Blind)</th>
                          <th style="text-align: right;">Blindness Rate</th>
                          <th style="text-align: right;">Caps Hit</th>
                          <th style="text-align: right;">Peak RSS</th>
                          <th style="text-align: right;">Time</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr v-for="(stat, name) in item.by_repo" :key="name">
                          <td><strong>{{ name }}</strong></td>
                          <td style="text-align: right;">{{ stat.files_scanned ?? '-' }}</td>
                          <td style="text-align: right;">{{ stat.files_partial ?? 0 }}</td>
                          <td style="text-align: right;">{{ stat.total_sinks ?? '-' }}</td>
                          <td style="text-align: right;">{{ stat.unknown_sinks ?? '-' }}</td>
                          <td style="text-align: right;"><strong>{{ stat.blindness_rate ?? 0 }}%</strong></td>
                          <td style="text-align: right;">{{ stat.truncation_caps ?? 0 }}</td>
                          <td style="text-align: right;">{{ stat.peak_rss_mb ? `${stat.peak_rss_mb} MB` : '-' }}</td>
                          <td style="text-align: right;">{{ stat.wall_s ? `${stat.wall_s}s` : '-' }}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>

                  <div v-if="item.overall.caps_breakdown && Object.keys(item.overall.caps_breakdown).length > 0" class="detail-section">
                    <h4>Safety Valve Bounds Fired (Dataflow Halts)</h4>
                    <div class="caps-tags">
                      <span
                        v-for="(count, cap) in item.overall.caps_breakdown"
                        :key="cap"
                        class="cap-pill"
                      >
                        <code>{{ cap }}</code>: <strong>{{ count }}</strong>
                      </span>
                    </div>
                  </div>
                </div>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.blindness-dashboard {
  margin: 1.5rem 0 3rem;
  font-family: var(--vp-font-family-base);
}

.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.kpi-card {
  background: var(--vp-c-bg-elv);
  border: 1px solid var(--vp-c-border);
  border-radius: 8px;
  padding: 1rem 1.25rem;
  display: flex;
  flex-direction: column;
}

.kpi-label {
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--vp-c-text-2);
  margin-bottom: 0.25rem;
}

.kpi-value {
  font-size: 1.75rem;
  font-weight: 800;
  line-height: 1.2;
}

.kpi-sub {
  font-size: 0.75rem;
  color: var(--vp-c-text-3);
  margin-top: 0.25rem;
}

.text-accent {
  color: var(--vp-c-brand-1);
}

.text-warn {
  color: #f59e0b;
}

.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
  margin-bottom: 1rem;
  flex-wrap: wrap;
}

.search-box {
  flex: 1;
  min-width: 260px;
}

.search-input {
  width: 100%;
  padding: 0.5rem 0.85rem;
  background: var(--vp-c-bg-elv);
  border: 1px solid var(--vp-c-border);
  border-radius: 6px;
  color: var(--vp-c-text-1);
  font-size: 0.875rem;
}

.search-input:focus {
  outline: none;
  border-color: var(--vp-c-brand-1);
}

.button-group {
  display: flex;
  gap: 0.5rem;
}

.btn {
  padding: 0.45rem 0.85rem;
  border-radius: 6px;
  font-size: 0.825rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
}

.btn-secondary {
  background: var(--vp-c-bg-alt);
  border: 1px solid var(--vp-c-border);
  color: var(--vp-c-text-1);
}

.btn-secondary:hover {
  background: var(--vp-c-bg-soft);
  border-color: var(--vp-c-brand-1);
  color: var(--vp-c-brand-1);
}

.table-container {
  overflow-x: auto;
  border: 1px solid var(--vp-c-border);
  border-radius: 8px;
  background: var(--vp-c-bg-elv);
}

.sheet-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
  margin: 0;
}

.sheet-table th {
  background: var(--vp-c-bg-alt);
  padding: 0.65rem 0.85rem;
  font-weight: 600;
  color: var(--vp-c-text-2);
  border-bottom: 1px solid var(--vp-c-border);
  font-size: 0.8rem;
  text-transform: uppercase;
}

.sheet-table td {
  padding: 0.75rem 0.85rem;
  border-bottom: 1px solid var(--vp-c-divider);
}

.table-row:hover {
  background: var(--vp-c-bg-soft);
}

.row-expanded {
  background: var(--vp-c-bg-soft);
}

.commit-link code {
  color: var(--vp-c-brand-1);
  font-weight: 600;
}

.commit-message {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.msg-text {
  max-width: 380px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.branch-tag {
  font-size: 0.7rem;
  background: var(--vp-c-bg-alt);
  border: 1px solid var(--vp-c-border);
  padding: 0.1rem 0.35rem;
  border-radius: 4px;
  color: var(--vp-c-text-2);
}

.rate-badge {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-weight: 700;
  font-size: 0.825rem;
}

.badge-ok {
  background: rgba(28, 200, 88, 0.15);
  color: #1cc858;
}

.badge-high {
  background: rgba(239, 68, 68, 0.15);
  color: #ef4444;
}

.caps-badge {
  display: inline-block;
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
  font-size: 0.8rem;
  color: var(--vp-c-text-3);
}

.caps-badge.has-caps {
  background: rgba(245, 158, 11, 0.15);
  color: #f59e0b;
  font-weight: 600;
}

.expand-btn {
  background: transparent;
  border: 1px solid var(--vp-c-border);
  border-radius: 4px;
  padding: 0.2rem 0.55rem;
  font-size: 0.75rem;
  color: var(--vp-c-text-2);
  cursor: pointer;
}

.expand-btn:hover {
  border-color: var(--vp-c-brand-1);
  color: var(--vp-c-brand-1);
}

.expanded-row td {
  background: var(--vp-c-bg-alt);
  padding: 1.25rem;
}

.detail-box {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.detail-section h4 {
  margin: 0 0 0.5rem;
  font-size: 0.875rem;
  font-weight: 700;
  color: var(--vp-c-text-1);
}

.sub-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.825rem;
  background: var(--vp-c-bg-elv);
  border-radius: 6px;
  border: 1px solid var(--vp-c-border);
}

.sub-table th, .sub-table td {
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--vp-c-divider);
}

.caps-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.cap-pill {
  background: var(--vp-c-bg-elv);
  border: 1px solid var(--vp-c-border);
  padding: 0.25rem 0.55rem;
  border-radius: 4px;
  font-size: 0.8rem;
}

.text-muted {
  color: var(--vp-c-text-2);
}

.text-sm {
  font-size: 0.8rem;
}
</style>
