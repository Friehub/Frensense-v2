<script setup lang="ts">
import { onMounted, onBeforeUnmount, ref, nextTick } from 'vue'
import { withBase } from 'vitepress'
import data from '../../public/announcements.json'
import { pickAnnouncement, type Announcement } from './announcements'

const KEY = 'frensense:dismissed-announcements'
const bar = ref<Announcement | undefined>()
const popup = ref<Announcement | undefined>()
const closeBtn = ref<HTMLButtonElement | null>(null)

function readDismissed(): string[] {
  try {
    return JSON.parse(localStorage.getItem(KEY) || '[]')
  } catch {
    return []
  }
}

function remember(id: string) {
  try {
    localStorage.setItem(KEY, JSON.stringify([...readDismissed(), id]))
  } catch {}
}

function setOffset(on: boolean) {
  const root = document.documentElement
  if (on) root.style.setProperty('--vp-layout-top-height', '44px')
  else root.style.removeProperty('--vp-layout-top-height')
}

function dismissBar() {
  if (!bar.value) return
  remember(bar.value.id)
  bar.value = undefined
  setOffset(false)
}

function dismissPopup() {
  if (!popup.value) return
  remember(popup.value.id)
  popup.value = undefined
}

// Site-root paths go through withBase; absolute https:// URLs pass through.
const url = (s: string) => (s.startsWith('/') ? withBase(s) : s)

function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape') dismissPopup()
}

onMounted(() => {
  const list = data.announcements as Announcement[]
  const seen = readDismissed()
  bar.value = pickAnnouncement(list, seen, 'bar')
  setOffset(!!bar.value)
  const p = pickAnnouncement(list, seen, 'popup')
  if (p) {
    // A beat after load so it never competes with first paint.
    setTimeout(async () => {
      popup.value = p
      await nextTick()
      closeBtn.value?.focus()
    }, 1200)
  }
  window.addEventListener('keydown', onKey)
})
onBeforeUnmount(() => {
  setOffset(false)
  window.removeEventListener('keydown', onKey)
})
</script>

<template>
  <div v-if="bar" class="announce" :class="`tone-${bar.tone || 'brand'}`" role="region" aria-label="Announcement">
    <p class="announce-text">
      {{ bar.message }}
      <a v-if="bar.link" :href="url(bar.link.href)" class="announce-link">{{ bar.link.text }} &rarr;</a>
    </p>
    <button class="announce-close" type="button" aria-label="Dismiss announcement" @click="dismissBar">&times;</button>
  </div>

  <div v-if="popup" class="pop-backdrop" @click.self="dismissPopup">
    <div class="pop" role="dialog" aria-modal="true" :aria-label="popup.title || 'Announcement'">
      <button ref="closeBtn" class="pop-close" type="button" aria-label="Close" @click="dismissPopup">&times;</button>
      <img v-if="popup.image" class="pop-img" :src="url(popup.image.src)" :alt="popup.image.alt" />
      <div class="pop-body" :class="{ 'no-img': !popup.image }">
        <h2 v-if="popup.title" class="pop-title">{{ popup.title }}</h2>
        <p class="pop-text">{{ popup.message }}</p>
        <a v-if="popup.link" :href="url(popup.link.href)" class="pop-cta" @click="dismissPopup">{{ popup.link.text }} &rarr;</a>
      </div>
    </div>
  </div>
</template>

<style scoped>
.announcement-banner {
  position: relative;
  z-index: 100;
}

.announcement-banner__item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px 20px;
  margin-bottom: 8px;
  border-radius: 8px;
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-border);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
  transition: all 0.2s ease;
}

.announcement-banner__item:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
}

.announcement-banner__item--warning {
  border-color: var(--vp-c-yellow-4);
  background: rgba(250, 204, 21, 0.06);
}

.announcement-banner__item--info {
  border-color: var(--vp-c-blue-4);
  background: rgba(59, 130, 246, 0.06);
}

.announcement-banner__item--success {
  border-color: var(--vp-c-green-4);
  background: rgba(16, 185, 129, 0.06);
}

.announcement-banner__content {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.announcement-banner__title {
  font-weight: 600;
  font-size: 0.95rem;
  line-height: 1.3;
  color: var(--vp-c-text-1);
}

.announcement-banner__body {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.announcement-banner__text {
  font-size: 0.85rem;
  line-height: 1.5;
  color: var(--vp-c-text-2);
}

.announcement-banner__link {
  margin-top: 4px;
  font-size: 0.85rem;
}

.announcement-banner__link a {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--vp-c-brand);
  font-weight: 500;
  text-decoration: none;
  transition: color 0.2s ease;
}

.announcement-banner__link a:hover {
  color: var(--vp-c-brand-dark);
}

.announcement-banner__icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border-radius: 6px;
  flex-shrink: 0;
}

.announcement-banner__item--warning .announcement-banner__icon {
  background: rgba(250, 204, 21, 0.18);
  color: #f59e0b;
}

.announcement-banner__item--info .announcement-banner__icon {
  background: rgba(59, 130, 246, 0.18);
  color: #3b82f6;
}  .announcement-banner__item--success .announcement-banner__icon {
    background: rgba(16, 185, 129, 0.18);
    color: #10b983;
  }

/* Popup: a rectangle, image in the top half, text in the bottom half. */
.pop-backdrop {
  position: fixed;
  inset: 0;
  z-index: 200;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 16px;
  background: rgba(11, 16, 13, 0.6);
}
.pop {
  position: relative;
  display: flex;
  flex-direction: column;
  width: min(440px, 100%);
  height: min(480px, 100%);
  overflow: hidden;
  border-radius: 12px;
  background: var(--vp-c-bg, #fff);
  color: var(--vp-c-text-1, #0b100d);
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.35);
}
.pop-img { flex: 0 0 50%; width: 100%; min-height: 0; object-fit: cover; display: block; }
.pop-body {
  flex: 1 1 50%;
  min-height: 0;
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 18px 22px 20px;
  overflow: auto;
}
.pop-body.no-img { justify-content: center; }
.pop-title { margin: 0; border: 0; padding: 0; font-size: 22px; line-height: 1.2; font-weight: 800; }
.pop-text { margin: 0; font-size: 15px; line-height: 1.45; color: var(--vp-c-text-2, #4a524c); }
.pop-cta {
  margin-top: auto;
  align-self: flex-start;
  padding: 9px 16px;
  border-radius: 8px;
  background: #0b100d;
  color: #f1f5f2;
  font-weight: 700;
  font-size: 14px;
  text-decoration: none;
}
.pop-close {
  position: absolute;
  top: 10px;
  right: 10px;
  z-index: 1;
  width: 32px;
  height: 32px;
  border: 0;
  border-radius: 50%;
  background: #0b100d;
  color: #f1f5f2;
  font-size: 20px;
  line-height: 1;
  cursor: pointer;
}
.pop-close:focus-visible, .pop-cta:focus-visible { outline: 3px solid #20acff; outline-offset: 2px; }
</style>
