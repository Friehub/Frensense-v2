<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (c) 2024-2026 Friehub. All rights reserved. -->
<script setup lang="ts">
import { onMounted, ref } from 'vue'
import {
  LANGUAGES,
  activeLanguage,
  applyLanguage,
  isTranslateEnabled,
  mountTranslate
} from './translate'

// `screen` renders the picker inside the mobile hamburger menu instead of the
// desktop navbar.
const props = defineProps<{ screen?: boolean }>()

// Nothing renders unless a translation host was compiled in: a picker that
// cannot translate anything is worse than no picker.
const enabled = isTranslateEnabled()
const ready = ref(false)

onMounted(async () => {
  if (!enabled) return
  // Mount first: it consumes `?lang=`, so the control shows the language the
  // page is actually in rather than the one that was stored before it.
  // A picker that cannot translate is worse than no picker, so stay hidden
  // when the service is unreachable (mountTranslate returns null on failure).
  const language = await mountTranslate()
  ready.value = language !== null
})

function onChange(event: Event) {
  applyLanguage((event.target as HTMLSelectElement).value)
}
</script>

<template>
  <label
    v-if="enabled"
    class="lang-picker"
    :class="{ 'is-ready': ready, 'lang-picker--screen': props.screen }"
  >
    <span class="visually-hidden">Documentation language</span>
    <select
      :value="activeLanguage"
      aria-label="Documentation language"
      title="Machine translation. The English text is authoritative."
      @change="onChange"
    >
      <option v-for="language in LANGUAGES" :key="language.id" :value="language.id">
        {{ language.label }}
      </option>
    </select>
  </label>
</template>
