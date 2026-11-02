<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (c) 2024-2026 Friehub. All rights reserved. -->
<script setup lang="ts">
import DefaultTheme from 'vitepress/theme'
import LanguagePicker from './LanguagePicker.vue'

const { Layout } = DefaultTheme
</script>

<template>
  <Layout>
    <!-- Desktop navbar, and the hamburger menu on narrow screens: the default
         theme has no shared slot, so the picker is mounted in both. -->
    <template #nav-bar-content-after>
      <LanguagePicker />
    </template>
    <template #nav-screen-content-after>
      <LanguagePicker screen />
    </template>
  </Layout>
</template>
