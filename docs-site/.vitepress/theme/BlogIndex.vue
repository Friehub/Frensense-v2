<script setup lang="ts">
import { data as posts } from '../loaders/blog.data'
import { formatDate } from '../support'

const sorted = [...posts]
  .filter((p) => p.frontmatter.date && !String(p.frontmatter.date).startsWith('1970'))
  .sort((a, b) => +new Date(b.frontmatter.date) - +new Date(a.frontmatter.date))
</script>

<template>
  <div class="blog-list">
    <h1>Blog</h1>
    <p class="lead">Notes from the frensense engine rebuild.</p>
    <article v-for="post of sorted" :key="post.url" class="blog-card">
      <div class="date">{{ formatDate(post.frontmatter.date) }}</div>
      <h2>
        <a :href="post.url">{{ post.frontmatter.title }}</a>
      </h2>
      <p v-if="post.frontmatter.description">{{ post.frontmatter.description }}</p>
      <a class="read-more" :href="post.url">Read more</a>
    </article>
  </div>
</template>

<style scoped>
.blog-list { max-width: 720px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }
.lead { color: var(--vp-c-text-2); margin-bottom: 2.5rem; }
.blog-card { border-top: 1px solid var(--vp-c-divider); padding: 1.5rem 0; }
.date { font-size: 0.85rem; color: var(--vp-c-text-3); }
h2 { margin: 0.25rem 0 0.5rem; border: none; }
h2 a { color: var(--vp-c-text-1); text-decoration: none; }
h2 a:hover { color: var(--vp-c-brand-1); }
.read-more { font-size: 0.9rem; }
</style>
