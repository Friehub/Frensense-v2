<script setup lang="ts">
import { data as posts } from '../loaders/blog.data'
import { formatDate } from '../support'

const sorted = [...posts]
  .filter((p) => p.frontmatter.date && !String(p.frontmatter.date).startsWith('1970'))
  .sort((a, b) => +new Date(b.frontmatter.date) - +new Date(a.frontmatter.date))
</script>

<template>
  <div class="blog-list">
    <header class="blog-header">
      <h1>Blog</h1>
      <p class="lead">Research, release notes, and architecture essays from the Frensense engineering team.</p>
    </header>

    <div class="blog-grid">
      <article v-for="post of sorted" :key="post.url" class="blog-card">
        <a :href="post.url" class="blog-card__media" :aria-label="post.frontmatter.title">
          <img
            :src="post.frontmatter.image || '/default-blog-cover.svg'"
            :alt="post.frontmatter.title"
            class="blog-card__img"
            loading="lazy"
          />
        </a>

        <div class="blog-card__body">
          <div class="date">{{ formatDate(post.frontmatter.date) }}</div>
          <h2>
            <a :href="post.url">{{ post.frontmatter.title }}</a>
          </h2>
          <p v-if="post.frontmatter.description" class="desc">
            {{ post.frontmatter.description }}
          </p>
          <a class="read-more" :href="post.url">Read article &rarr;</a>
        </div>
      </article>
    </div>
  </div>
</template>

<style scoped>
.blog-list {
  max-width: 860px;
  margin: 0 auto;
  padding: 2.5rem 1.5rem 5rem;
}
.blog-header {
  margin-bottom: 2.5rem;
}
.blog-header h1 {
  font-size: 2.25rem;
  font-weight: 800;
  letter-spacing: -0.02em;
  margin-bottom: 0.5rem;
}
.lead {
  color: var(--vp-c-text-2);
  font-size: 1.05rem;
  line-height: 1.5;
}
.blog-grid {
  display: flex;
  flex-direction: column;
  gap: 2rem;
}
.blog-card {
  display: flex;
  gap: 1.75rem;
  align-items: flex-start;
  padding-top: 2rem;
  border-top: 1px solid var(--vp-c-divider);
  transition: border-color 0.25s;
}
.blog-card__media {
  flex: 0 0 280px;
  width: 280px;
  aspect-ratio: 16 / 9;
  border-radius: 10px;
  overflow: hidden;
  border: 1px solid var(--vp-c-divider);
  background-color: var(--vp-c-bg-soft);
  display: block;
}
.blog-card__img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  display: block;
  transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);
}
.blog-card:hover .blog-card__img {
  transform: scale(1.03);
}
.blog-card__body {
  flex: 1;
  min-width: 0;
}
.date {
  font-size: 0.85rem;
  color: var(--vp-c-text-3);
  font-weight: 500;
  margin-bottom: 0.25rem;
}
h2 {
  font-size: 1.25rem;
  line-height: 1.35;
  font-weight: 700;
  margin: 0 0 0.5rem;
  border: none;
}
h2 a {
  color: var(--vp-c-text-1);
  text-decoration: none;
  transition: color 0.2s;
}
h2 a:hover {
  color: var(--vp-c-brand-1);
}
.desc {
  color: var(--vp-c-text-2);
  font-size: 0.95rem;
  line-height: 1.55;
  margin-bottom: 0.85rem;
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
.read-more {
  display: inline-flex;
  align-items: center;
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--vp-c-brand-1);
  text-decoration: none;
}
.read-more:hover {
  text-decoration: underline;
}

@media (max-width: 680px) {
  .blog-card {
    flex-direction: column;
    gap: 1rem;
  }
  .blog-card__media {
    flex: none;
    width: 100%;
  }
}
</style>
