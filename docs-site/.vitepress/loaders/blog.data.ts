import { createContentLoader } from 'vitepress'

export default createContentLoader('blog/*.md', {
  excerpt: true,
  transformRawData({ frontmatter }) {
    if (!frontmatter.date) frontmatter.date = '1970-01-01'
  }
})
