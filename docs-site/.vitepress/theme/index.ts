import DefaultTheme from 'vitepress/theme'
import BlogIndex from './BlogIndex.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('BlogIndex', BlogIndex)
  }
}
