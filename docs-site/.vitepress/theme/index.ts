import DefaultTheme from 'vitepress/theme'
import BlogIndex from './BlogIndex.vue'
import DownloadStrip from './DownloadStrip.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('BlogIndex', BlogIndex)
    app.component('DownloadStrip', DownloadStrip)
  }
}
