import DefaultTheme from 'vitepress/theme'
import BlogIndex from './BlogIndex.vue'
import DownloadStrip from './DownloadStrip.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app, router }) {
    app.component('BlogIndex', BlogIndex)
    app.component('DownloadStrip', DownloadStrip)

    if (typeof window !== 'undefined') {
      const ensureMainLandmark = () => {
        setTimeout(() => {
          if (!document.querySelector('main, [role="main"]')) {
            const content = document.getElementById('VPContent')
            if (content) content.setAttribute('role', 'main')
          }
        }, 0)
      }
      window.addEventListener('DOMContentLoaded', ensureMainLandmark)
      if (router) {
        router.onAfterRouteChanged = () => {
          ensureMainLandmark()
        }
      }
    }
  }
}
