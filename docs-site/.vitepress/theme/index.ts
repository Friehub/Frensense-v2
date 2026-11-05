import { h } from 'vue'
import DefaultTheme from 'vitepress/theme'
import AnnouncementBanner from './AnnouncementBanner.vue'
import BlogIndex from './BlogIndex.vue'
import DownloadStrip from './DownloadStrip.vue'
import BlindnessSheet from './BlindnessSheet.vue'
import BlindnessChallenges from './BlindnessChallenges.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  // Layout.vue (language picker) is not wired in; the banner mounts through the
  // default theme's layout-top slot without touching it.
  Layout: () => h(DefaultTheme.Layout, null, { 'layout-top': () => h(AnnouncementBanner) }),
  enhanceApp({ app, router }) {
    app.component('BlogIndex', BlogIndex)
    app.component('DownloadStrip', DownloadStrip)
    app.component('BlindnessSheet', BlindnessSheet)
    app.component('BlindnessChallenges', BlindnessChallenges)

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
