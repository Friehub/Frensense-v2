// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

/**
 * Client-side machine translation for the docs site.
 *
 * translate.js (MIT, https://translate.zvo.cn) rewrites text nodes in place:
 * no per-language build, no language files, no API key. It is loaded lazily
 * after hydration, and only when `FRENSENSE_TRANSLATE_HOST` was set at build
 * time - an unset host disables the feature rather than shipping a picker that
 * talks to a service nobody deployed.
 *
 * Two rules the rest of this file exists to enforce:
 *
 * 1. It must never run during the SSR build. translate.js touches
 *    `XMLHttpRequest` in its own module body, so it is reached only through
 *    the dynamic import inside `mountTranslate()`.
 * 2. Code is never translated. `--compare-baseline` mangled into another
 *    language is worse than an untranslated page, so every element that can
 *    carry source text is on the ignore list before the first request.
 */

import { ref } from 'vue'

/** Injected by `vite.define` in `.vitepress/config.mts`. */
declare const __TRANSLATE_HOST__: string

/** One row of the picker: a translate.js id, its own-language label, its tag. */
export interface LanguageOption {
  /** translate.js language id, as accepted by `selectLanguageTag.languages`. */
  id: string
  /** Name of the language in that language. */
  label: string
  /** Value written to `<html lang>` when this language is active. */
  htmlLang: string
}

/**
 * The languages the picker offers, English first because it is authoritative.
 * Ids are translate.js ids - `deutsch`, not `german`; an id the script does
 * not recognise is dropped without an error, so these are checked against the
 * script's own vocabulary rather than guessed.
 *
 * Arabic is deliberately absent: the default theme is not RTL, and a
 * right-to-left page rendered through a left-to-right layout reads as broken.
 * Add it together with a `dir` switch, not before.
 */
export const LANGUAGES: readonly LanguageOption[] = [
  { id: 'english', label: 'English', htmlLang: 'en' },
  { id: 'chinese_simplified', label: '简体中文', htmlLang: 'zh-CN' },
  { id: 'chinese_traditional', label: '繁體中文', htmlLang: 'zh-TW' },
  { id: 'japanese', label: '日本語', htmlLang: 'ja' },
  { id: 'korean', label: '한국어', htmlLang: 'ko' },
  { id: 'deutsch', label: 'Deutsch', htmlLang: 'de' },
  { id: 'spanish', label: 'Español', htmlLang: 'es' },
  { id: 'french', label: 'Français', htmlLang: 'fr' },
  { id: 'portuguese', label: 'Português', htmlLang: 'pt' },
  { id: 'italian', label: 'Italiano', htmlLang: 'it' },
  { id: 'russian', label: 'Русский', htmlLang: 'ru' }
]

/**
 * Terminology that must survive translation verbatim. translate.js matches
 * whole words and phrases, not sentences, so this is a product-name guard
 * rather than a style guide. Keep it in sync with the CLI's glossary when the
 * CLI grows one (`src/i18n/`).
 */
const GLOSSARY = [
  'Frensense=Frensense',
  '.frc=.frc',
  'SVFG=SVFG',
  'frensense=frensense',
  'MCP=MCP',
  'LSP=LSP',
  'taint=taint',
  'dataflow=dataflow',
  'codebase=codebase'
].join('\n')

/** localStorage key holding the reader's choice, so it survives navigation. */
const STORAGE_KEY = 'frensense.lang'

/** Query parameter that opens a page in a given language (`?lang=ja`). */
const QUERY_KEY = 'lang'

/** The subset of the translate.js API this site uses. */
interface TranslateJs {
  language: {
    setLocal(id: string): void
    setDefaultTo(id: string): void
  }
  request: { setHost(hosts: string[]): void }
  selectLanguageTag: { show: boolean; languages: string }
  ignore: {
    tag: string[]
    id: string[]
    class: { push(name: string): void }
  }
  nomenclature: { append(from: string, to: string, terms: string): void }
  listener: { start(): void }
  execute(): void
  changeLanguage(id: string): void
}

let instance: TranslateJs | null = null
let starting: Promise<string | null> | null = null

/**
 * The language currently shown. A page can mount the picker twice (navbar and
 * mobile menu), so this is shared module state rather than per-component `ref`.
 */
export const activeLanguage = ref('english')

/** The build-time host, normalised to the trailing slash translate.js wants. */
export function translateHost(): string {
  if (typeof __TRANSLATE_HOST__ !== 'string') return ''
  const host = __TRANSLATE_HOST__.trim()
  if (!host) return ''
  return host.endsWith('/') ? host : `${host}/`
}

/** Is the feature compiled in? False whenever no host was configured. */
export function isTranslateEnabled(): boolean {
  return translateHost().length > 0
}

/**
 * Read `?lang=<id>` once, remember it, and drop the parameter from the
 * address bar so a later pick in the UI is not overruled by a stale URL.
 */
function consumeQueryLanguage(): void {
  const url = new URL(window.location.href)
  const fromQuery = url.searchParams.get(QUERY_KEY)
  if (!fromQuery) return
  url.searchParams.delete(QUERY_KEY)
  window.history.replaceState(window.history.state, '', url.toString())
  if (isKnown(fromQuery)) store(fromQuery)
}

function isKnown(id: string | null): boolean {
  return id !== null && LANGUAGES.some((language) => language.id === id)
}

function readStored(): string | null {
  try {
    return window.localStorage.getItem(STORAGE_KEY)
  } catch {
    // Storage can be unavailable (private mode, blocked cookies); a reader
    // without persistence still gets the translation.
    return null
  }
}


function store(id: string): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, id)
  } catch {
    /* no persistence, no failure */
  }
}

function applyHtmlLang(id: string): void {
  const language = LANGUAGES.find((candidate) => candidate.id === id)
  if (language) document.documentElement.lang = language.htmlLang
}

/**
 * Load translate.js. The package is UMD: in a bundler it exposes the instance
 * as `module.exports`, and as a plain `<script>` it assigns `window.translate`.
 * Handle both so a future packaging change on their side cannot silently
 * produce an undefined picker.
 */
async function load(): Promise<TranslateJs> {
  const module = (await import('i18n-jsautotranslate')) as unknown as {
    default?: TranslateJs
  }
  const translate =
    module.default ?? (window as unknown as { translate?: TranslateJs }).translate
  if (!translate) {
    throw new Error('translate.js exposed no instance')
  }
  return translate
}

function configure(translate: TranslateJs): void {
  // The site is authored in English. Stating it skips the detector's
  // frequency analysis and stops a short page from being guessed wrong.
  translate.language.setLocal('english')

  // Our own translate.service, never the vendor's shared edge channel: this
  // is what keeps page text on our infrastructure. The host is set through
  // `request.setHost`, which also switches `service.use` to `translate.service`.
  translate.request.setHost([translateHost()])

  // The stock <select> is not ours - `LanguagePicker.vue` owns the choice.
  translate.selectLanguageTag.show = false
  translate.selectLanguageTag.languages = LANGUAGES.map((language) => language.id).join(',')

  // Never send source text, identifiers or CLI flags to the service.
  for (const tag of ['pre', 'code', 'kbd', 'samp', 'var', 'script', 'style']) {
    translate.ignore.tag.push(tag)
  }
  for (const className of [
    'lang',
    'copy',
    'vp-code',
    'shiki',
    'line-numbers-mode',
    'ignore',
    'no-translate',
    // The picker's own option labels are language names; translating them
    // turns "Deutsch" into "German" in a German menu.
    'lang-picker'
  ]) {
    translate.ignore.class.push(className)
  }
  // translate.js materialises a container for its own control if the page has
  // none; keep it out of the translation pass.
  translate.ignore.id.push('translate')

  for (const language of LANGUAGES) {
    if (language.id !== 'english') {
      translate.nomenclature.append('english', language.id, GLOSSARY)
    }
  }

  // MutationObserver: content VitePress swaps in on navigation is translated
  // without a second `execute()` call.
  translate.listener.start()
}

/**
 * Load, configure and apply the reader's language. Idempotent: repeated calls
 * (every layout mount, every hot reload) reuse the first load.
 *
 * Returns the language now active, or `null` when translation is unavailable
 * (not configured, or the script failed to load). A failure is deliberately
 * not fatal: English is always a valid page.
 */
export function mountTranslate(): Promise<string | null> {
  if (!isTranslateEnabled()) return Promise.resolve(null)
  if (starting) return starting

  starting = (async () => {
    try {
      // Before the first request, so `?lang=` and the stored choice agree.
      consumeQueryLanguage()
      const stored = readStored()
      const language = stored !== null && isKnown(stored) ? stored : 'english'

      const translate = await load()
      configure(translate)
      instance = translate
      activeLanguage.value = language

      if (language !== 'english') {
        // `setDefaultTo` picks the target before the first pass, so the page
        // is translated once instead of twice (English, then the target).
        translate.language.setDefaultTo(language)
        translate.changeLanguage(language)
      } else {
        translate.execute()
      }
      applyHtmlLang(language)
      return language
    } catch (error) {
      // A failed translator must not break the page: English still renders.
      console.warn('[docs] machine translation unavailable:', error)
      return null
    }
  })()

  return starting
}

/** Switch language from the picker. */
export function applyLanguage(id: string): void {
  if (!isKnown(id)) return
  activeLanguage.value = id
  store(id)
  applyHtmlLang(id)
  instance?.changeLanguage(id)
}

/**
 * Re-run translation after a client-side navigation. VitePress replaces the
 * `vp-doc` subtree wholesale, and `listener.start()` does not always observe
 * that as a mutation, so a route change is the one place we ask explicitly.
 */
export function onRouteChanged(): void {
  if (!instance || activeLanguage.value === 'english') return
  instance.execute()
}
