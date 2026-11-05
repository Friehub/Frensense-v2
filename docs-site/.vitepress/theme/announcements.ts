export type Announcement = {
  /** First active announcement of this display type the visitor has not dismissed. */
  display?: 'bar' | 'popup'
  /** Popup headline. Ignored by the bar. */
  title?: string
  /** Popup picture, shown in the top half of the card. https:// or a path from the site root. */
  image?: { src: string; alt: string }
  tone?: 'brand' | 'info' | 'warn'
  link?: { text: string; href: string }
  /** Inclusive, YYYY-MM-DD (UTC). Omit for "from the beginning". */
  start?: string
  /** Inclusive, YYYY-MM-DD (UTC). Omit for "until the end". */
  end?: string
  id: string
  message: string
}

export function isActive(a: Announcement, now: number = Date.now()): boolean {
  if (a.start && now < Date.parse(a.start + 'T00:00:00Z')) return false
  if (a.end && now >= Date.parse(a.end + 'T00:00:00Z')) return false
  return true
}

/** First active announcement of this display type the visitor has not dismissed. */
export function pickAnnouncement(
  list: Announcement[],
  dismissed: string[],
  display: 'bar' | 'popup' = 'bar',
  now: number = Date.now()
): Announcement | undefined {
  return list.find(
    (a) =>
      a.id &&
      a.message &&
      (a.display || 'bar') === display &&
      isActive(a, now) &&
      !dismissed.includes(a.id)
  )
}
