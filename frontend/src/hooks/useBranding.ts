import { useEffect, useState } from 'react'

interface BrandingData {
  darkLogo: string | null
  lightLogo: string | null
  logomark: string | null
  hideOtherLinks: boolean
}

let cache: BrandingData | null = null
let promise: Promise<BrandingData> | null = null

function fetchBranding(): Promise<BrandingData> {
  if (!promise) {
    promise = fetch('/api/branding')
      .then(r => r.ok ? r.json() : { darkLogo: null, lightLogo: null, logomark: null, hideOtherLinks: false })
      .then(d => { cache = d; return d })
      .catch(() => ({ darkLogo: null, lightLogo: null, logomark: null, hideOtherLinks: false }))
  }
  return promise
}

export function useColorTheme(): 'dark' | 'light' {
  const get = () => (document.documentElement.dataset.theme ?? 'dark') as 'dark' | 'light'
  const [theme, setTheme] = useState<'dark' | 'light'>(get)

  useEffect(() => {
    const obs = new MutationObserver(() => setTheme(get()))
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    return () => obs.disconnect()
  }, [])

  return theme
}

export function useBranding() {
  const theme = useColorTheme()
  const [data, setData] = useState<BrandingData | null>(cache)

  useEffect(() => {
    if (!cache) fetchBranding().then(setData)
  }, [])

  const isDark = theme === 'dark'

  const textLogo = isDark
    ? (data?.darkLogo ?? '/assets/branding/logo_dark.svg')
    : (data?.lightLogo ?? '/assets/branding/logo_light.svg')

  const logomark = data?.logomark ?? '/assets/branding/logomark.svg'

  return { textLogo, logomark, theme, data, hideOtherLinks: data?.hideOtherLinks ?? false }
}
