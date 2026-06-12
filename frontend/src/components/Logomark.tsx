import { useState } from 'react'
import { useBranding } from '../hooks/useBranding'
import { Logo } from './Logo'

export function Logomark({ size = 30 }: { size?: number }) {
  const { logomark } = useBranding()
  const [err, setErr] = useState(false)

  if (err) return <Logo size={size} />

  return (
    <img
      src={logomark}
      alt="Logo"
      width={size}
      height={size}
      style={{ objectFit: 'contain' }}
      onError={() => setErr(true)}
    />
  )
}

export function TextLogo({ height = 32 }: { height?: number }) {
  const { textLogo } = useBranding()
  const [err, setErr] = useState(false)

  if (err) return <Logo size={height} />

  return (
    <img
      src={textLogo}
      alt="Logo"
      style={{ height, maxHeight: height, width: 'auto', objectFit: 'contain', display: 'block' }}
      onError={() => setErr(true)}
    />
  )
}
