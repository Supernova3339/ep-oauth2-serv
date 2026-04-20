import React from 'react'
import ReactDOM from 'react-dom/client'
import { ChakraProvider } from '@chakra-ui/react'
import { BrowserRouter } from 'react-router-dom'
import { system } from './system'
import App from './App'
import { AuthProvider } from './context/auth'

// Set favicon from branding API logomark
fetch('/api/branding')
  .then(r => r.ok ? r.json() : null)
  .then((d: { logomark?: string | null } | null) => {
    const url = d?.logomark ?? '/assets/branding/logomark.svg'
    const link: HTMLLinkElement = document.querySelector("link[rel~='icon']") ?? document.createElement('link')
    link.rel = 'icon'
    link.type = 'image/svg+xml'
    link.href = url
    document.head.appendChild(link)
  })
  .catch(() => {})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ChakraProvider value={system}>
      <BrowserRouter>
        <AuthProvider>
          <App />
        </AuthProvider>
      </BrowserRouter>
    </ChakraProvider>
  </React.StrictMode>
)
