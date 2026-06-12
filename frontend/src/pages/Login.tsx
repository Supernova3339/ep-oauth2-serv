import { useState } from 'react'
import {
  Box, Button, Center, Checkbox, Field,
  Flex, Input, Link, Stack, Text,
} from '@chakra-ui/react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '../context/auth'
import { TextLogo } from '../components/Logomark'
import { useBranding } from '../hooks/useBranding'
import { LINKS } from '../constants'

function EyeOpen() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
    </svg>
  )
}

function EyeClosed() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
      <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
      <line x1="1" y1="1" x2="23" y2="23"/>
    </svg>
  )
}

const CARD_INPUT = {
  bg: '#1e1e1e',
  border: '1px solid',
  borderColor: '#2a2a2a',
  color: 'white',
  _placeholder: { color: '#4a5568' },
  _focus: { borderColor: '#0BA864', boxShadow: '0 0 0 1px #0BA864', outline: 'none' },
} as const

export default function Login() {
  const { csrfToken, setUser, refreshCsrf } = useAuth()
  const { hideOtherLinks } = useBranding()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const returnTo = params.get('returnTo') || '/'

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [rememberMe, setRememberMe] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const token = csrfToken || await refreshCsrf()
      const res = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, rememberMe, csrf_token: token }),
      })
      const data = await res.json()
      if (!res.ok) { setError(data.error || 'Invalid credentials'); await refreshCsrf(); return }
      if (data.twoFactorRequired) { await refreshCsrf(); navigate('/two-factor', { state: { returnTo } }); return }
      setUser(data.user)
      window.location.href = returnTo
    } catch {
      setError('An unexpected error occurred')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Center minH="100vh" bg="#0a0a0a" px={4}>
      <Stack w="full" maxW="480px" gap={6} align="stretch">

        <Box bg="#141414" border="1px solid #2a2a2a" rounded="2xl" p={10}>
          <Box mb={10} display="flex" justifyContent="center">
            <TextLogo height={40} />
          </Box>

          <Stack as="form" gap={5} onSubmit={handleSubmit}>
            {error && (
              <Box bg="#1a0808" border="1px solid #3a1515" rounded="lg" px={4} py={3}>
                <Text color="red.400" fontSize="sm">{error}</Text>
              </Box>
            )}

            <Field.Root required>
              <Field.Label color="gray.200" fontWeight={500}>
                Email <Text as="span" color="red.400">*</Text>
              </Field.Label>
              <Input
                {...CARD_INPUT}
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                autoFocus
              />
            </Field.Root>

            <Field.Root required>
              <Field.Label color="gray.200" fontWeight={500}>
                Password <Text as="span" color="red.400">*</Text>
              </Field.Label>
              <Flex position="relative" align="center" w="full">
                <Input
                  {...CARD_INPUT}
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  pr={12}
                  w="full"
                />
                <Button
                  type="button"
                  variant="ghost"
                  position="absolute"
                  right={1}
                  size="sm"
                  color="gray.500"
                  _hover={{ color: 'gray.300', bg: 'transparent' }}
                  onClick={() => setShowPassword(v => !v)}
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOpen /> : <EyeClosed />}
                </Button>
              </Flex>
            </Field.Root>

            <Checkbox.Root
              checked={rememberMe}
              onCheckedChange={({ checked }) => setRememberMe(!!checked)}
            >
              <Checkbox.HiddenInput />
              <Checkbox.Control
                bg={rememberMe ? '#0BA864' : '#1e1e1e'}
                borderColor={rememberMe ? '#0BA864' : '#4a5568'}
                _hover={{ borderColor: '#0BA864' }}
              />
              <Checkbox.Label color="gray.200" fontSize="sm">
                Remember Me
              </Checkbox.Label>
            </Checkbox.Root>

            <Button
              type="submit"
              bg="#0BA864"
              color="white"
              fontWeight={700}
              fontSize="md"
              h={11}
              _hover={{ bg: '#099558' }}
              _active={{ bg: '#07784a' }}
              loading={loading}
              loadingText="Signing in…"
            >
              Login
            </Button>

            <Link
              href={LINKS.forgotPassword}
              target="_blank"
              rel="noopener noreferrer"
              color="gray.200"
              fontSize="sm"
              _hover={{ textDecoration: 'underline' }}
            >
              Forgot your password?
            </Link>
          </Stack>
        </Box>

        {!hideOtherLinks && (
          <Text textAlign="center" color="gray.600" fontSize="sm">
            Hosting Control Panel
          </Text>
        )}

      </Stack>
    </Center>
  )
}
