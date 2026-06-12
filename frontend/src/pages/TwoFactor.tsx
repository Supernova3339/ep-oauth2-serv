import { useState } from 'react'
import {
  Box, Button, Center, Flex,
  PinInputControl, PinInputHiddenInput, PinInputInput, PinInputRoot,
  Stack, Text,
} from '@chakra-ui/react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/auth'
import { Logomark as Logo } from '../components/Logomark'

const PIN_BOX = {
  w: 11,
  h: 12,
  textAlign: 'center' as const,
  fontSize: 'xl',
  fontWeight: '600',
  bg: '#1e1e1e',
  border: '1px solid',
  borderColor: '#2a2a2a',
  color: 'white',
  rounded: 'lg',
  _focus: { borderColor: '#0BA864', boxShadow: '0 0 0 1px #0BA864', outline: 'none' },
}

export default function TwoFactor() {
  const { csrfToken, setUser, refreshCsrf } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const returnTo = (location.state as { returnTo?: string })?.returnTo || '/admin/clients'

  const [pinValue, setPinValue] = useState<string[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const code = pinValue.join('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (code.length < 6) return
    setError('')
    setLoading(true)
    try {
      const token = csrfToken || await refreshCsrf()
      const res = await fetch('/twoFactor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, csrf_token: token }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error || 'Invalid code')
        await refreshCsrf()
        return
      }
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
      <Stack w="full" maxW="400px" gap={6} align="center">
        <Stack gap={3} align="center">
          <Logo size={48} />
          <Text fontSize="2xl" fontWeight="700" color="white">Two-factor auth</Text>
          <Text color="gray.400" fontSize="sm" textAlign="center">
            Enter the 6-digit code from your authenticator app
          </Text>
        </Stack>

        <Box w="full" bg="#141414" border="1px solid #2a2a2a" rounded="2xl" p={8}>
          <Stack as="form" gap={6} onSubmit={handleSubmit}>
            {error && (
              <Box bg="#1a0808" border="1px solid #3a1515" rounded="lg" px={4} py={3}>
                <Text color="red.400" fontSize="sm">{error}</Text>
              </Box>
            )}

            <PinInputRoot
              count={6}
              value={pinValue}
              onValueChange={({ value }) => setPinValue(value)}
              otp
              autoFocus
              w="full"
              justifyContent="center"
            >
              <PinInputHiddenInput />
              <PinInputControl>
                <Flex gap={2} justify="center">
                  {Array.from({ length: 6 }).map((_, i) => (
                    <PinInputInput key={i} index={i} {...PIN_BOX} />
                  ))}
                </Flex>
              </PinInputControl>
            </PinInputRoot>

            <Stack gap={3}>
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
                loadingText="Verifying…"
                disabled={code.length < 6}
              >
                Verify
              </Button>
              <Button
                variant="ghost"
                color="gray.500"
                _hover={{ color: 'gray.300', bg: 'transparent' }}
                onClick={() => navigate('/login')}
                size="sm"
              >
                Back to sign in
              </Button>
            </Stack>
          </Stack>
        </Box>
      </Stack>
    </Center>
  )
}
