import { useState } from 'react'
import { Box, Button, Center, Field, Heading, Input, Stack, Text } from '@chakra-ui/react'
import { useSearchParams } from 'react-router-dom'
import { useAuth } from '../context/auth'
import { Logomark as Logo } from '../components/Logomark'

type State = 'idle' | 'success' | 'error'

export default function Device() {
  const { csrfToken, refreshCsrf } = useAuth()
  const [params] = useSearchParams()

  const [code, setCode] = useState(() => {
    const raw = params.get('user_code') || ''
    return raw.replace(/-/g, '').toUpperCase()
  })
  const [state, setState] = useState<State>('idle')
  const [message, setMessage] = useState('')
  const [loading, setLoading] = useState(false)

  function fmt(val: string) {
    const clean = val.replace(/[^A-Z0-9]/gi, '').toUpperCase().slice(0, 8)
    return clean.length > 4 ? `${clean.slice(0, 4)}-${clean.slice(4)}` : clean
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    try {
      const token = csrfToken || await refreshCsrf()
      const res = await fetch('/device/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_code: code.replace(/-/g, ''), csrf_token: token }),
      })
      const data = await res.json()
      if (res.ok && data.success) {
        setState('success')
        setMessage(data.message || 'Your device has been successfully authorized.')
      } else {
        setState('error')
        setMessage(data.message || data.error || 'Invalid or expired code.')
      }
    } catch {
      setState('error')
      setMessage('An unexpected error occurred.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Center minH="100vh" bg="#0c0e11">
      <Box w="full" maxW="380px" px={4}>
        <Stack gap={8} align="center">
          <Stack gap={3} align="center">
            <Logo size={48} />
            <Heading size="lg" color="white">Device sign-in</Heading>
            <Text color="gray.400" fontSize="sm" textAlign="center">
              Enter the code shown on your device
            </Text>
          </Stack>

          <Box w="full" bg="#111418" border="1px solid #1e2533" rounded="xl" p={6}>
            {state === 'success' ? (
              <Stack gap={4} align="center" py={2}>
                <Box w={12} h={12} rounded="full" bg="#0a2518" border="1px solid #1a4a2a"
                  display="flex" alignItems="center" justifyContent="center" fontSize="xl">
                  ✓
                </Box>
                <Text color="green.400" fontWeight={600} textAlign="center">{message}</Text>
                <Text color="gray.500" fontSize="sm" textAlign="center">
                  You can close this tab and return to your device.
                </Text>
              </Stack>
            ) : (
              <Stack as="form" gap={4} onSubmit={handleSubmit}>
                {state === 'error' && (
                  <Box bg="#1a0a0a" border="1px solid #4a1515" rounded="lg" px={4} py={3}>
                    <Text color="red.300" fontSize="sm">{message}</Text>
                  </Box>
                )}
                <Field.Root>
                  <Field.Label color="gray.400" fontSize="sm">Device code</Field.Label>
                  <Input
                    value={fmt(code)}
                    onChange={e => setCode(e.target.value.replace(/[^A-Z0-9]/gi, '').toUpperCase())}
                    placeholder="XXXX-XXXX"
                    required
                    autoFocus
                    autoComplete="off"
                    textAlign="center"
                    letterSpacing="0.2em"
                    fontSize="xl"
                    fontFamily="mono"
                    bg="gray.800"
                    border="1px solid"
                    borderColor="gray.700"
                    color="white"
                    _focus={{ borderColor: 'green.500', boxShadow: '0 0 0 1px var(--chakra-colors-green-500)' }}
                    _placeholder={{ color: 'gray.600', letterSpacing: '0.1em' }}
                  />
                </Field.Root>
                <Button
                  type="submit"
                  bg="green.500"
                  color="white"
                  _hover={{ bg: 'green.600' }}
                  w="full"
                  loading={loading}
                  loadingText="Verifying…"
                  disabled={code.replace(/-/g, '').length < 8}
                >
                  Authorize device
                </Button>
              </Stack>
            )}
          </Box>
        </Stack>
      </Box>
    </Center>
  )
}
