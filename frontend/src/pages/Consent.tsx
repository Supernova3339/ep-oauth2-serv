import { useEffect, useState } from 'react'
import {
  Badge, Box, Button, Center, Flex, Heading, Spinner, Stack, Text,
} from '@chakra-ui/react'
import { useSearchParams } from 'react-router-dom'
import { useAuth } from '../context/auth'
import { Logomark as Logo } from '../components/Logomark'

interface ConsentInfo {
  client: { id: string; name: string }
  scopes: string[]
  user: { email: string }
  csrfToken: string
}

const SCOPE_LABELS: Record<string, string> = {
  openid: 'Know who you are',
  profile: 'Access your profile',
  email: 'Access your email address',
}

export default function Consent() {
  const [params] = useSearchParams()
  const { csrfToken } = useAuth()
  const [info, setInfo] = useState<ConsentInfo | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const clientId = params.get('client_id') || ''
  const redirectUri = params.get('redirect_uri') || ''
  const scope = params.get('scope') || ''
  const state = params.get('state') || ''
  const nonce = params.get('nonce') || ''

  useEffect(() => {
    const q = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, scope })
    fetch(`/api/consent-info?${q}`)
      .then(r => r.ok ? r.json() : Promise.reject(r))
      .then(setInfo)
      .catch(() => setError('Failed to load authorization details.'))
  }, [clientId, redirectUri, scope])

  async function respond(approved: boolean) {
    setLoading(true)
    try {
      const token = info?.csrfToken || csrfToken
      const res = await fetch('/oauth/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: clientId,
          redirect_uri: redirectUri,
          scopes: info?.scopes ?? [],
          approved: approved ? 'true' : 'false',
          state,
          nonce,
          csrf_token: token,
        }),
      })
      const data = await res.json()
      if (data.redirect) window.location.href = data.redirect
    } catch {
      setError('Something went wrong.')
      setLoading(false)
    }
  }

  if (error) {
    return (
      <Center minH="100vh" bg="gray.950">
        <Box bg="red.950" border="1px solid" borderColor="red.800" rounded="xl" p={6} maxW="360px">
          <Text color="red.300">{error}</Text>
        </Box>
      </Center>
    )
  }

  if (!info) {
    return <Center minH="100vh" bg="gray.950"><Spinner color="green.500" size="xl" /></Center>
  }

  return (
    <Center minH="100vh" bg="gray.950">
      <Box w="full" maxW="400px" px={4}>
        <Stack gap={6} align="center">
          <Stack gap={3} align="center">
            <Logo size={48} />
            <Heading size="lg" color="white">Authorize access</Heading>
            <Text color="gray.400" fontSize="sm" textAlign="center">
              <Text as="span" color="green.400" fontWeight="semibold">{info.client.name}</Text>
              {' '}is requesting access to your account
            </Text>
          </Stack>

          <Box w="full" bg="gray.900" border="1px solid" borderColor="gray.800" rounded="xl" p={6}>
            <Stack gap={4}>
              <Box>
                <Text fontSize="xs" color="gray.500" mb={2} textTransform="uppercase" letterSpacing="wide">
                  Signed in as
                </Text>
                <Text color="gray.200" fontSize="sm">{info.user.email}</Text>
              </Box>

              <Box borderTop="1px solid" borderColor="gray.800" pt={4}>
                <Text fontSize="xs" color="gray.500" mb={3} textTransform="uppercase" letterSpacing="wide">
                  This app will be able to
                </Text>
                <Stack gap={2}>
                  {info.scopes.map(scope => (
                    <Flex key={scope} align="center" gap={2}>
                      <Box w={1.5} h={1.5} rounded="full" bg="green.500" flexShrink={0} />
                      <Text fontSize="sm" color="gray.300">
                        {SCOPE_LABELS[scope] ?? scope}
                      </Text>
                      <Badge ml="auto" colorPalette="green" variant="subtle" fontSize="xs">{scope}</Badge>
                    </Flex>
                  ))}
                </Stack>
              </Box>

              <Stack gap={2} pt={2}>
                <Button
                  bg="green.500"
                  color="white"
                  _hover={{ bg: 'green.600' }}
                  onClick={() => respond(true)}
                  loading={loading}
                >
                  Allow access
                </Button>
                <Button
                  variant="outline"
                  borderColor="gray.700"
                  color="gray.400"
                  _hover={{ bg: 'gray.800', color: 'gray.200' }}
                  onClick={() => respond(false)}
                  disabled={loading}
                >
                  Deny
                </Button>
              </Stack>
            </Stack>
          </Box>
        </Stack>
      </Box>
    </Center>
  )
}
