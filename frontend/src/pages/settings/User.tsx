import { useState } from 'react'
import {
  Box, Button, Center, Flex,
  PinInputControl, PinInputHiddenInput, PinInputInput, PinInputRoot,
  Stack, Text,
} from '@chakra-ui/react'
import { useAuth } from '../../context/auth'
import { Layout } from '../../components/Layout'
import { Card } from '../../components/Card'

const PIN_BOX = {
  w: 11, h: 12, textAlign: 'center' as const,
  fontSize: 'xl', fontWeight: '600',
  bg: '#1a1a1a', border: '1px solid', borderColor: '#2a2a2a', color: 'white', rounded: 'lg',
  _focus: { borderColor: '#0BA864', boxShadow: '0 0 0 1px #0BA864', outline: 'none' },
}

function EyeIcon({ open }: { open: boolean }) {
  return open ? (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
    </svg>
  ) : (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
      <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
      <line x1="1" y1="1" x2="23" y2="23"/>
    </svg>
  )
}

function FieldLabel({ children, required }: { children: React.ReactNode; required?: boolean }) {
  return (
    <Text color="white" fontSize="14px" fontWeight={500} mb="6px">
      {children}{required && <Text as="span" color="red.400" ml={1}>*</Text>}
    </Text>
  )
}

function TextInput({ value, onChange, type = 'text', readOnly, placeholder }: {
  value: string; onChange?: (v: string) => void; type?: string; readOnly?: boolean; placeholder?: string
}) {
  const [show, setShow] = useState(false)
  const isPassword = type === 'password'
  return (
    <Flex position="relative" align="center">
      <input
        type={isPassword && show ? 'text' : type}
        value={value}
        readOnly={readOnly}
        placeholder={placeholder}
        onChange={e => onChange?.(e.target.value)}
        style={{
          width: '100%',
          background: readOnly ? '#111' : '#1a1a1a',
          border: '1px solid #2a2a2a',
          color: readOnly ? '#666' : 'white',
          borderRadius: 8,
          padding: isPassword ? '10px 44px 10px 14px' : '10px 14px',
          fontSize: 14,
          outline: 'none',
          boxSizing: 'border-box',
        }}
      />
      {isPassword && (
        <Box
          position="absolute" right={3} color="#666" cursor="pointer"
          _hover={{ color: '#aaa' }}
          onClick={() => setShow(s => !s)}
        >
          <EyeIcon open={show} />
        </Box>
      )}
    </Flex>
  )
}

const CARD_PROPS = { flex: 1, minW: '300px', maxW: '520px' }

export default function UserSettings() {
  const { user, setUser } = useAuth()

  const [oldPassword, setOldPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [pwLoading, setPwLoading] = useState(false)
  const [pwError, setPwError] = useState('')
  const [pwSuccess, setPwSuccess] = useState('')

  const [qr, setQr] = useState<{ secret: string; otpAuthUrl: string } | null>(null)
  const [pinValue, setPinValue] = useState<string[]>([])
  const [twoFaLoading, setTwoFaLoading] = useState(false)
  const [twoFaError, setTwoFaError] = useState('')
  const [twoFaSuccess, setTwoFaSuccess] = useState('')

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault()
    setPwError(''); setPwSuccess('')
    if (newPassword.length < 8) { setPwError('New password must be at least 8 characters'); return }
    setPwLoading(true)
    try {
      const res = await fetch('/api/settings/change-credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: user?.email, oldPassword, newPassword }),
      })
      const data = await res.json()
      if (!res.ok) { setPwError(data.error || 'Failed to change password'); return }
      setPwSuccess('Password changed successfully.')
      setOldPassword(''); setNewPassword('')
    } catch {
      setPwError('An error occurred')
    } finally {
      setPwLoading(false)
    }
  }

  async function configure2fa() {
    setTwoFaError(''); setTwoFaLoading(true)
    try {
      const res = await fetch('/api/2fa/configure', { method: 'POST' })
      const data = await res.json()
      if (!res.ok) { setTwoFaError(data.error || 'Failed'); return }
      setQr(data); setPinValue([])
    } catch { setTwoFaError('An error occurred') }
    finally { setTwoFaLoading(false) }
  }

  async function enable2fa() {
    setTwoFaError(''); setTwoFaLoading(true)
    try {
      const res = await fetch('/api/2fa/enable', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: pinValue.join('') }),
      })
      const data = await res.json()
      if (!res.ok) { setTwoFaError(data.error || 'Invalid code'); return }
      setQr(null); setPinValue([]); setTwoFaSuccess('Two-factor authentication enabled.')
      if (user) setUser({ ...user, twoFactorEnabled: true })
    } catch { setTwoFaError('An error occurred') }
    finally { setTwoFaLoading(false) }
  }

  async function disable2fa() {
    setTwoFaError(''); setTwoFaLoading(true)
    try {
      const res = await fetch('/api/2fa/disable', { method: 'POST' })
      const data = await res.json()
      if (!res.ok) { setTwoFaError(data.error || 'Failed'); return }
      setTwoFaSuccess('Two-factor authentication disabled.')
      if (user) setUser({ ...user, twoFactorEnabled: false })
    } catch { setTwoFaError('An error occurred') }
    finally { setTwoFaLoading(false) }
  }

  return (
    <Layout>
      <Flex direction="column" align="center" px={8} pt={10}>
        <Box w="full" maxW="1060px">
        <Text fontSize="20px" fontWeight={600} color="white" mb={6}>Authentication</Text>

        <Flex gap={4} align="start" wrap="wrap" justify="center">

          {/* ── Change Credentials ── */}
          <Card {...CARD_PROPS}>
            <Text fontSize="15px" fontWeight={500} color="#aaa" mb={5}>Change Credentials</Text>
            <Stack as="form" gap={4} onSubmit={handleChangePassword}>
              {pwError && (
                <Text color="red.400" fontSize="13px">{pwError}</Text>
              )}
              {pwSuccess && (
                <Text color="green.400" fontSize="13px">{pwSuccess}</Text>
              )}
              <Box>
                <FieldLabel required>Email</FieldLabel>
                <TextInput value={user?.email ?? ''} readOnly />
              </Box>
              <Box>
                <FieldLabel required>Old password</FieldLabel>
                <TextInput type="password" value={oldPassword} onChange={setOldPassword} />
              </Box>
              <Box>
                <FieldLabel required>New password</FieldLabel>
                <TextInput type="password" value={newPassword} onChange={setNewPassword} />
              </Box>
              <Box>
                <Button
                  type="submit"
                  bg="#0BA864" color="white" fontWeight={600}
                  h={10} px={6} rounded="lg"
                  _hover={{ bg: '#099558' }}
                  loading={pwLoading}
                >
                  Save
                </Button>
              </Box>
            </Stack>
          </Card>

          {/* ── Two Factor Auth ── */}
          <Card {...CARD_PROPS}>
            <Text fontSize="15px" fontWeight={500} color="#aaa" mb={5}>Two Factor Authentication</Text>

            {twoFaError && <Text color="red.400" fontSize="13px" mb={4}>{twoFaError}</Text>}
            {twoFaSuccess && <Text color="green.400" fontSize="13px" mb={4}>{twoFaSuccess}</Text>}

            {qr ? (
              <Stack gap={5}>
                <Text color="#888" fontSize="13px">
                  Scan the QR code with your authenticator app then enter the 6-digit code to confirm.
                </Text>
                <Flex gap={5} align="start">
                  <Center bg="white" p={2} rounded="lg" flexShrink={0}>
                    <img
                      src={`https://api.qrserver.com/v1/create-qr-code/?size=140x140&data=${encodeURIComponent(qr.otpAuthUrl)}`}
                      alt="QR" width={140} height={140}
                    />
                  </Center>
                  <Stack gap={3} flex={1}>
                    <Box>
                      <Text color="#666" fontSize="11px" mb={1}>Manual key</Text>
                      <Box bg="#1a1a1a" border="1px solid #2a2a2a" rounded="lg" px={3} py={2}>
                        <Text color="#aaa" fontSize="12px" fontFamily="mono" wordBreak="break-all">{qr.secret}</Text>
                      </Box>
                    </Box>
                    <PinInputRoot count={6} value={pinValue} onValueChange={({ value }) => setPinValue(value)} otp autoFocus>
                      <PinInputHiddenInput />
                      <PinInputControl>
                        <Flex gap={1.5}>
                          {Array.from({ length: 6 }).map((_, i) => (
                            <PinInputInput key={i} index={i} {...PIN_BOX} />
                          ))}
                        </Flex>
                      </PinInputControl>
                    </PinInputRoot>
                    <Flex gap={2}>
                      <Button bg="#0BA864" color="white" fontWeight={600} h={9} px={5} rounded="lg" _hover={{ bg: '#099558' }} loading={twoFaLoading} disabled={pinValue.join('').length < 6} onClick={enable2fa}>
                        Enable
                      </Button>
                      <Button variant="ghost" color="#666" h={9} px={4} _hover={{ color: 'white', bg: '#1a1a1a' }} onClick={() => { setQr(null); setPinValue([]) }}>
                        Cancel
                      </Button>
                    </Flex>
                  </Stack>
                </Flex>
              </Stack>
            ) : user?.twoFactorEnabled ? (
              <Stack gap={4}>
                <Text color="#0BA864" fontSize="13px">
                  Two-factor authentication is enabled on your account.
                </Text>
                <Box>
                  <Button
                    bg="#1a1a1a" border="1px solid #2a2a2a" color="white" fontWeight={600}
                    h={10} px={6} rounded="lg"
                    _hover={{ bg: '#2a1414', borderColor: '#3a1515', color: 'red.400' }}
                    loading={twoFaLoading}
                    onClick={disable2fa}
                  >
                    Disable Two Factor Authentication
                  </Button>
                </Box>
              </Stack>
            ) : (
              <Stack gap={4}>
                {!twoFaSuccess && (
                  <Text color="red.400" fontSize="13px">
                    Your account is not secured with two-factor authentication. We recommend enabling two factor authentication to improve your account's security
                  </Text>
                )}
                <Box>
                  <Button
                    bg="#0BA864" color="white" fontWeight={600}
                    h={10} px={6} rounded="lg"
                    _hover={{ bg: '#099558' }}
                    loading={twoFaLoading}
                    onClick={configure2fa}
                  >
                    Configure Two Factor Authentication
                  </Button>
                </Box>
              </Stack>
            )}
          </Card>

        </Flex>
        </Box>
      </Flex>
    </Layout>
  )
}
