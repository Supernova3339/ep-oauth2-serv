import { useEffect, useState } from 'react'
import {
  Box, Button, Center, Flex, Spinner, Stack, Text,
} from '@chakra-ui/react'
import { Layout } from '../../components/Layout'
import { Card } from '../../components/Card'
import { Modal, Dialog } from '../../components/Modal'
import { CopyField } from '../../components/CopyButton'

interface EpUser {
  id: string
  email: string
  admin: boolean
  twoFactorEnabled?: boolean
  apiToken?: string
}

const ROW = { borderBottom: '1px solid #1a1a1a', py: 4 }
const BADGE = (on: boolean) => ({
  display: 'inline-block',
  px: '8px', py: '2px',
  rounded: 'full',
  fontSize: '11px',
  fontWeight: 600,
  bg: on ? '#0a2518' : '#1a1a1a',
  color: on ? '#0BA864' : '#555',
  border: `1px solid ${on ? '#1a4a2a' : '#2a2a2a'}`,
})


function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Stack gap={1}>
      <Text color="gray.400" fontSize="xs">{label}</Text>
      {children}
    </Stack>
  )
}

function StyledInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      style={{
        width: '100%', background: '#1e1e1e', border: '1px solid #2a2a2a',
        color: 'white', borderRadius: 8, padding: '8px 12px', fontSize: 14, outline: 'none',
      }}
    />
  )
}


export default function UsersPage() {
  const [users, setUsers] = useState<EpUser[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [createOpen, setCreateOpen] = useState(false)
  const [editUser, setEditUser] = useState<EpUser | null>(null)
  const [deleteUser, setDeleteUser] = useState<EpUser | null>(null)
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState('')

  const [createForm, setCreateForm] = useState({ email: '', password: '', admin: false })
  const [editForm, setEditForm] = useState({ password: '', admin: false })
  const [generatedToken, setGeneratedToken] = useState<{ email: string; token: string } | null>(null)

  async function load() {
    try {
      const res = await fetch('/api/users')
      const data = await res.json()
      if (res.ok) setUsers(data.users)
      else setError(data.error || 'Failed to load users')
    } catch {
      setError('Failed to load users')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  async function handleCreate() {
    setFormError('')
    setSaving(true)
    try {
      const res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(createForm),
      })
      const data = await res.json()
      if (!res.ok) { setFormError(data.error || 'Failed'); return }
      setCreateOpen(false)
      setCreateForm({ email: '', password: '', admin: false })
      load()
    } catch {
      setFormError('An error occurred')
    } finally {
      setSaving(false)
    }
  }

  async function handleEdit() {
    if (!editUser) return
    setFormError('')
    setSaving(true)
    try {
      const body: Record<string, unknown> = { admin: editForm.admin }
      if (editForm.password) body.password = editForm.password
      const res = await fetch(`/api/users/${editUser.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await res.json()
      if (!res.ok) { setFormError(data.error || 'Failed'); return }
      setEditUser(null)
      load()
    } catch {
      setFormError('An error occurred')
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete() {
    if (!deleteUser) return
    setSaving(true)
    try {
      await fetch(`/api/users/${deleteUser.id}`, { method: 'DELETE' })
      setDeleteUser(null)
      load()
    } finally {
      setSaving(false)
    }
  }

  async function handleGenerateToken(user: EpUser) {
    const res = await fetch(`/api/users/${user.id}/generate-api-token`, { method: 'POST' })
    const data = await res.json()
    if (res.ok && data.apiToken) setGeneratedToken({ email: user.email, token: data.apiToken })
    load()
  }

  async function handleRevokeToken(user: EpUser) {
    await fetch(`/api/users/${user.id}/revoke-api-token`, { method: 'POST' })
    load()
  }

  if (loading) return <Center minH="100vh" bg="#0a0a0a"><Spinner color="green.500" size="xl" /></Center>

  return (
    <Layout>
      <Box px={10} py={10}>
        <Flex align="center" mb={8} gap={3}>
          <Text fontSize="22px" fontWeight={700} color="white">Users</Text>
          <Button
            ml="auto"
            bg="#0BA864" color="white" fontWeight={600} size="sm" h={9}
            _hover={{ bg: '#099558' }}
            onClick={() => { setCreateForm({ email: '', password: '', admin: false }); setFormError(''); setCreateOpen(true) }}
          >
            + New User
          </Button>
        </Flex>

        {error && (
          <Box bg="#1a0808" border="1px solid #3a1515" rounded="lg" px={4} py={3} mb={4}>
            <Text color="red.400" fontSize="sm">{error}</Text>
          </Box>
        )}

        <Card p={0} overflow="hidden">
          {users.length === 0 ? (
            <Center py={16}><Text color="#444" fontSize="14px">No users found.</Text></Center>
          ) : users.map((u, i) => (
            <Box key={u.id} px={6} {...ROW} borderBottom={i === users.length - 1 ? 'none' : '1px solid #1a1a1a'}>
              <Flex align="center" gap={4} wrap="wrap">
                <Stack gap={0} flex={1} minW={0}>
                  <Text color="white" fontSize="14px" fontWeight={500}>{u.email}</Text>
                  <Text color="#444" fontSize="12px" fontFamily="mono">{u.id}</Text>
                </Stack>
                <Flex gap={2} align="center" flexShrink={0}>
                  <Box {...BADGE(u.admin)}>{u.admin ? 'Admin' : 'User'}</Box>
                  {u.twoFactorEnabled && <Box {...BADGE(true)}>2FA</Box>}
                </Flex>
                <Flex gap={1} flexShrink={0}>
                  <Button
                    size="xs" variant="ghost" color="gray.500" _hover={{ color: 'gray.300', bg: '#1e1e1e' }}
                    onClick={() => { setEditUser(u); setEditForm({ password: '', admin: u.admin }); setFormError('') }}
                  >
                    Edit
                  </Button>
                  {u.apiToken ? (
                    <Button size="xs" variant="ghost" color="gray.500" _hover={{ color: 'gray.300', bg: '#1e1e1e' }} onClick={() => handleRevokeToken(u)}>
                      Revoke Token
                    </Button>
                  ) : (
                    <Button size="xs" variant="ghost" color="gray.500" _hover={{ color: 'gray.300', bg: '#1e1e1e' }} onClick={() => handleGenerateToken(u)}>
                      Gen Token
                    </Button>
                  )}
                  <Button
                    size="xs" variant="ghost" color="red.400" _hover={{ color: 'red.300', bg: '#1e1e1e' }}
                    onClick={() => setDeleteUser(u)}
                  >
                    Delete
                  </Button>
                </Flex>
              </Flex>
            </Box>
          ))}
        </Card>
      </Box>

      {/* Create modal */}
      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="New User">
        <Dialog.Body px={6} py={5}>
          <Stack gap={4}>
            {formError && <Box bg="#1a0808" border="1px solid #3a1515" rounded="lg" px={3} py={2}><Text color="red.400" fontSize="sm">{formError}</Text></Box>}
            <Field label="Email">
              <StyledInput type="email" value={createForm.email} onChange={e => setCreateForm(f => ({ ...f, email: e.target.value }))} placeholder="user@example.com" />
            </Field>
            <Field label="Password">
              <StyledInput type="password" value={createForm.password} onChange={e => setCreateForm(f => ({ ...f, password: e.target.value }))} placeholder="••••••••" />
            </Field>
            <Flex align="center" gap={3}>
              <button
                type="button"
                onClick={() => setCreateForm(f => ({ ...f, admin: !f.admin }))}
                style={{
                  width: 36, height: 20, borderRadius: 10, border: 'none', cursor: 'pointer',
                  background: createForm.admin ? '#0BA864' : '#2a2a2a', transition: 'background 0.2s', position: 'relative',
                }}
              >
                <span style={{
                  position: 'absolute', top: 2, left: createForm.admin ? 18 : 2,
                  width: 16, height: 16, borderRadius: '50%', background: 'white', transition: 'left 0.2s',
                }} />
              </button>
              <Text color="gray.300" fontSize="sm">Admin</Text>
            </Flex>
            <Flex gap={2} pt={2}>
              <Button flex={1} bg="#0BA864" color="white" fontWeight={600} h={10} _hover={{ bg: '#099558' }} loading={saving} onClick={handleCreate}>
                Create
              </Button>
              <Button variant="ghost" color="gray.500" h={10} _hover={{ color: 'gray.300', bg: 'transparent' }} onClick={() => setCreateOpen(false)}>
                Cancel
              </Button>
            </Flex>
          </Stack>
        </Dialog.Body>
      </Modal>

      {/* Edit modal */}
      <Modal open={!!editUser} onClose={() => setEditUser(null)} title={editUser ? `Edit ${editUser.email}` : 'Edit User'}>
        <Dialog.Body px={6} py={5}>
          <Stack gap={4}>
            {formError && <Box bg="#1a0808" border="1px solid #3a1515" rounded="lg" px={3} py={2}><Text color="red.400" fontSize="sm">{formError}</Text></Box>}
            <Field label="New Password (leave blank to keep)">
              <StyledInput type="password" value={editForm.password} onChange={e => setEditForm(f => ({ ...f, password: e.target.value }))} placeholder="••••••••" />
            </Field>
            <Flex align="center" gap={3}>
              <button
                type="button"
                onClick={() => setEditForm(f => ({ ...f, admin: !f.admin }))}
                style={{
                  width: 36, height: 20, borderRadius: 10, border: 'none', cursor: 'pointer',
                  background: editForm.admin ? '#0BA864' : '#2a2a2a', transition: 'background 0.2s', position: 'relative',
                }}
              >
                <span style={{
                  position: 'absolute', top: 2, left: editForm.admin ? 18 : 2,
                  width: 16, height: 16, borderRadius: '50%', background: 'white', transition: 'left 0.2s',
                }} />
              </button>
              <Text color="gray.300" fontSize="sm">Admin</Text>
            </Flex>
            <Flex gap={2} pt={2}>
              <Button flex={1} bg="#0BA864" color="white" fontWeight={600} h={10} _hover={{ bg: '#099558' }} loading={saving} onClick={handleEdit}>
                Save
              </Button>
              <Button variant="ghost" color="gray.500" h={10} _hover={{ color: 'gray.300', bg: 'transparent' }} onClick={() => setEditUser(null)}>
                Cancel
              </Button>
            </Flex>
          </Stack>
        </Dialog.Body>
      </Modal>

      {/* API Token */}
      <Modal open={!!generatedToken} onClose={() => setGeneratedToken(null)} title="API Token Generated">
        <Dialog.Body px={6} py={5}>
          <Stack gap={4}>
            <Box bg="#0a1a10" border="1px solid #1a4a2a" rounded="lg" px={4} py={3}>
              <Text color="green.300" fontSize="sm">Token generated for <Text as="span" fontWeight={600} color="white">{generatedToken?.email}</Text>. Save it now — it won't be shown again.</Text>
            </Box>
            <CopyField label="API Token" value={generatedToken?.token ?? ''} />
            <Button bg="#0BA864" color="white" fontWeight={600} h={10} _hover={{ bg: '#099558' }} onClick={() => setGeneratedToken(null)}>Done</Button>
          </Stack>
        </Dialog.Body>
      </Modal>

      {/* Delete confirm */}
      <Modal open={!!deleteUser} onClose={() => setDeleteUser(null)} title="Delete User">
        <Dialog.Body px={6} py={5}>
          <Stack gap={4}>
            <Text color="gray.300" fontSize="sm">
              Are you sure you want to delete <Text as="span" color="white" fontWeight={600}>{deleteUser?.email}</Text>? This cannot be undone.
            </Text>
            <Flex gap={2}>
              <Button flex={1} bg="red.600" color="white" fontWeight={600} h={10} _hover={{ bg: 'red.700' }} loading={saving} onClick={handleDelete}>
                Delete
              </Button>
              <Button variant="ghost" color="gray.500" h={10} _hover={{ color: 'gray.300', bg: 'transparent' }} onClick={() => setDeleteUser(null)}>
                Cancel
              </Button>
            </Flex>
          </Stack>
        </Dialog.Body>
      </Modal>
    </Layout>
  )
}
