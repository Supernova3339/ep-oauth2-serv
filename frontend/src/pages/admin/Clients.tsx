import { useEffect, useState } from 'react'
import {
  Badge, Box, Button, Field,
  Flex, Input, Stack, Text, Textarea,
} from '@chakra-ui/react'
import { useAuth } from '../../context/auth'
import { Layout } from '../../components/Layout'
import { Card } from '../../components/Card'
import { Modal, Dialog } from '../../components/Modal'
import { CopyField } from '../../components/CopyButton'

interface Client {
  id: string
  name: string
  redirectUris: string[]
  allowedScopes: string[]
  persistent: boolean
  createdAt: string
}

const ALL_SCOPES = ['openid', 'profile', 'email']

function ScopeToggle({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const toggle = (s: string) =>
    onChange(value.includes(s) ? value.filter(x => x !== s) : [...value, s])
  return (
    <Flex gap={2}>
      {ALL_SCOPES.map(s => {
        const on = value.includes(s)
        return (
          <Box
            key={s}
            as="button"
            onClick={() => toggle(s)}
            px={3} py={1}
            rounded="md"
            fontSize="sm"
            border="1px solid"
            borderColor={on ? 'green.700' : '#2d3748'}
            bg={on ? '#0a2518' : 'transparent'}
            color={on ? 'green.400' : 'gray.500'}
            cursor="pointer"
            transition="all 0.15s"
            _hover={{ borderColor: on ? 'green.500' : '#4a5568', color: on ? 'green.300' : 'gray.300' }}
          >
            {s}
          </Box>
        )
      })}
    </Flex>
  )
}

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: () => void; label: string }) {
  return (
    <Flex
      as="button"
      align="center"
      gap={3}
      onClick={onChange}
      cursor="pointer"
      bg="transparent"
      border="none"
      p={0}
    >
      <Box
        w={9} h={5} rounded="full" position="relative" transition="background 0.2s"
        bg={checked ? 'green.500' : '#2d3748'}
      >
        <Box
          position="absolute"
          top="2px"
          left={checked ? 'calc(100% - 18px)' : '2px'}
          w={4} h={4}
          rounded="full"
          bg="white"
          transition="left 0.2s"
        />
      </Box>
      <Text fontSize="sm" color="gray.300">{label}</Text>
    </Flex>
  )
}

const TH_STYLE = {
  padding: '12px 20px',
  textAlign: 'left' as const,
  fontSize: '11px',
  fontWeight: 600,
  textTransform: 'uppercase' as const,
  letterSpacing: '0.07em',
  color: '#555',
  borderBottom: '1px solid #1a1a1a',
  background: '#111',
  whiteSpace: 'nowrap' as const,
}

const TD_STYLE = {
  padding: '14px 20px',
  borderBottom: '1px solid #161616',
  verticalAlign: 'middle' as const,
}

const INPUT = {
  bg: 'gray.800',
  border: '1px solid',
  borderColor: 'gray.700',
  color: 'white',
  _placeholder: { color: 'gray.600' },
  _focus: { borderColor: 'green.500', boxShadow: '0 0 0 1px var(--chakra-colors-green-500)' },
} as const

interface FormState { name: string; uris: string; scopes: string[]; persistent: boolean }
const DEFAULT_FORM: FormState = { name: '', uris: '', scopes: ['profile', 'email'], persistent: false }


export default function Clients() {
  useAuth()

  const [clients, setClients] = useState<Client[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const [createOpen, setCreateOpen] = useState(false)
  const [createForm, setCreateForm] = useState<FormState>({ ...DEFAULT_FORM })

  const [editClient, setEditClient] = useState<(FormState & { id: string }) | null>(null)
  const [deleteClient, setDeleteClient] = useState<Client | null>(null)
  const [secretResult, setSecretResult] = useState<{ name: string; secret: string } | null>(null)

  async function load() {
    setLoading(true)
    const r = await fetch('/api/clients')
    if (r.ok) setClients((await r.json()).clients)
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  async function handleCreate() {
    setSaving(true); setError('')
    const uris = createForm.uris.split('\n').map(s => s.trim()).filter(Boolean)
    const r = await fetch('/api/clients', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: createForm.name, redirectUris: uris, allowedScopes: createForm.scopes, persistent: createForm.persistent }),
    })
    const d = await r.json()
    setSaving(false)
    if (!r.ok) { setError(d.error || 'Failed to create'); return }
    setCreateOpen(false)
    setCreateForm({ ...DEFAULT_FORM })
    setSecretResult({ name: d.client.name, secret: d.client.secret })
    await load()
  }

  async function handleEdit() {
    if (!editClient) return
    setSaving(true); setError('')
    const uris = editClient.uris.split('\n').map(s => s.trim()).filter(Boolean)
    const r = await fetch(`/api/clients/${editClient.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: editClient.name, redirectUris: uris, allowedScopes: editClient.scopes, persistent: editClient.persistent }),
    })
    const d = await r.json()
    setSaving(false)
    if (!r.ok) { setError(d.error || 'Failed to update'); return }
    setEditClient(null)
    await load()
  }

  async function handleDelete() {
    if (!deleteClient) return
    setSaving(true)
    const r = await fetch(`/api/clients/${deleteClient.id}`, { method: 'DELETE' })
    setSaving(false)
    if (r.ok) { setDeleteClient(null); await load() }
  }

  async function regenerateSecret(client: Client) {
    const r = await fetch(`/api/clients/${client.id}/secret`, { method: 'POST' })
    const d = await r.json()
    if (r.ok) setSecretResult({ name: d.clientName, secret: d.clientSecret })
  }

  return (
    <Layout>
      <Box px={10} py={10}>
        <Flex align="center" justify="space-between" mb={8}>
          <Text fontSize="22px" fontWeight={700} color="white">OAuth Clients</Text>
          <Flex gap={2}>
            <Button size="sm" variant="ghost" color="gray.400" _hover={{ bg: '#1e1e1e', color: 'gray.100' }}
              onClick={() => window.location.href = '/docs'}>API Docs</Button>
            <Button size="sm" bg="#0BA864" color="white" _hover={{ bg: '#099558' }} fontWeight={500}
              onClick={() => { setError(''); setCreateForm({ ...DEFAULT_FORM }); setCreateOpen(true) }}>
              New Client
            </Button>
          </Flex>
        </Flex>
        {loading ? (
          <Text color="gray.500" fontSize="sm">Loading…</Text>
        ) : clients.length === 0 ? (
          <Card p={16} textAlign="center">
            <Text color="#444" fontSize="14px">No clients registered yet.</Text>
          </Card>
        ) : (
          <Card p={0} overflow="hidden">
            <Box overflowX="auto">
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr>
                    {['Name', 'Client ID', 'Redirect URIs', 'Scopes', 'Persistent', 'Created', 'Actions'].map(h => (
                      <th key={h} style={TH_STYLE}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {clients.map((c, i) => (
                    <tr key={c.id} style={{ background: i % 2 === 0 ? '#111' : '#0d0d0d' }}>
                      <td style={TD_STYLE}>
                        <Text fontWeight={600} fontSize="sm">{c.name}</Text>
                      </td>
                      <td style={TD_STYLE}>
                        <Text fontFamily="mono" fontSize="xs" color="gray.400">{c.id}</Text>
                      </td>
                      <td style={TD_STYLE}>
                        <Stack gap={0}>
                          {c.redirectUris.map(u => (
                            <Text key={u} fontSize="xs" color="gray.400">{u}</Text>
                          ))}
                        </Stack>
                      </td>
                      <td style={TD_STYLE}>
                        <Flex gap={1} flexWrap="wrap">
                          {c.allowedScopes.map(s => (
                            <Badge key={s} colorPalette="green" variant="subtle" size="sm">{s}</Badge>
                          ))}
                        </Flex>
                      </td>
                      <td style={TD_STYLE}>
                        <Text fontSize="sm" color="gray.400">{c.persistent ? 'Yes' : 'No'}</Text>
                      </td>
                      <td style={TD_STYLE}>
                        <Text fontSize="xs" color="gray.500">{new Date(c.createdAt).toLocaleDateString()}</Text>
                      </td>
                      <td style={TD_STYLE}>
                        <Flex gap={1.5}>
                          <Button size="xs" variant="outline" borderColor="#2d3748" color="gray.400"
                            _hover={{ bg: '#1e2533', color: 'white', borderColor: '#4a5568' }}
                            onClick={() => { setError(''); setEditClient({ id: c.id, name: c.name, uris: c.redirectUris.join('\n'), scopes: c.allowedScopes, persistent: c.persistent }) }}>
                            Edit
                          </Button>
                          <Button size="xs" variant="outline" borderColor="#2d3748" color="gray.400"
                            _hover={{ bg: '#1e2533', color: 'white', borderColor: '#4a5568' }}
                            onClick={() => regenerateSecret(c)}>
                            New secret
                          </Button>
                          <Button size="xs" variant="outline" borderColor="red.900" color="red.400"
                            _hover={{ bg: 'red.950', color: 'red.300' }}
                            onClick={() => setDeleteClient(c)}>
                            Delete
                          </Button>
                        </Flex>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Box>
          </Card>
        )}
      </Box>

      {/* Create Modal */}
      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="New OAuth client">
        <Dialog.Body px={6} py={5}>
          <Stack gap={4}>
            {error && <ErrorBox>{error}</ErrorBox>}
            <Field.Root>
              <Field.Label color="gray.400" fontSize="sm">Client name</Field.Label>
              <Input {...INPUT} value={createForm.name} onChange={e => setCreateForm(f => ({ ...f, name: e.target.value }))} placeholder="My App" />
            </Field.Root>
            <Field.Root>
              <Field.Label color="gray.400" fontSize="sm">Redirect URIs</Field.Label>
              <Textarea {...INPUT} value={createForm.uris} onChange={e => setCreateForm(f => ({ ...f, uris: e.target.value }))} placeholder="https://myapp.com/callback" minH="80px" />
              <Field.HelperText color="gray.600" fontSize="xs">One URI per line</Field.HelperText>
            </Field.Root>
            <Field.Root>
              <Field.Label color="gray.400" fontSize="sm">Allowed scopes</Field.Label>
              <ScopeToggle value={createForm.scopes} onChange={scopes => setCreateForm(f => ({ ...f, scopes }))} />
            </Field.Root>
            <Toggle checked={createForm.persistent} onChange={() => setCreateForm(f => ({ ...f, persistent: !f.persistent }))} label="Persistent (survives restart)" />
          </Stack>
        </Dialog.Body>
        <Dialog.Footer px={6} py={4} borderTop="1px solid #1e2533" gap={2}>
          <Button variant="ghost" color="gray.400" _hover={{ bg: '#1e2533' }} onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button bg="green.500" color="white" _hover={{ bg: 'green.600' }} loading={saving} onClick={handleCreate}>Create</Button>
        </Dialog.Footer>
      </Modal>

      {/* Edit Modal */}
      <Modal open={!!editClient} onClose={() => setEditClient(null)} title="Edit client">
        <Dialog.Body px={6} py={5}>
          <Stack gap={4}>
            {error && <ErrorBox>{error}</ErrorBox>}
            <Field.Root>
              <Field.Label color="gray.400" fontSize="sm">Client name</Field.Label>
              <Input {...INPUT} value={editClient?.name ?? ''} onChange={e => setEditClient(c => c ? { ...c, name: e.target.value } : c)} />
            </Field.Root>
            <Field.Root>
              <Field.Label color="gray.400" fontSize="sm">Redirect URIs</Field.Label>
              <Textarea {...INPUT} value={editClient?.uris ?? ''} onChange={e => setEditClient(c => c ? { ...c, uris: e.target.value } : c)} minH="80px" />
              <Field.HelperText color="gray.600" fontSize="xs">One URI per line</Field.HelperText>
            </Field.Root>
            <Field.Root>
              <Field.Label color="gray.400" fontSize="sm">Allowed scopes</Field.Label>
              <ScopeToggle value={editClient?.scopes ?? []} onChange={scopes => setEditClient(c => c ? { ...c, scopes } : c)} />
            </Field.Root>
            <Toggle checked={editClient?.persistent ?? false} onChange={() => setEditClient(c => c ? { ...c, persistent: !c.persistent } : c)} label="Persistent" />
          </Stack>
        </Dialog.Body>
        <Dialog.Footer px={6} py={4} borderTop="1px solid #1e2533" gap={2}>
          <Button variant="ghost" color="gray.400" _hover={{ bg: '#1e2533' }} onClick={() => setEditClient(null)}>Cancel</Button>
          <Button bg="green.500" color="white" _hover={{ bg: 'green.600' }} loading={saving} onClick={handleEdit}>Save</Button>
        </Dialog.Footer>
      </Modal>

      {/* Delete Modal */}
      <Modal open={!!deleteClient} onClose={() => setDeleteClient(null)} title="Delete client">
        <Dialog.Body px={6} py={5}>
          <Stack gap={3}>
            <Text fontSize="sm" color="gray.300">
              Delete <Text as="span" color="white" fontWeight={600}>{deleteClient?.name}</Text>? This cannot be undone.
            </Text>
            <Box bg="#1a0a0a" border="1px solid #4a1515" rounded="lg" px={4} py={3}>
              <Text color="red.300" fontSize="sm">All applications using this client will immediately lose access.</Text>
            </Box>
          </Stack>
        </Dialog.Body>
        <Dialog.Footer px={6} py={4} borderTop="1px solid #1e2533" gap={2}>
          <Button variant="ghost" color="gray.400" _hover={{ bg: '#1e2533' }} onClick={() => setDeleteClient(null)}>Cancel</Button>
          <Button bg="red.600" color="white" _hover={{ bg: 'red.700' }} loading={saving} onClick={handleDelete}>Delete</Button>
        </Dialog.Footer>
      </Modal>

      {/* Secret Result Modal */}
      <Modal open={!!secretResult} onClose={() => setSecretResult(null)} title="Client secret">
        <Dialog.Body px={6} py={5}>
          <Stack gap={4}>
            <Box bg="#0a1a10" border="1px solid #1a4a2a" rounded="lg" px={4} py={3}>
              <Text color="green.300" fontSize="sm">
                Secret for <Text as="span" fontWeight={600} color="white">{secretResult?.name}</Text>. Save it now — it won't be shown again.
              </Text>
            </Box>
            <CopyField label="Client Secret" value={secretResult?.secret ?? ''} />
          </Stack>
        </Dialog.Body>
        <Dialog.Footer px={6} py={4} borderTop="1px solid #1e2533">
          <Button bg="green.500" color="white" _hover={{ bg: 'green.600' }} onClick={() => setSecretResult(null)}>Done</Button>
        </Dialog.Footer>
      </Modal>
    </Layout>
  )
}

function ErrorBox({ children }: { children: React.ReactNode }) {
  return (
    <Box bg="#1a0a0a" border="1px solid #4a1515" rounded="lg" px={4} py={3}>
      <Text color="red.300" fontSize="sm">{children}</Text>
    </Box>
  )
}
