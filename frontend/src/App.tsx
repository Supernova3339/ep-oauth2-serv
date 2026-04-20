import { Box, Spinner, Center } from '@chakra-ui/react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './context/auth'
import Login from './pages/Login'
import TwoFactor from './pages/TwoFactor'
import Consent from './pages/Consent'
import Device from './pages/Device'
import Docs from './pages/Docs'
import Clients from './pages/admin/Clients'
import Users from './pages/admin/Users'
import UserSettings from './pages/settings/User'
import Home from './pages/Home'

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth()
  if (loading) return <Center h="100vh"><Spinner color="green.500" size="xl" /></Center>
  if (!user) return <Navigate to="/login" replace />
  return <>{children}</>
}

function RequireAdmin({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth()
  if (loading) return <Center h="100vh"><Spinner color="green.500" size="xl" /></Center>
  if (!user) return <Navigate to="/login" replace />
  if (!user.admin && !user.isAdmin) return <Navigate to="/" replace />
  return <>{children}</>
}

function Index() {
  const { user, loading } = useAuth()
  if (loading) return <Center h="100vh"><Spinner color="green.500" size="xl" /></Center>
  if (!user) return <Navigate to="/login" replace />
  return <Home />
}

export default function App() {
  const { loading } = useAuth()

  if (loading) {
    return (
      <Box bg="gray.950" minH="100vh">
        <Center h="100vh"><Spinner color="green.500" size="xl" /></Center>
      </Box>
    )
  }

  return (
    <Routes>
      <Route path="/" element={<Index />} />
      <Route path="/login" element={<Login />} />
      <Route path="/two-factor" element={<TwoFactor />} />
      <Route path="/consent" element={<RequireAuth><Consent /></RequireAuth>} />
      <Route path="/device" element={<RequireAuth><Device /></RequireAuth>} />
      <Route path="/docs" element={<RequireAuth><Docs /></RequireAuth>} />
      <Route path="/admin/clients" element={<RequireAdmin><Clients /></RequireAdmin>} />
      <Route path="/admin/users" element={<RequireAdmin><Users /></RequireAdmin>} />
      <Route path="/settings/user" element={<RequireAuth><UserSettings /></RequireAuth>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
