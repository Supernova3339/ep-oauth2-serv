import { Box, Flex, Text } from '@chakra-ui/react'
import { useAuth } from '../context/auth'
import { Logomark as Logo } from './Logomark'
import React from "react";

export interface NavItem {
  label: string
  href: string
  icon: React.ReactNode
  active?: boolean
}

export interface NavGroup {
  label: string
  items: NavItem[]
}

function NavLink({ item }: { item: NavItem }) {
  return (
    <a
      href={item.href}
      style={{
        display: 'flex', alignItems: 'center', gap: '10px',
        padding: '7px 12px', borderRadius: 6,
        fontSize: 13, fontWeight: item.active ? 500 : 400,
        color: item.active ? 'white' : '#666',
        background: item.active ? '#1c1c1c' : 'transparent',
        transition: 'all 0.1s', textDecoration: 'none',
      }}
      onMouseEnter={e => { (e.currentTarget as HTMLAnchorElement).style.background = '#181818'; (e.currentTarget as HTMLAnchorElement).style.color = '#ccc' }}
      onMouseLeave={e => { (e.currentTarget as HTMLAnchorElement).style.background = item.active ? '#1c1c1c' : 'transparent'; (e.currentTarget as HTMLAnchorElement).style.color = item.active ? 'white' : '#666' }}
    >
      <span style={{ color: item.active ? '#aaa' : '#444', flexShrink: 0, display: 'flex', alignItems: 'center' }}>
        {item.icon}
      </span>
      {item.label}
    </a>
  )
}

const path = window.location.pathname

function buildGroups(isAdmin: boolean): NavGroup[] {
  const groups: NavGroup[] = []

  if (isAdmin) {
    groups.push({
      label: 'Admin',
      items: [
        { label: 'OAuth Clients', href: '/admin/clients', icon: <ClientsIcon />, active: path === '/admin/clients' },
        { label: 'Users', href: '/admin/users', icon: <UsersIcon />, active: path === '/admin/users' },
      ],
    })
  }

  groups.push({
    label: 'User',
    items: [
      { label: 'Authentication', href: '/settings/user', icon: <AuthIcon />, active: path === '/settings/user' },
    ],
  })

  return groups
}

interface LayoutProps {
  children: React.ReactNode
}

export function Layout({ children }: LayoutProps) {
  const { user } = useAuth()
  const isAdmin = !!(user?.admin || user?.isAdmin)
  const groups = buildGroups(isAdmin)

  async function handleLogout() {
    await fetch('/logout', { method: 'POST' })
    window.location.href = '/login'
  }

  return (
    <Flex minH="100vh" bg="#0a0a0a">
      {/* Sidebar */}
      <Box
        w="220px"
        flexShrink={0}
        bg="#0d0d0d"
        borderRight="1px solid #161616"
        display="flex"
        flexDirection="column"
        position="fixed"
        top={0}
        left={0}
        bottom={0}
        overflowY="auto"
      >
        {/* Logo */}
        <Box px="14px" py={4} mb={1}>
          <a href="/" style={{ display: 'flex', alignItems: 'center', gap: '10px', textDecoration: 'none' }}>
            <Logo size={26} />
            <Text fontSize="13px" fontWeight={600} color="white" letterSpacing="-0.01em">OAuth Server</Text>
          </a>
        </Box>

        {/* Nav groups */}
        <Box flex={1} px="10px">
          {groups.map(group => (
            <Box key={group.label} mb={4}>
              <Text
                fontSize="10px" fontWeight={600} color="#333"
                textTransform="uppercase" letterSpacing="0.08em"
                px={3} mb="4px"
              >
                {group.label}
              </Text>
              {group.items.map(item => (
                <NavLink key={item.href} item={item} />
              ))}
            </Box>
          ))}
        </Box>

        {/* Logout */}
        <Box px="10px" py={3} borderTop="1px solid #161616">
          <Box
            display="flex" alignItems="center" gap="10px"
            px={3} py="7px" rounded="md" fontSize="13px"
            color="#666" cursor="pointer"
            _hover={{ bg: '#181818', color: '#ccc' }}
            transition="all 0.1s"
            onClick={handleLogout}
          >
            <Box color="#444" display="flex" alignItems="center"><LogoutIcon /></Box>
            Logout
          </Box>
        </Box>
      </Box>

      {/* Main content */}
      <Box ml="220px" flex={1} minH="100vh" color="white">
        {children}
      </Box>
    </Flex>
  )
}

// ── Icons ──────────────────────────────────────────────────────────────────

function LogoutIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>
    </svg>
  )
}

export function ClientsIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8m-4-4v4"/>
    </svg>
  )
}

export function UsersIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>
      <path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
    </svg>
  )
}

export function AuthIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
  )
}
