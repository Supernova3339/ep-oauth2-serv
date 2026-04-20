import { Flex, Text } from '@chakra-ui/react'
import { useAuth } from '../context/auth'
import { Layout } from '../components/Layout'

export default function Home() {
  const { user } = useAuth()

  return (
    <Layout>
      <Flex direction="column" align="center" justify="center" minH="100vh" gap={3} color="white">
        <Text fontSize="xl" fontWeight={700}>Welcome back, {user?.email}</Text>
        <Text color="#666" fontSize="sm">Select a section from the sidebar to get started.</Text>
      </Flex>
    </Layout>
  )
}
