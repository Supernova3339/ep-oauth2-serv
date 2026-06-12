import { useState } from 'react'
import { Box } from '@chakra-ui/react'

export function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    await navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <Box
      as="button"
      onClick={copy}
      px={2} py={1}
      rounded="md"
      fontSize="11px"
      fontWeight={600}
      cursor="pointer"
      border="1px solid"
      borderColor={copied ? '#1a4a2a' : '#2a2a2a'}
      bg={copied ? '#0a2518' : '#1a1a1a'}
      color={copied ? '#0BA864' : '#666'}
      _hover={{ borderColor: copied ? '#1a4a2a' : '#3a3a3a', color: copied ? '#0BA864' : '#aaa' }}
      transition="all 0.15s"
      flexShrink={0}
    >
      {copied ? 'Copied!' : 'Copy'}
    </Box>
  )
}

export function CopyField({ label, value }: { label?: string; value: string }) {
  return (
    <Box>
      {label && <Box color="#666" fontSize="11px" mb={1}>{label}</Box>}
      <Box display="flex" alignItems="center" gap={2} bg="#1a1a1a" border="1px solid #2a2a2a" rounded="lg" px={3} py={2}>
        <Box flex={1} color="#aaa" fontSize="13px" fontFamily="mono" wordBreak="break-all" overflow="hidden">{value}</Box>
        <CopyButton value={value} />
      </Box>
    </Box>
  )
}
