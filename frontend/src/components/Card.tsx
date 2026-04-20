import { Box } from '@chakra-ui/react'

export function Card({ children, ...props }: React.ComponentProps<typeof Box>) {
  return (
    <Box
      bg="#111"
      border="1px solid #222"
      rounded="xl"
      p={6}
      {...props}
    >
      {children}
    </Box>
  )
}
