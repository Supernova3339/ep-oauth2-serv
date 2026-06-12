import { Dialog, Portal } from '@chakra-ui/react'

interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  children: React.ReactNode
  maxW?: string
}

export function Modal({ open, onClose, title, children, maxW = '480px' }: ModalProps) {
  return (
    <Dialog.Root open={open} onOpenChange={({ open }) => { if (!open) onClose() }} placement="center">
      <Portal>
        <Dialog.Backdrop bg="blackAlpha.800" backdropFilter="blur(4px)" />
        <Dialog.Positioner>
          <Dialog.Content
            bg="#111" border="1px solid #222" rounded="xl"
            maxW={maxW} w="full" mx={4} shadow="2xl"
          >
            <Dialog.Header px={6} py={4} borderBottom="1px solid #1e1e1e">
              <Dialog.Title color="white" fontWeight={600} fontSize="md">{title}</Dialog.Title>
              <Dialog.CloseTrigger
                position="absolute" top={3} right={4}
                color="#555" cursor="pointer"
                _hover={{ color: 'white' }}
              />
            </Dialog.Header>
            {children}
          </Dialog.Content>
        </Dialog.Positioner>
      </Portal>
    </Dialog.Root>
  )
}

export { Dialog }
