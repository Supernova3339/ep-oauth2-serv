import { createSystem, defaultConfig, defineConfig } from '@chakra-ui/react'

const config = defineConfig({
  theme: {
    tokens: {
      colors: {
        green: {
          50:  { value: '#e6f7ef' },
          100: { value: '#b3e7d2' },
          200: { value: '#80d7b5' },
          300: { value: '#4dc797' },
          400: { value: '#26bb7e' },
          500: { value: '#0BA864' },
          600: { value: '#099558' },
          700: { value: '#07784a' },
          800: { value: '#055c38' },
          900: { value: '#034027' },
          950: { value: '#02291a' },
        },
      },
    },
  },
})

export const system = createSystem(defaultConfig, config)
