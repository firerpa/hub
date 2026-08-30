import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

// 后端地址
const target = (process.env.PIGEON_API_BASE_URL || 'https://192.168.50.200:8000').replace(/\/+$/, '')

export default defineConfig({
  base: './',
  build: {
    assetsDir: 'static',
    chunkSizeWarningLimit: 4096,
    rollupOptions: {
      output: {
        hashCharacters: 'hex',
        chunkFileNames: 'static/js/chunk-[hash].js',
        manualChunks: undefined,
        assetFileNames: (chunkInfo) => {
          if (chunkInfo.name == undefined) {
            return 'static/chunk-[hash][extname]'
          }
          let extType = chunkInfo.name.split('.').at(1)!
          if (/png|jpe?g|svg|gif|tiff|bmp|ico/i.test(extType)) {
            extType = 'img'
          }
          return `static/${extType}/chunk-[hash][extname]`
        },
        entryFileNames: 'static/js/chunk-[hash].js',
      },
    },
  },
  worker: {
    rollupOptions: {
      output: {
        hashCharacters: 'hex',
        entryFileNames: 'static/js/chunk-[hash].js',
        chunkFileNames: 'static/js/chunk-[hash].js',
      },
    },
  },
  plugins: [
    vue(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },

  server: {
    host: '0.0.0.0',
    port: 8090,
    open: false,
    strictPort: false,
    proxy: {
      '/api': {
        target,
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path,
      },
      '/proxy': {
        target,
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/proxy/, ''),
      },
      '/d': {
        target,
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path,
        ws: true,
      },
      '/mqtt': {
        target,
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path,
        ws: true,
      },
    },
  },
})
