import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: '.', testMatch: /viewer\.spec\.ts/,
  timeout: 25_000, expect: { timeout: 8_000 },
  use: { baseURL:'http://127.0.0.1:4175', trace:'retain-on-failure' },
  projects: [{name:'chromium',use:{...devices['Desktop Chrome']}}],
  webServer: {command:'npm run dev -- --host 127.0.0.1 --port 4175 --strictPort',
              url:'http://127.0.0.1:4175/e2e/viewer.html',
              reuseExistingServer:false,timeout:45_000},
})
