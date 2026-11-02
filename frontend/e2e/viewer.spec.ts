import {test,expect} from '@playwright/test'
import type { Page } from '@playwright/test'
import type { FrameLocator } from '@playwright/test'

// Chromium and Gecko can round subpixel CSS transform hit-testing to
// adjacent logical coordinates. Require a fresh pointer event no farther
// than one remote-display pixel from the intended 1920x1080 grid point.
async function clickRemotePixel(page: Page, frame: ReturnType<Page['locator']>, x: number, y: number) {
  // This is a true parent-window pointer event, not a locator click inside
  // the scaled child. Read the browser's actual transformed rectangle, derive
  // its physical scale from rendered width and aim at logical pixel CENTER.
  const box = await frame.boundingBox()
  expect(box).not.toBeNull()
  const sx = box!.width / 1920
  const sy = box!.height / 1080
  expect(Math.abs(sx - sy)).toBeLessThan(0.001)
  await page.mouse.click(box!.x + (x + 0.5) * sx,
                         box!.y + (y + 0.5) * sy)
}

async function expectFreshRemotePointer(inside: FrameLocator, x: number, y: number, count: number) {
  await expect.poll(async () => {
    const seen = await inside.locator('body').evaluate(() => ({
      point: (window as any).__lastRemotePoint,
      count: (window as any).__pointerCount,
    }))
    if (seen.count !== count || !seen.point) return Infinity
    return Math.max(Math.abs(seen.point.x - (x + 0.5)), Math.abs(seen.point.y - (y + 0.5)))
  }).toBeLessThanOrEqual(1)
}


test('real browser iframe hit-testing, browser resize, local fit and fixed geometry', async ({page}) => {
  await page.setViewportSize({width:1024,height:768})
  await page.goto('/e2e/viewer.html#/unused')
  const frame = page.locator('iframe[title="VNC workspace one"]')
  await expect(frame).toBeVisible()
  await expect(frame).toHaveCSS('width','1920px')
  await expect(frame).toHaveCSS('height','1080px')
  const stage = page.locator('.vnc-scaled-display[data-workspace-id="one"]')
  await expect.poll(async () => Number(await stage.getAttribute('data-local-scale'))).toBeGreaterThan(0.4)
  const scale = Number(await stage.getAttribute('data-local-scale'))
  expect(scale).toBeLessThan(1)
  let rect = await frame.boundingBox()
  expect(rect).not.toBeNull()
  expect(rect!.width).toBeCloseTo(1920 * scale,0)
  expect(rect!.height).toBeCloseTo(1080 * scale,0)

  const expected = {x:320,y:300}
  const inside = page.frameLocator('iframe[title="VNC workspace one"]')
  await clickRemotePixel(page, frame, expected.x, expected.y)
  await expectFreshRemotePointer(inside, 320, 300, 1)

  await page.setViewportSize({width:1440,height:900})
  await expect.poll(async () => Number(await stage.getAttribute('data-local-scale'))).toBeGreaterThan(scale)
  const resizedScale = Number(await stage.getAttribute('data-local-scale'))
  const next = await frame.boundingBox()
  expect(next!.width).toBeCloseTo(1920 * resizedScale, 0)
  await clickRemotePixel(page, frame, 320, 300)
  await expectFreshRemotePointer(inside, 320, 300, 2)
  expect(await frame.getAttribute('src')).toContain('resize=scale')
  expect(await frame.getAttribute('src')).not.toContain('resize=remote')
  await expect(frame).toHaveCSS('width','1920px')
  await expect(frame).toHaveCSS('height','1080px')
})

test('iframe identity survives navigation; zoom and fit survive reconnect per Workspace', async ({page}) => {
  await page.setViewportSize({width:1200,height:850})
  await page.goto('/e2e/viewer.html')
  const frame = page.locator('iframe[title="VNC workspace one"]')
  await expect(frame).toBeVisible()
  const identity = await frame.contentFrame().locator('body').evaluate(() => (window as any).__viewerFrameIdentity)
  await page.getByRole('button',{name:'Zoom in'}).click()
  await expect(page.getByLabel('Viewer zoom')).toHaveText('125%')
  const scaled = page.locator('.vnc-scaled-display[data-workspace-id="one"]')
  await expect.poll(async () => Number(await scaled.getAttribute('data-local-scale'))).toBeGreaterThan(0.5)
  // Zoom is a real browser transform: hit-testing must still deliver exact
  // iframe-local desktop coordinates, not scaled terminal coordinates.
  const zoomScale = Number(await scaled.getAttribute('data-local-scale'))
  const zoomBounds = await frame.boundingBox()
  expect(zoomBounds!.width).toBeCloseTo(1920 * zoomScale, 0)
  await clickRemotePixel(page, frame, 250, 260)
  await expectFreshRemotePointer(frame.contentFrame(), 250, 260, 1)
  await page.getByRole('link',{name:'Away'}).click()
  await expect(page.getByTestId('away')).toBeVisible()
  await expect(frame).toHaveCount(1)
  expect(await frame.contentFrame().locator('body').evaluate(() => (window as any).__viewerFrameIdentity)).toBe(identity)
  await page.getByRole('link',{name:'Workspace one'}).click()
  await expect(page.getByLabel('Viewer zoom')).toHaveText('125%')
  expect(await frame.contentFrame().locator('body').evaluate(() => (window as any).__viewerFrameIdentity)).toBe(identity)

  await page.getByRole('button',{name:'Close viewer'}).click()
  await expect(frame).toHaveCount(0)
  await page.getByRole('button',{name:'Connect'}).click()
  await expect(frame).toBeVisible()
  await expect(page.getByLabel('Viewer zoom')).toHaveText('125%')
  await page.getByRole('link',{name:'Workspace two'}).click()
  await expect(page.getByLabel('Viewer zoom')).toHaveText('100%')
  await expect(page.locator('iframe[title="VNC workspace one"]')).toHaveCount(1)
  await page.getByRole('link',{name:'Workspace one'}).click()
  await expect(page.getByLabel('Viewer zoom')).toHaveText('125%')
  await page.getByLabel('Fit window').uncheck()
  await expect.poll(async () => Number(await scaled.getAttribute('data-local-scale'))).toBe(1.25)
  await page.getByRole('button',{name:'Reset view'}).click()
  await expect(page.getByLabel('Fit window')).toBeChecked()
  await expect(page.getByLabel('Viewer zoom')).toHaveText('100%')
})
