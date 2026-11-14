// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The detection overlay (motion grid, line crossing, intrusion, privacy masks)
 * was a fixed 560 x 315 px box, so on a 390px phone two thirds of the camera
 * image and its editable cells sat off-screen (a 589px right edge in the demo
 * walk). Its width is now a maximum: it fills a narrower container and keeps
 * its aspect ratio. The SVG works in normalised viewBox units, so the editing
 * hit areas scale with it.
 */
import { render } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { CameraCanvasOverlay } from '../CameraCanvasOverlay';

vi.mock('@/lib/api', () => ({
  camerasApi: { getSnapshotUrlAsync: () => Promise.resolve('') },
}));

describe('CameraCanvasOverlay', () => {
  it('uses its width as a maximum and keeps the aspect ratio', () => {
    const { container } = render(<CameraCanvasOverlay cameraId="c1" width={560} />);
    const box = container.firstElementChild as HTMLElement;
    expect(box.style.maxWidth).toBe('560px');
    expect(box.style.width).toBe('');
    expect(box.style.height).toBe('');
    expect(parseFloat(box.style.aspectRatio)).toBeCloseTo(16 / 9);
    expect(box.className).toContain('w-full');
    expect(box.querySelector('svg')?.getAttribute('viewBox')).toBeTruthy();
  });
});
