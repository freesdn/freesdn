// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import * as React from 'react';
import * as TabsPrimitive from '@radix-ui/react-tabs';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '../../lib/utils';

const Tabs = TabsPrimitive.Root;

/**
 * TabsList · horizontally scrollable tab strip with overflow affordances.
 *
 * Behavior:
 *  - Hidden native scrollbar; horizontal scroll on overflow
 *  - Edge gradient fades signal more content is available
 *  - Chevron buttons on either side scroll by ~80% viewport when overflowing
 *  - The active tab auto-scrolls into view (smooth, centered) on state change
 *  - Keyboard arrow keys still work via Radix primitive
 */
const TabsList = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.List>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.List>
>(({ className, children, ...props }, ref) => {
  const { t } = useTranslation('common');
  const innerRef = React.useRef<HTMLDivElement | null>(null);
  const [showLeftFade, setShowLeftFade] = React.useState(false);
  const [showRightFade, setShowRightFade] = React.useState(false);

  // Compose external ref + our innerRef
  const setRefs = React.useCallback(
    (node: HTMLDivElement | null) => {
      innerRef.current = node;
      if (typeof ref === 'function') ref(node);
      else if (ref) (ref as React.MutableRefObject<HTMLDivElement | null>).current = node;
    },
    [ref]
  );

  const updateFades = React.useCallback(() => {
    const el = innerRef.current;
    if (!el) return;
    const { scrollLeft, scrollWidth, clientWidth } = el;
    // 2px fudge avoids flicker at exact edges
    setShowLeftFade(scrollLeft > 2);
    setShowRightFade(scrollLeft + clientWidth < scrollWidth - 2);
  }, []);

  // Auto-scroll active tab into view (centered, smooth)
  const scrollActiveIntoView = React.useCallback(() => {
    const el = innerRef.current;
    if (!el) return;
    const active = el.querySelector<HTMLElement>('[data-state="active"]');
    if (!active) return;
    active.scrollIntoView({ block: 'nearest', inline: 'center', behavior: 'smooth' });
  }, []);

  React.useEffect(() => {
    const el = innerRef.current;
    if (!el) return;

    updateFades();

    // Resize: container width or content width changed
    const ro = new ResizeObserver(() => updateFades());
    ro.observe(el);
    Array.from(el.children).forEach((c) => ro.observe(c as Element));

    // Mutation: tabs added/removed OR data-state attribute flipped (active change)
    const mo = new MutationObserver((mutations) => {
      let activeChanged = false;
      for (const m of mutations) {
        if (m.type === 'attributes' && m.attributeName === 'data-state') {
          activeChanged = true;
        }
      }
      updateFades();
      if (activeChanged) scrollActiveIntoView();
    });
    mo.observe(el, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['data-state'],
    });

    // Initial: scroll active into view if it starts off-screen
    requestAnimationFrame(() => {
      scrollActiveIntoView();
      updateFades();
    });

    const onScroll = () => updateFades();
    el.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', updateFades);

    // Convert vertical wheel into horizontal scroll when the strip overflows.
    // Only intercepts when there's actual horizontal overflow to scroll into,
    // so pages still scroll vertically when the tab strip already fits.
    const onWheel = (e: WheelEvent) => {
      const overflow = el.scrollWidth - el.clientWidth;
      if (overflow <= 0) return;
      // Prefer the larger axis (lets touchpad horizontal swipes pass through naturally)
      const delta = Math.abs(e.deltaX) > Math.abs(e.deltaY) ? e.deltaX : e.deltaY;
      if (delta === 0) return;
      const atStart = el.scrollLeft <= 0 && delta < 0;
      const atEnd = el.scrollLeft >= overflow && delta > 0;
      if (atStart || atEnd) return; // let page scroll take over at the edges
      e.preventDefault();
      el.scrollLeft += delta;
    };
    el.addEventListener('wheel', onWheel, { passive: false });

    return () => {
      ro.disconnect();
      mo.disconnect();
      el.removeEventListener('scroll', onScroll);
      el.removeEventListener('wheel', onWheel);
      window.removeEventListener('resize', updateFades);
    };
  }, [updateFades, scrollActiveIntoView]);

  const scrollBy = (dir: 'left' | 'right') => {
    const el = innerRef.current;
    if (!el) return;
    const delta = el.clientWidth * 0.8 * (dir === 'left' ? -1 : 1);
    el.scrollBy({ left: delta, behavior: 'smooth' });
  };

  return (
    <div className="relative w-full border-b border-border">
      {/* Left chevron · only when overflowing left */}
      {showLeftFade && (
        <button
          type="button"
          aria-label={t('Tabs.aria.scrollLeft')}
          tabIndex={-1}
          onClick={() => scrollBy('left')}
          className={cn(
            'absolute left-0 top-1/2 z-20 -translate-y-1/2',
            'flex h-7 w-7 items-center justify-center rounded-full',
            'bg-background/95 text-muted-foreground shadow-sm ring-1 ring-border',
            'hover:text-foreground hover:bg-background',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring'
          )}
        >
          <ChevronLeft className="h-4 w-4" />
        </button>
      )}

      {/* Left edge fade */}
      <div
        aria-hidden
        className={cn(
          'pointer-events-none absolute inset-y-0 left-0 z-10 w-8',
          'bg-gradient-to-r from-background to-transparent',
          'transition-opacity duration-150',
          showLeftFade ? 'opacity-100' : 'opacity-0'
        )}
      />

      {/* Right edge fade */}
      <div
        aria-hidden
        className={cn(
          'pointer-events-none absolute inset-y-0 right-0 z-10 w-8',
          'bg-gradient-to-l from-background to-transparent',
          'transition-opacity duration-150',
          showRightFade ? 'opacity-100' : 'opacity-0'
        )}
      />

      {/* Right chevron · only when overflowing right */}
      {showRightFade && (
        <button
          type="button"
          aria-label={t('Tabs.aria.scrollRight')}
          tabIndex={-1}
          onClick={() => scrollBy('right')}
          className={cn(
            'absolute right-0 top-1/2 z-20 -translate-y-1/2',
            'flex h-7 w-7 items-center justify-center rounded-full',
            'bg-background/95 text-muted-foreground shadow-sm ring-1 ring-border',
            'hover:text-foreground hover:bg-background',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring'
          )}
        >
          <ChevronRight className="h-4 w-4" />
        </button>
      )}

      <TabsPrimitive.List
        ref={setRefs}
        className={cn(
          'flex h-9 items-center gap-1 overflow-x-auto scrollbar-hide',
          // Avoid bottom-edge clipping of underline when scrolling
          'scroll-smooth',
          className
        )}
        {...props}
      >
        {children}
      </TabsPrimitive.List>
    </div>
  );
});
TabsList.displayName = TabsPrimitive.List.displayName;

const TabsTrigger = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.Trigger>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Trigger
    ref={ref}
    className={cn(
      'relative inline-flex shrink-0 items-center justify-center whitespace-nowrap px-3 pb-2 text-sm font-medium text-muted-foreground',
      // Keyboard focus ring · essential a11y for users navigating tabs with arrow keys
      'rounded-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
      'disabled:pointer-events-none disabled:opacity-50',
      'hover:text-foreground',
      'data-[state=active]:text-foreground',
      'after:absolute after:bottom-0 after:left-0 after:right-0 after:h-0.5 after:bg-transparent',
      'data-[state=active]:after:bg-primary',
      className
    )}
    {...props}
  />
));
TabsTrigger.displayName = TabsPrimitive.Trigger.displayName;

const TabsContent = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.Content>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Content
    ref={ref}
    className={cn(
      'mt-2 ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
      className
    )}
    {...props}
  />
));
TabsContent.displayName = TabsPrimitive.Content.displayName;

export { Tabs, TabsList, TabsTrigger, TabsContent };
