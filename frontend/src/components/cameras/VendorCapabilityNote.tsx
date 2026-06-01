// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * VendorCapabilityNote, honest inline note shown on recordings / playback /
 * zone surfaces when a camera's vendor isn't natively supported (i.e. anything
 * but Hikvision in this release). Renders nothing for natively-supported vendors,
 * so it's safe to drop into any of those panels unconditionally.
 */
import { useTranslation } from 'react-i18next';
import { Info } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { cn } from '@/lib/utils';
import { isNativeVendor } from '@/lib/cameraVendors';

type Feature = 'recordings' | 'playback' | 'zones';

interface VendorCapabilityNoteProps {
  vendor?: string | null;
  feature: Feature;
  className?: string;
}

export function VendorCapabilityNote({ vendor, feature, className }: VendorCapabilityNoteProps) {
  const { t } = useTranslation('common');
  if (isNativeVendor(vendor)) return null;
  return (
    <Alert className={cn('border-amber-500/40 bg-amber-500/5', className)}>
      <Info className="h-4 w-4 text-amber-500" />
      <AlertDescription className="text-xs text-muted-foreground">
        {t(`vendorSupport.notes.${feature}`)}
      </AlertDescription>
    </Alert>
  );
}

export default VendorCapabilityNote;
