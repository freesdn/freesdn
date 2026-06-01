// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Camera Preview Widget
 * 
 * Live camera thumbnails with status
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';
import { 
  Video, 
  VideoOff, 
  Maximize2, 
  Camera,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

interface CameraPreview {
  id: string;
  name: string;
  location?: string;
  status: 'online' | 'offline' | 'recording' | 'error';
  thumbnail?: string;
  isRecording?: boolean;
}

interface CameraPreviewWidgetProps {
  cameras: CameraPreview[];
  maxDisplay?: number;
  onViewCamera?: (cameraId: string) => void;
  onViewAll?: () => void;
  className?: string;
}

const statusColors = {
  online: 'bg-success',
  offline: 'bg-muted-foreground',
  recording: 'bg-destructive animate-pulse',
  error: 'bg-warning',
};

export function CameraPreviewWidget({
  cameras,
  maxDisplay = 4,
  onViewCamera,
  onViewAll,
  className,
}: CameraPreviewWidgetProps) {
  const { t } = useTranslation('common');
  const displayCameras = cameras.slice(0, maxDisplay);
  const remainingCount = cameras.length - maxDisplay;

  if (cameras.length === 0) {
    return (
      <div className={cn('flex flex-col items-center justify-center py-12', className)}>
        <Camera className="h-12 w-12 text-muted-foreground/30" />
        <p className="mt-4 text-sm text-muted-foreground">{t('CameraPreviewWidget.empty.title')}</p>
        <Button variant="outline" size="sm" className="mt-4">
          {t('CameraPreviewWidget.actions.addCamera')}
        </Button>
      </div>
    );
  }

  return (
    <div className={cn('space-y-4', className)}>
      <div className="grid grid-cols-2 gap-2">
        {displayCameras.map((camera, index) => (
          <CameraThumb
            key={camera.id}
            camera={camera}
            index={index}
            onClick={() => onViewCamera?.(camera.id)}
          />
        ))}
      </div>

      {(remainingCount > 0 || onViewAll) && (
        <Button
          variant="ghost"
          className="w-full"
          onClick={onViewAll}
        >
          {remainingCount > 0
            ? t('CameraPreviewWidget.actions.viewAllCount', { count: cameras.length })
            : t('CameraPreviewWidget.actions.viewAll')
          }
        </Button>
      )}
    </div>
  );
}

function CameraThumb({
  camera,
  index,
  onClick,
}: {
  camera: CameraPreview;
  index: number;
  onClick?: () => void;
}) {
  const { t } = useTranslation('common');
  const [imageError, setImageError] = useState(false);
  const isOnline = camera.status === 'online' || camera.status === 'recording';

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ delay: index * 0.05 }}
      className="group relative aspect-video overflow-hidden rounded-lg bg-muted cursor-pointer"
      onClick={onClick}
    >
      {/* Thumbnail or placeholder */}
      {camera.thumbnail && !imageError ? (
        <img
          src={camera.thumbnail}
          alt={camera.name}
          className="h-full w-full object-cover"
          onError={() => setImageError(true)}
        />
      ) : (
        <div className="flex h-full w-full items-center justify-center">
          {isOnline ? (
            <Video className="h-8 w-8 text-muted-foreground/70" />
          ) : (
            <VideoOff className="h-8 w-8 text-muted-foreground/70" />
          )}
        </div>
      )}

      {/* Status indicator */}
      <div className="absolute top-2 left-2 flex items-center gap-1.5">
        <span className={cn('h-2 w-2 rounded-full', statusColors[camera.status])} />
        {camera.isRecording && (
          <span className="text-[10px] font-medium text-destructive-foreground bg-destructive px-1 rounded">
            {t('CameraPreviewWidget.recording')}
          </span>
        )}
      </div>

      {/* Overlay on hover */}
      <div className="absolute inset-0 bg-gradient-to-t from-black/70 via-black/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity">
        <div className="absolute bottom-0 left-0 right-0 p-2">
          <p className="text-xs font-medium text-white truncate">{camera.name}</p>
          {camera.location && (
            <p className="text-[10px] text-white/70 truncate">{camera.location}</p>
          )}
        </div>
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2">
          <Maximize2 className="h-6 w-6 text-white" />
        </div>
      </div>

      {/* Name label (always visible) */}
      <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/60 to-transparent p-2 group-hover:opacity-0 transition-opacity">
        <p className="text-[10px] font-medium text-white truncate">{camera.name}</p>
      </div>
    </motion.div>
  );
}
