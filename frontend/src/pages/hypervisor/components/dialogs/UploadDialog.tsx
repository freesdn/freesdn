// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { StorageOperationDialog } from './StorageOperationDialog';

export function UploadDialog({ open, onClose, onTracked, controllerId, storage, node }: {
  open: boolean; onClose: () => void; onTracked: () => void;
  controllerId: string; storage: string; node: string;
}) {
  return open ? <StorageOperationDialog controllerId={controllerId} node={node} storage={storage}
    action="upload" onClose={onClose} onTracked={onTracked} /> : null;
}
