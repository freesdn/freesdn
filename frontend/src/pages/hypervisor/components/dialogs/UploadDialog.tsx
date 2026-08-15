// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Storage Upload Dialog
 * Upload ISO images or container templates to Proxmox storage.
 *
 * Built on the canonical FormDialog primitive. The selected File lives
 * outside the form (browsers won't let you set <input type=file>'s value
 * programmatically), so it's tracked as local state and validated via the
 * `submitDisabled` prop and a manual check inside `onSubmit`.
 */
import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import { Upload, FileUp } from 'lucide-react';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { hypervisorApi } from '@/lib/api';
import { formatBytes } from '../helpers';

interface UploadDialogProps {
  open: boolean;
  onClose: () => void;
  controllerId: string;
  storage: string;
  node: string;
}

const schema = z.object({
  contentType: z.enum(['iso', 'vztmpl']),
});
type UploadFormValues = z.infer<typeof schema>;

const defaultValues: UploadFormValues = { contentType: 'iso' };

export function UploadDialog({ open, onClose, controllerId, storage, node }: UploadDialogProps) {
  const { t } = useTranslation('hypervisor');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const uploadMutation = useMutation({
    mutationFn: ({ file, contentType }: { file: File; contentType: string }) =>
      hypervisorApi.uploadToStorage(controllerId, node, storage, file, contentType),
    onSuccess: (_data, vars) => {
      toast({ title: t('UploadDialog.toast.startedTitle'), description: t('UploadDialog.toast.startedDescription', { fileName: vars.file.name, storage }) });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'storage'] });
      setSelectedFile(null);
      onClose();
    },
    onError: (err: unknown) => {
      const e = err as { response?: { data?: { detail?: string } }; message?: string };
      toast({ title: t('UploadDialog.toast.failedTitle'), description: e?.response?.data?.detail || e.message, variant: 'destructive' });
    },
  });

  return (
    <FormDialog<UploadFormValues>
      open={open}
      onOpenChange={(o) => { if (!o) { setSelectedFile(null); onClose(); } }}
      title={t('UploadDialog.title')}
      description={t('UploadDialog.description', { storage, node })}
      schema={schema}
      defaultValues={defaultValues}
      submitLabel={uploadMutation.isPending ? t('UploadDialog.submit.uploading') : t('UploadDialog.submit.upload')}
      contentClassName="sm:max-w-md"
      submitDisabled={!selectedFile}
      onSubmit={async (values) => {
        if (!selectedFile) throw new Error(t('UploadDialog.errors.noFileSelected'));
        await uploadMutation.mutateAsync({ file: selectedFile, contentType: values.contentType });
      }}
    >
      {(form) => {
        const contentType = form.watch('contentType');
        return (
          <>
            <FormField
              control={form.control}
              name="contentType"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('UploadDialog.fields.contentType')}</FormLabel>
                  <Select value={field.value} onValueChange={field.onChange}>
                    <FormControl>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="iso">{t('UploadDialog.contentTypes.iso')}</SelectItem>
                      <SelectItem value="vztmpl">{t('UploadDialog.contentTypes.vztmpl')}</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="space-y-2">
              <Label>{t('UploadDialog.fields.file')}</Label>
              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                accept={contentType === 'iso' ? '.iso,.img' : '.tar.gz,.tar.xz,.tar.zst'}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) setSelectedFile(file);
                }}
              />
              <div
                className="border-2 border-dashed rounded-lg p-6 text-center cursor-pointer hover:border-primary/50 transition-colors"
                onClick={() => fileInputRef.current?.click()}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInputRef.current?.click(); } }}
                role="button"
                tabIndex={0}
              >
                {selectedFile ? (
                  <div className="space-y-1">
                    <FileUp className="h-8 w-8 text-primary mx-auto" />
                    <p className="text-sm font-medium">{selectedFile.name}</p>
                    <p className="text-xs text-muted-foreground">{formatBytes(selectedFile.size)}</p>
                  </div>
                ) : (
                  <div className="space-y-1">
                    <Upload className="h-8 w-8 text-muted-foreground mx-auto" />
                    <p className="text-sm text-muted-foreground">{t('UploadDialog.dropzone.selectFile')}</p>
                    <p className="text-xs text-muted-foreground">
                      {contentType === 'iso' ? t('UploadDialog.dropzone.isoHint') : t('UploadDialog.dropzone.tmplHint')}
                    </p>
                  </div>
                )}
              </div>
            </div>
          </>
        );
      }}
    </FormDialog>
  );
}
