// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * AdoptDeviceDialog - 3-step wizard to adopt a discovered device.
 *
 * Steps: 1) Select Driver  2) Configure Credentials  3) Review & Adopt
 *
 * Built on the canonical FormDialog primitive. The wizard step is local
 * UI state (not part of the form values). FormDialog's submit button
 * is bound to "Adopt Device" and is only enabled on the final step.
 * Back/Next navigation lives in the `footerExtra` slot.
 */

import { useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { z } from 'zod';
import {
  Cpu,
  Key,
  CheckCircle2,
  ChevronRight,
  ChevronLeft,
  Plus,
} from 'lucide-react';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { cn } from '@/lib/utils';
import { discoveryApi, credentialsApi } from '@/lib/api';
import DriverSelector, { type DriverInfo } from './DriverSelector';
import type { DiscoveredDevice } from './DiscoveredDeviceCard';

interface AdoptDeviceDialogProps {
  device: DiscoveredDevice | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  siteId: string;
  onAdopted?: () => void;
  /**
   * Live driver registry from discoveryApi.listDrivers(). When the parent
   * page already fetches it, pass it down so the selector shows real
   * registry ids (the adopt endpoint 400s on unknown ids). Falls back to
   * FALLBACK_DRIVERS when empty/omitted.
   */
  drivers?: DriverInfo[];
}

const WIZARD_STEPS = [
  { labelKey: 'steps.driver', icon: Cpu },
  { labelKey: 'steps.credentials', icon: Key },
  { labelKey: 'steps.confirm', icon: CheckCircle2 },
];

// Fallback driver list used only when the live registry is unavailable.
// IDs match the backend DRIVER_REGISTRY (discovery.py), single-device adopt
// 400s on any id the registry doesn't know. Grandstream/SNMP are intentionally
// absent: they are not registered backend drivers (use "generic" for those).
const FALLBACK_DRIVERS: DriverInfo[] = [
  { id: 'omada_controller', name: 'TP-Link Omada Controller', vendor: 'tp-link', device_types: ['omada_controller', 'access_point', 'switch', 'gateway'], capabilities: ['monitoring', 'configuration'], version: '1.0.0' },
  { id: 'hikvision_isapi', name: 'Hikvision ISAPI', vendor: 'hikvision', device_types: ['camera', 'nvr', 'dvr'], capabilities: ['streams', 'monitoring'], version: '1.0.0' },
  { id: 'mikrotik_routeros', name: 'MikroTik RouterOS', vendor: 'mikrotik', device_types: ['router', 'switch', 'access_point'], capabilities: ['monitoring', 'configuration', 'firmware'], version: '1.0.0' },
  { id: 'opnsense_api', name: 'OPNsense Firewall', vendor: 'deciso', device_types: ['firewall', 'router', 'gateway'], capabilities: ['monitoring', 'firewall_rules', 'vpn'], version: '1.0.0' },
  { id: 'pfsense_api', name: 'pfSense Firewall', vendor: 'netgate', device_types: ['firewall', 'router', 'gateway'], capabilities: ['monitoring', 'firewall_rules', 'vpn'], version: '1.0.0' },
  { id: 'generic', name: 'Generic Tracked Device', vendor: 'generic', device_types: ['other', 'iot_device', 'voip_phone', 'switch', 'router', 'camera'], capabilities: ['inventory'], version: '1.0.0' },
];

// Cross-field validation: enforce credential requirements based on mode +
// driver selection. The driver itself isn't a form input (it's chosen via the
// custom <DriverSelector>) so we surface a refinement-level error if missing.
const buildSchema = (t: TFunction) =>
  z
    .object({
      deviceName: z.string(),
      driverId: z.string().min(1, t('AdoptDeviceDialog.validation.selectDriver')),
      credentialMode: z.enum(['existing', 'new']),
      selectedCredentialId: z.string(),
      newCredName: z.string(),
      newCredUsername: z.string(),
      newCredPassword: z.string(),
    })
    .superRefine((data, ctx) => {
      if (data.credentialMode === 'existing') {
        if (!data.selectedCredentialId) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['selectedCredentialId'], message: t('AdoptDeviceDialog.validation.selectCredential') });
        }
      } else {
        if (!data.newCredUsername.trim()) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['newCredUsername'], message: t('AdoptDeviceDialog.validation.usernameRequired') });
        }
        if (!data.newCredPassword.trim()) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['newCredPassword'], message: t('AdoptDeviceDialog.validation.passwordRequired') });
        }
      }
    });
type AdoptFormValues = z.infer<ReturnType<typeof buildSchema>>;

const initialValues: AdoptFormValues = {
  deviceName: '',
  driverId: '',
  credentialMode: 'existing',
  selectedCredentialId: '',
  newCredName: '',
  newCredUsername: '',
  newCredPassword: '',
};

export default function AdoptDeviceDialog({
  device,
  open,
  onOpenChange,
  siteId,
  onAdopted,
  drivers,
}: AdoptDeviceDialogProps) {
  const { t } = useTranslation('common');
  const queryClient = useQueryClient();
  const schema = buildSchema(t);
  const [step, setStep] = useState(0);
  // Prefer the live registry passed from the page; fall back only if absent.
  const availableDrivers = drivers && drivers.length > 0 ? drivers : FALLBACK_DRIVERS;
  // Per-instance ref bridging children render-prop (where form state lives)
  // with footerExtra (rendered in FormDialog's outer scope).
  const canProceedRef = useRef<() => boolean>(() => false);

  // Fetch existing credentials
  const { data: credentialsData } = useQuery({
    queryKey: ['credentials'],
    queryFn: async () => {
      const res = await credentialsApi.list();
      return res.data;
    },
    enabled: open,
  });
  const credentials = credentialsData ?? [];  // backend returns a bare array

  // Adopt mutation · server errors propagate via FormDialog's banner.
  const adoptMutation = useMutation({
    mutationFn: (data: Parameters<typeof discoveryApi.adoptDevice>[0]) =>
      discoveryApi.adoptDevice(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['discovery'] });
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      onOpenChange(false);
      onAdopted?.();
      setStep(0);
    },
  });

  if (!device) return null;

  const recommendedDriverId = device.driver_match?.driver_id;
  const isFinalStep = step === WIZARD_STEPS.length - 1;

  return (
    <FormDialog<AdoptFormValues>
      open={open}
      onOpenChange={(next) => {
        if (!next) setStep(0);
        onOpenChange(next);
      }}
      title={t('AdoptDeviceDialog.title', { ip: device.ip })}
      schema={schema}
      defaultValues={initialValues}
      submitLabel={t('AdoptDeviceDialog.submitLabel')}
      submitDisabled={!isFinalStep}
      contentClassName="max-w-lg"
      onSubmit={async (values) => {
        if (!isFinalStep) return;
        const driver = availableDrivers.find((d) => d.id === values.driverId);
        if (!driver) throw new Error(t('AdoptDeviceDialog.errors.driverNotSelected'));

        let credentialId = values.credentialMode === 'existing' ? values.selectedCredentialId : undefined;

        // If creating new credential, create it first.
        if (values.credentialMode === 'new') {
          const res = await credentialsApi.create({
            name: values.newCredName || t('AdoptDeviceDialog.defaultCredentialName', { ip: device.ip }),
            credential_type: 'username_password',
            scope: 'device',
            username: values.newCredUsername,
            password: values.newCredPassword,
            site_id: siteId,
          });
          credentialId = res.data.id;
        }

        await adoptMutation.mutateAsync({
          ip_address: device.ip,
          name: values.deviceName || device.hostname || device.ip,
          mac_address: device.mac,
          site_id: siteId,
          driver_id: driver.id,
          credential_id: credentialId,
          device_type: device.device_type || driver.device_types[0],
        });
      }}
      footerExtra={
        <div className="flex flex-1 items-center gap-2">
          {step > 0 && (
            <Button
              type="button"
              variant="ghost"
              onClick={() => setStep((s) => s - 1)}
              className="gap-1.5"
            >
              <ChevronLeft className="h-4 w-4" />
              {t('AdoptDeviceDialog.actions.back')}
            </Button>
          )}
          {!isFinalStep && (
            <Button
              type="button"
              onClick={() => {
                if (canProceedRef.current()) setStep((s) => s + 1);
              }}
              className="gap-1.5 ml-auto"
            >
              {t('AdoptDeviceDialog.actions.next')} <ChevronRight className="h-4 w-4" />
            </Button>
          )}
        </div>
      }
    >
      {(form) => {
        const driverId = form.watch('driverId');
        const credentialMode = form.watch('credentialMode');
        const selectedCredentialId = form.watch('selectedCredentialId');
        const newCredUsername = form.watch('newCredUsername');
        const newCredPassword = form.watch('newCredPassword');
        const newCredName = form.watch('newCredName');
        const deviceName = form.watch('deviceName');

        const selectedDriver = availableDrivers.find((d) => d.id === driverId) ?? null;

        // Bridge form state (only readable inside this render-prop) into the
        // Next button rendered in `footerExtra` via the ref.
        canProceedRef.current = () => {
          if (step === 0) return !!driverId;
          if (step === 1) {
            if (credentialMode === 'existing') return !!selectedCredentialId;
            return !!(newCredUsername.trim() && newCredPassword.trim());
          }
          return true;
        };

        return (
          <>
            {/* Step indicator */}
            <div className="flex items-center gap-3 mb-1">
              {WIZARD_STEPS.map((s, i) => {
                const Icon = s.icon;
                return (
                  <div key={i} className="flex items-center gap-2">
                    <div className={cn(
                      'w-8 h-8 rounded-full flex items-center justify-center border transition-colors',
                      i < step ? 'bg-primary text-primary-foreground border-primary' :
                      i === step ? 'bg-primary/10 text-primary border-primary' :
                      'bg-muted text-muted-foreground border-border',
                    )}>
                      <Icon className="h-4 w-4" />
                    </div>
                    <span className={cn('text-xs', i === step ? 'font-medium' : 'text-muted-foreground')}>
                      {t(`AdoptDeviceDialog.${s.labelKey}`)}
                    </span>
                    {i < WIZARD_STEPS.length - 1 && (
                      <div className={cn('w-6 h-0.5 rounded', i < step ? 'bg-primary' : 'bg-border')} />
                    )}
                  </div>
                );
              })}
            </div>

            {/* Step 0: Driver Selection */}
            {step === 0 && (
              <div className="space-y-3">
                <FormField
                  control={form.control}
                  name="deviceName"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('AdoptDeviceDialog.fields.deviceName')}</FormLabel>
                      <FormControl>
                        <Input placeholder={device.hostname || device.ip} {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="driverId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('AdoptDeviceDialog.fields.selectDriver')}</FormLabel>
                      <DriverSelector
                        drivers={availableDrivers}
                        selectedDriverId={field.value || undefined}
                        recommendedDriverId={recommendedDriverId}
                        onSelect={(d) => field.onChange(d.id)}
                      />
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
            )}

            {/* Step 1: Credentials */}
            {step === 1 && (
              <FormField
                control={form.control}
                name="credentialMode"
                render={({ field }) => (
                  <Tabs
                    value={field.value}
                    onValueChange={(v) => field.onChange(v as 'existing' | 'new')}
                  >
                    <TabsList className="grid w-full grid-cols-2">
                      <TabsTrigger value="existing">
                        <Key className="h-3.5 w-3.5 mr-1.5" /> {t('AdoptDeviceDialog.credentials.useExisting')}
                      </TabsTrigger>
                      <TabsTrigger value="new">
                        <Plus className="h-3.5 w-3.5 mr-1.5" /> {t('AdoptDeviceDialog.credentials.createNew')}
                      </TabsTrigger>
                    </TabsList>

                    <TabsContent value="existing" className="space-y-3 mt-3">
                      <FormField
                        control={form.control}
                        name="selectedCredentialId"
                        render={({ field: credField }) => (
                          <FormItem>
                            <Select value={credField.value} onValueChange={credField.onChange}>
                              <FormControl>
                                <SelectTrigger>
                                  <SelectValue placeholder={t('AdoptDeviceDialog.credentials.selectPlaceholder')} />
                                </SelectTrigger>
                              </FormControl>
                              <SelectContent>
                                {credentials.map((c: { id: string; name: string; vendor?: string }) => (
                                  <SelectItem key={c.id} value={c.id}>
                                    <div className="flex items-center gap-2">
                                      <Key className="h-3.5 w-3.5" />
                                      {c.name}
                                      {c.vendor && <Badge variant="secondary" className="text-[9px]">{c.vendor}</Badge>}
                                    </div>
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      {credentials.length === 0 && (
                        <p className="text-xs text-muted-foreground text-center py-4">
                          {t('AdoptDeviceDialog.credentials.noneFound')}
                        </p>
                      )}
                    </TabsContent>

                    <TabsContent value="new" className="space-y-3 mt-3">
                      <FormField
                        control={form.control}
                        name="newCredName"
                        render={({ field: nameField }) => (
                          <FormItem>
                            <FormLabel>{t('AdoptDeviceDialog.fields.nameOptional')}</FormLabel>
                            <FormControl>
                              <Input placeholder={t('AdoptDeviceDialog.fields.namePlaceholder')} {...nameField} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={form.control}
                        name="newCredUsername"
                        render={({ field: userField }) => (
                          <FormItem>
                            <FormLabel>{t('AdoptDeviceDialog.fields.username')}</FormLabel>
                            <FormControl>
                              <Input placeholder="admin" {...userField} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={form.control}
                        name="newCredPassword"
                        render={({ field: pwField }) => (
                          <FormItem>
                            <FormLabel>{t('AdoptDeviceDialog.fields.password')}</FormLabel>
                            <FormControl>
                              <Input type="password" placeholder="••••••••" {...pwField} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </TabsContent>
                  </Tabs>
                )}
              />
            )}

            {/* Step 2: Review & Confirm */}
            {step === 2 && (
              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-muted/50 space-y-2.5">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{t('AdoptDeviceDialog.review.device')}</span>
                    <span className="font-mono">{device.ip}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{t('AdoptDeviceDialog.review.name')}</span>
                    <span>{deviceName || device.hostname || device.ip}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{t('AdoptDeviceDialog.review.driver')}</span>
                    <span className="font-medium">{selectedDriver?.name}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{t('AdoptDeviceDialog.review.credentials')}</span>
                    <span>
                      {credentialMode === 'existing'
                        ? credentials.find((c: { id: string; name: string }) => c.id === selectedCredentialId)?.name || '-'
                        : t('AdoptDeviceDialog.review.newCredential', { name: newCredName || t('AdoptDeviceDialog.review.autoNamed') })
                      }
                    </span>
                  </div>
                  {device.vendor && (
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">{t('AdoptDeviceDialog.review.vendor')}</span>
                      <Badge variant="secondary">{device.vendor}</Badge>
                    </div>
                  )}
                </div>
                <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20 text-sm text-blue-700 dark:text-blue-300">
                  {t('AdoptDeviceDialog.review.info')}
                </div>
              </div>
            )}
          </>
        );
      }}
    </FormDialog>
  );
}

