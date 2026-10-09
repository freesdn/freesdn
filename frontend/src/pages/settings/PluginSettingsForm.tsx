/**
 * Configuring a plugin from the UI.
 *
 * The plugin row advertised a "Configurable" badge and there was no way to
 * configure anything: `GET`/`PUT /plugins/{id}/settings` had no caller at all,
 * so the whole `settings_schema` contract, and the save-time validation behind
 * it, were reachable only by hand with curl. An operator installed a sync
 * plugin, saw the badge, and had nowhere to type the URL and token.
 *
 * The form is generated from the plugin's own JSON Schema, so a plugin gets a
 * settings UI by declaring one and nothing here needs to know about it.
 *
 * SECRETS ARE THE PART TO BE CAREFUL WITH. `GET` never returns a stored
 * credential -- it reports `***` to mean "configured" -- so a form that posted
 * its fields back verbatim would send `***` as the token. The backend now reads
 * that as "unchanged" (it used to encrypt the literal and destroy the real
 * credential), but this form does not rely on that: it sends a secret only when
 * the operator actually changed it. Two independent reasons the credential
 * survives, because one of them is a remote endpoint anyone can call.
 */

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { AlertCircle, Info, KeyRound, Loader2, Save, Settings2 } from 'lucide-react';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { api, getApiErrorMessage } from '@/lib/api';

/** What GET reports in place of a stored secret. Must match SECRET_MASK server-side. */
const SECRET_MASK = '***';

type SettingValue = string | number | boolean | null;

interface FieldSpec {
  type?: string;
  title?: string;
  description?: string;
  default?: SettingValue;
  enum?: SettingValue[];
  secret?: boolean;
  format?: string;
  minimum?: number;
  maximum?: number;
}

interface SettingsSchema {
  properties?: Record<string, FieldSpec>;
  required?: string[];
}

function isSecret(spec: FieldSpec): boolean {
  return spec.secret === true || String(spec.format ?? '').toLowerCase() === 'password';
}

// Select control values are strings, but the settings API preserves JSON types.
// JSON scalar encoding also keeps 1 / "1" and true / "true" distinct.
function optionKey(value: SettingValue): string {
  return JSON.stringify(value);
}

export function PluginSettingsForm({
  pluginId,
  manifest,
}: {
  pluginId: string;
  manifest: Record<string, unknown>;
}) {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();

  const schema = manifest.settings_schema as SettingsSchema | undefined;
  const properties = useMemo(() => schema?.properties ?? {}, [schema]);
  const required = useMemo(() => new Set(schema?.required ?? []), [schema]);
  const fieldNames = useMemo(() => Object.keys(properties), [properties]);

  const { data, isLoading } = useQuery<{ settings: Record<string, SettingValue> }>({
    queryKey: ['plugin-settings', pluginId],
    queryFn: () => api.get(`/plugins/${pluginId}/settings`).then((r) => r.data),
    enabled: fieldNames.length > 0,
  });

  const [values, setValues] = useState<Record<string, SettingValue>>({});
  // Which secrets the operator explicitly edited or selected. Only these are sent.
  const [touchedSecrets, setTouchedSecrets] = useState<Set<string>>(new Set());
  const [warning, setWarning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!data) return;
    const next: Record<string, SettingValue> = {};
    for (const [name, spec] of Object.entries(properties)) {
      const stored = data.settings?.[name];
      // A field the operator has never set falls back to the schema default, so
      // the form shows what the plugin will actually do rather than a blank
      // that implies "off".
      next[name] = stored === undefined ? (spec.default === undefined ? '' : spec.default) : stored;
    }
    setValues(next);
    setTouchedSecrets(new Set());
  }, [data, properties]);

  const save = useMutation({
    mutationFn: () => {
      const payload: Record<string, SettingValue> = {};
      for (const [name, spec] of Object.entries(properties)) {
        if (isSecret(spec) && !touchedSecrets.has(name)) continue;
        payload[name] = values[name] === undefined
          ? (spec.default === undefined ? '' : spec.default)
          : values[name];
      }
      return api.put(`/plugins/${pluginId}/settings`, { settings: payload }).then((r) => r.data);
    },
    onSuccess: (res) => {
      setError(null);
      setSaved(true);
      // The plugin's own verdict on what was just saved. Advisory: the settings
      // are already stored, and a remote being briefly down must not read as a
      // failed save.
      setWarning(res?.warning ?? null);
      setTouchedSecrets(new Set());
      queryClient.invalidateQueries({ queryKey: ['plugin-settings', pluginId] });
      queryClient.invalidateQueries({ queryKey: ['plugin-health', pluginId] });
    },
    onError: (e) => {
      setSaved(false);
      setWarning(null);
      setError(getApiErrorMessage(e, t('PluginsPage.settings.saveFailed')));
    },
  });

  if (fieldNames.length === 0) return null;

  const set = (name: string, value: SettingValue, secret: boolean) => {
    setValues((v) => ({ ...v, [name]: value }));
    setSaved(false);
    if (secret) setTouchedSecrets((s) => new Set(s).add(name));
  };

  return (
    <div className="space-y-3 rounded-md border border-border p-3">
      <div className="flex items-center gap-2">
        <Settings2 className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="text-xs font-medium">{t('PluginsPage.settings.title')}</span>
      </div>

      {isLoading ? (
        <p className="text-xs text-muted-foreground">{t('PluginsPage.settings.loading')}</p>
      ) : (
        <div className="space-y-3">
          {fieldNames.map((name) => {
            const spec = properties[name];
            const secret = isSecret(spec);
            const label = spec.title || name;
            const value = values[name];
            const id = `plugin-${pluginId}-${name}`;
            const options = Array.isArray(spec.enum) ? spec.enum : [];
            const secretUntouched = secret && !touchedSecrets.has(name);
            const retainedChoice = !secretUntouched && value !== undefined
              && !options.some((option) => Object.is(option, value));
            const optionLabel = (option: SettingValue) => {
              if (option === '') return t('PluginsPage.settings.emptyChoice');
              const display = String(option);
              const ambiguous = options.some((other) => !Object.is(other, option) && String(other) === display);
              if (!ambiguous) return display;
              const kind = option === null ? 'null' : typeof option;
              return t('PluginsPage.settings.typedChoice', {
                value: display,
                type: t(`PluginsPage.settings.choiceType.${kind}`),
              });
            };

            return (
              <div key={name} className="space-y-1">
                {spec.type === 'boolean' ? (
                  <div className="flex items-center justify-between gap-3">
                    <Label htmlFor={id} className="text-xs font-medium">
                      {label}
                      {required.has(name) && <span className="text-destructive"> *</span>}
                    </Label>
                    <Switch
                      id={id}
                      checked={value === true}
                      onCheckedChange={(v) => set(name, v, false)}
                    />
                  </div>
                ) : (
                  <>
                    <Label htmlFor={id} className="flex items-center gap-1 text-xs font-medium">
                      {secret && <KeyRound className="h-3 w-3 text-muted-foreground" />}
                      {label}
                      {required.has(name) && <span className="text-destructive"> *</span>}
                    </Label>
                    {options.length > 0 ? (
                      <Select
                        value={secretUntouched || value === undefined ? '' : optionKey(value)}
                        onValueChange={(key) => {
                          const option = options.find((item) => optionKey(item) === key);
                          if (option !== undefined) set(name, option, secret);
                        }}
                      >
                        <SelectTrigger id={id} className="h-8 text-xs">
                          <SelectValue placeholder={secretUntouched
                            ? t(value === SECRET_MASK ? 'PluginsPage.settings.secretChoiceConfigured' : 'PluginsPage.settings.secretEmpty')
                            : undefined} />
                        </SelectTrigger>
                        <SelectContent>
                          {retainedChoice && (
                            <SelectItem value={optionKey(value)} disabled>
                              {t('PluginsPage.settings.retainedChoice', { value: optionLabel(value) })}
                            </SelectItem>
                          )}
                          {options.map((option) => (
                            <SelectItem key={optionKey(option)} value={optionKey(option)}>
                              {optionLabel(option)}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    ) : (
                      <Input
                        id={id}
                        className="h-8 text-xs"
                        type={
                          secret ? 'password' : spec.type === 'integer' || spec.type === 'number' ? 'number' : 'text'
                        }
                        min={spec.minimum}
                        max={spec.maximum}
                        // A configured secret shows an empty box with a
                        // placeholder rather than a fake value: a masked string
                        // sitting in the field invites someone to "correct" it,
                        // and typing over it is how the credential got replaced
                        // with asterisks in the first place.
                        value={secret && !touchedSecrets.has(name) ? '' : String(value ?? '')}
                        placeholder={
                          secret
                            ? value === SECRET_MASK
                              ? t('PluginsPage.settings.secretConfigured')
                              : t('PluginsPage.settings.secretEmpty')
                            : undefined
                        }
                        onChange={(e) =>
                          set(
                            name,
                            spec.type === 'integer' || spec.type === 'number'
                              ? e.target.value === ''
                                ? ''
                                : Number(e.target.value)
                              : e.target.value,
                            secret,
                          )
                        }
                      />
                    )}
                  </>
                )}
                {options.length > 0 && retainedChoice && (
                  <p className="text-[11px] text-muted-foreground">
                    {t('PluginsPage.settings.retainedChoiceHint')}
                  </p>
                )}
                {spec.description && (
                  <p className="text-[11px] leading-snug text-muted-foreground whitespace-pre-line">
                    {spec.description.trim()}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {warning && (
        <Alert>
          <Info className="h-4 w-4" />
          <AlertTitle>{t('PluginsPage.settings.checkTitle')}</AlertTitle>
          <AlertDescription>{warning}</AlertDescription>
        </Alert>
      )}

      {saved && !warning && !error && (
        <p className="text-xs text-success">{t('PluginsPage.settings.savedOk')}</p>
      )}

      <Button size="sm" onClick={() => save.mutate()} disabled={save.isPending || isLoading}>
        {save.isPending ? (
          <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
        ) : (
          <Save className="mr-2 h-3.5 w-3.5" />
        )}
        {t('PluginsPage.settings.save')}
      </Button>
    </div>
  );
}
