// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * LagsTab · Link Aggregation Group cards for the switch detail view.
 *
 * Extracted from SwitchesPage as part of the monolith breakup. Receives all
 * data and edit/delete callbacks via props; the parent owns the LAG dialog
 * and mutations.
 */
import { Edit, Link2, MoreVertical, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { EmptyState } from '@/components/ui/empty-state';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

// Local LAG shape · matches the internal type used by SwitchesPage.
export interface LagsTabLAG {
  id: string;
  name: string;
  lag_id: number;
  mode: string;
  member_ports: number[];
  status: string;
  active_ports: number;
  aggregate_speed: number;
}

export interface LagsTabProps {
  lags: LagsTabLAG[] | undefined;
  lagsLoading: boolean;
  onCreate: () => void;
  onEdit: (lag: LagsTabLAG) => void;
  onDelete: (lag: LagsTabLAG) => void;
}

export function LagsTab({ lags, lagsLoading, onCreate, onEdit, onDelete }: LagsTabProps) {
  const { t } = useTranslation('switches');
  return (
    <>
      <div className="flex justify-end">
        <Button onClick={onCreate}>
          <Plus className="mr-2 h-4 w-4" />
          {t('LagsTab.actions.createLag')}
        </Button>
      </div>

      {lagsLoading && (
        <div className="flex items-center justify-center py-8">
          <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      )}

      {!lagsLoading && (!lags || lags.length === 0) && (
        <Card>
          <EmptyState
            icon={Link2}
            title={t('LagsTab.empty.title')}
            description={t('LagsTab.empty.description')}
          />
        </Card>
      )}

      <div className="grid gap-4">
        {lags?.map((lag) => (
          <Card key={lag.id}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Link2 className="h-5 w-5" />
                  <div>
                    <CardTitle className="text-lg">{lag.name}</CardTitle>
                    <CardDescription>{t('LagsTab.card.subtitle', { lagId: lag.lag_id, mode: lag.mode.toUpperCase() })}</CardDescription>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={lag.status === 'up' ? 'default' : 'secondary'}>
                    {lag.status}
                  </Badge>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon">
                        <MoreVertical className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem onClick={() => onEdit(lag)}>
                        <Edit className="mr-2 h-4 w-4" />
                        {t('LagsTab.actions.edit')}
                      </DropdownMenuItem>
                      <DropdownMenuItem className="text-destructive" onClick={() => onDelete(lag)}>
                        <Trash2 className="mr-2 h-4 w-4" />
                        {t('LagsTab.actions.delete')}
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">{t('LagsTab.fields.memberPorts')}</span>
                  <div className="font-medium">{lag.member_ports.join(', ')}</div>
                </div>
                <div>
                  <span className="text-muted-foreground">{t('LagsTab.fields.active')}</span>
                  <div className="font-medium">{lag.active_ports} / {lag.member_ports.length}</div>
                </div>
                <div>
                  <span className="text-muted-foreground">{t('LagsTab.fields.speed')}</span>
                  <div className="font-medium">{t('LagsTab.fields.speedValue', { value: lag.aggregate_speed })}</div>
                </div>
                <div>
                  <span className="text-muted-foreground">{t('LagsTab.fields.mode')}</span>
                  <div className="font-medium">{lag.mode}</div>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </>
  );
}
