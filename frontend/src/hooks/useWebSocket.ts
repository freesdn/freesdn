// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useEffect, useRef, useCallback, useMemo } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { getCookie, getWebSocketUrl } from '../lib/api';
import { useAuthStore } from '../stores/authStore';
import { isDemoMode } from '@/demo/mode';

type ConnectionStatus = 'connecting' | 'online' | 'offline';

interface WebSocketMessage {
  type: string;
  data: unknown;
  timestamp?: string;
}

interface UseWebSocketOptions {
  url?: string;
  enabled?: boolean;
  reconnectAttempts?: number;
  reconnectInterval?: number;
  heartbeatInterval?: number;
  batchInterval?: number;
  onMessage?: (message: WebSocketMessage) => void;
  /** Called when connection status changes · use to sync with external store
   *  without causing re-renders of the host component. */
  onStatusChange?: (status: ConnectionStatus) => void;
  /** Override the default firehose subscription set. A secondary, page-scoped
   *  socket (e.g. DiscoveryPage) should pass only what it needs (['discovery.*'])
   *  so it doesn't also receive, and re-dispatch, camera/vpn/pbx events that
   *  the global App socket already handles. */
  subscriptions?: string[];
  /** When false, suppress the global window CustomEvent dispatches
   *  (freesdn:camera-event / camera-status / vpn-event / pbx-sync). The app-wide
   *  socket fires these once; a second page-scoped socket must NOT duplicate
   *  them. Defaults to true. */
  dispatchWindowEvents?: boolean;
}

const DEFAULT_OPTIONS = {
  enabled: true,
  // NOTE: previously capped at 10 attempts, after the cap the socket
  // would never come back, so a 30-second network blip permanently
  // detached the UI from realtime updates until a manual page reload.
  // We set this very high (effectively no cap) and still apply
  // exponential backoff with jitter so we don't pound the server.
  reconnectAttempts: 1000,
  reconnectInterval: 1000,
  heartbeatInterval: 30000,
  batchInterval: 2000,
  onMessage: () => {},
};

export function useWebSocket(options: UseWebSocketOptions = {}) {
  // Get the WebSocket URL dynamically from the API configuration
  const wsUrl = useMemo(() => options.url || getWebSocketUrl(), [options.url]);
  const opts = { ...DEFAULT_OPTIONS, ...options, url: wsUrl };
  const queryClient = useQueryClient();

  // Use ref for status to avoid re-rendering the host component on every
  // connecting ↔ offline cycle during reconnection.  Components that need
  // the connection status should read it from the zustand store.
  const statusRef = useRef<ConnectionStatus>('connecting');
  const onStatusChangeRef = useRef(opts.onStatusChange);
  onStatusChangeRef.current = opts.onStatusChange;

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectCountRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Resets reconnect backoff only after the socket has stayed open past the
  // server's unauthenticated-accept→close window.
  const stableTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const heartbeatTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // Last time ANY inbound frame arrived (pong or event), for half-open
  // socket detection in the heartbeat.
  const lastActivityRef = useRef<number>(Date.now());
  const batchRef = useRef<Set<string>>(new Set());
  const batchTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // NOTE: track active subscriptions + site filters so that after a
  // reconnection we can re-send them. Previously the hook reconnected
  // but the server-side ConnectionManager had no record of the prior
  // subscriptions, so the user's UI stopped receiving events even though
  // the socket showed "online".
  const subscriptionsRef = useRef<Set<string>>(new Set());
  const siteFiltersRef = useRef<string[] | null>(null);

  const updateStatus = useCallback((s: ConnectionStatus) => {
    if (statusRef.current !== s) {
      statusRef.current = s;
      onStatusChangeRef.current?.(s);
    }
  }, []);

  // Process batched messages
  const processBatch = useCallback(() => {
    if (batchRef.current.size === 0) return;

    const messages = Array.from(batchRef.current);
    batchRef.current.clear();

    messages.forEach((msgString) => {
      try {
        const msg: WebSocketMessage = JSON.parse(msgString);
        handleMessage(msg);
      } catch (e) {
        console.error('Failed to parse WebSocket message:', e);
      }
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Handle incoming message
  const handleMessage = useCallback((msg: WebSocketMessage) => {
    opts.onMessage(msg);

    // A secondary, page-scoped socket (dispatchWindowEvents=false) must not
    // re-fire the global window CustomEvents the app-wide socket already fires,
    // else every camera/vpn/pbx event is handled twice (duplicate toasts) while
    // that page is mounted.
    const dispatchWindowEvent = (event: Event): void => {
      if (opts.dispatchWindowEvents !== false) window.dispatchEvent(event);
    };

    // Update React Query cache based on message type
    switch (msg.type) {
      case 'device_discovered':
      case 'device_updated':
      case 'device_status_change':
        // Invalidate devices query to refetch
        queryClient.invalidateQueries({ queryKey: ['devices'] });
        queryClient.invalidateQueries({ queryKey: ['device-stats'] });
        break;

      case 'discovery_complete':
        queryClient.invalidateQueries({ queryKey: ['devices'] });
        queryClient.invalidateQueries({ queryKey: ['device-stats'] });
        queryClient.invalidateQueries({ queryKey: ['controllers'] });
        break;

      case 'controller_online':
      case 'controller_offline':
        queryClient.invalidateQueries({ queryKey: ['controllers'] });
        break;

      case 'pong':
        // Heartbeat response - connection is alive
        break;

      // NOTE: the legacy top-level 'camera_event'/'camera_alert'/
      // 'camera_health_update' cases were removed, the production WS forwarder
      // wraps every bus event as {type:'event'}, so those flat types are never
      // emitted. Camera events are routed in the 'event' case below
      // (camera.alert.*/camera.status.*/camera.*/nvr.*), which invalidates all
      // three count keys + dispatches the toast. Keeping the dead cases risked a
      // stale two-key contract if anyone revived them.

      case 'port_link_up':
      case 'port_link_down':
      case 'port_status_change':
        queryClient.invalidateQueries({ queryKey: ['switch-ports'] });
        queryClient.invalidateQueries({ queryKey: ['devices'] });
        break;

      case 'poe_fault':
      case 'poe_overbudget':
      case 'poe_status_change':
        queryClient.invalidateQueries({ queryKey: ['switch-ports'] });
        break;

      case 'firmware_upgrade_progress':
      case 'firmware_upgrade_complete':
      case 'firmware_upgrade_failed':
        queryClient.invalidateQueries({ queryKey: ['firmware-jobs'] });
        queryClient.invalidateQueries({ queryKey: ['firmware-device-status'] });
        break;

      case 'alert_fired':
      case 'alert_resolved':
        queryClient.invalidateQueries({ queryKey: ['alerts'] });
        queryClient.invalidateQueries({ queryKey: ['alert-rules'] });
        break;

      case 'sla_breach_created':
      case 'sla_breach_resolved':
        queryClient.invalidateQueries({ queryKey: ['sla-breaches'] });
        queryClient.invalidateQueries({ queryKey: ['sla-policies'] });
        break;

      case 'config_change':
      case 'config_version_created':
        queryClient.invalidateQueries({ queryKey: ['config-versions'] });
        break;

      case 'client_connect':
      case 'client_disconnect':
        queryClient.invalidateQueries({ queryKey: ['access-point-clients'] });
        queryClient.invalidateQueries({ queryKey: ['access-points'] });
        break;

      case 'topology_change':
        queryClient.invalidateQueries({ queryKey: ['topology'] });
        break;

      case 'vpn_connection_down':
      case 'vpn_connection_restored':
        queryClient.invalidateQueries({ queryKey: ['vpnConnections'] });
        queryClient.invalidateQueries({ queryKey: ['vpn', 'status'] });
        queryClient.invalidateQueries({ queryKey: ['vpn', 'dashboard'] });
        queryClient.invalidateQueries({ queryKey: ['vpnAggregateMetrics'] });
        dispatchWindowEvent(
          new CustomEvent('freesdn:vpn-event', { detail: { type: msg.type, data: msg.data } }),
        );
        break;

      case 'vpn_health_degraded':
        queryClient.invalidateQueries({ queryKey: ['vpnConnections'] });
        queryClient.invalidateQueries({ queryKey: ['vpn', 'dashboard'] });
        queryClient.invalidateQueries({ queryKey: ['vpnAggregateMetrics'] });
        dispatchWindowEvent(
          new CustomEvent('freesdn:vpn-event', { detail: { type: msg.type, data: msg.data } }),
        );
        break;

      case 'vpn_tunnel_status_changed':
        queryClient.invalidateQueries({ queryKey: ['vpn', 'tunnels'] });
        queryClient.invalidateQueries({ queryKey: ['vpn', 'dashboard'] });
        dispatchWindowEvent(
          new CustomEvent('freesdn:vpn-event', { detail: { type: msg.type, data: msg.data } }),
        );
        break;

      case 'vpn_reconnect_started':
      case 'vpn_reconnect_exhausted':
        queryClient.invalidateQueries({ queryKey: ['vpnReconnectStatus'] });
        queryClient.invalidateQueries({ queryKey: ['vpnConnections'] });
        dispatchWindowEvent(
          new CustomEvent('freesdn:vpn-event', { detail: { type: msg.type, data: msg.data } }),
        );
        break;

      // ── Bus-forwarded events (canonical pattern) ──
      // The backend WebSocket forwarder wraps every event bus message
      // as ``{type: "event", event: {event_type, payload, ...}}``.
      // Unwrap and route by the inner ``event_type``. We added
      // ``pbx.sync.*`` here but this is the right home for
      // any future ``<adapter>.<resource>.<action>`` event family.
      case 'event': {
        const inner = (msg as any).event as
          | { event_type?: string; payload?: Record<string, unknown> }
          | undefined;
        const eventType = inner?.event_type ?? '';
        const data = inner?.payload ?? {};

        if (eventType.startsWith('pbx.sync.')) {
          dispatchWindowEvent(
            new CustomEvent('freesdn:pbx-sync', {
              detail: { type: eventType, data },
            }),
          );
          if (eventType === 'pbx.sync.completed' || eventType === 'pbx.sync.failed') {
            queryClient.invalidateQueries({ queryKey: ['voip-pbx'] });
            queryClient.invalidateQueries({ queryKey: ['voip-extensions'] });
            queryClient.invalidateQueries({ queryKey: ['voip-trunks'] });
            queryClient.invalidateQueries({ queryKey: ['voip-ring-groups'] });
            queryClient.invalidateQueries({ queryKey: ['pbx-dashboard'] });
            queryClient.invalidateQueries({ queryKey: ['pbx-extensions'] });
            queryClient.invalidateQueries({ queryKey: ['pbx-ring-groups'] });
            queryClient.invalidateQueries({ queryKey: ['pbx-trunks'] });
          }
        } else if (eventType.startsWith('camera.alert.')) {
          // NVR smart-detection alert (line-cross/intrusion/tamper/…). The
          // backend ingest task publishes these on the bus; refresh the event
          // lists + unread badge and pop the app-wide toast. The payload
          // already carries {event_type, camera_name, timestamp, camera_id}
          // which CameraEventAlerts/CamerasPage/CameraWall read off the detail.
          queryClient.invalidateQueries({ queryKey: ['camera-events'] });
          queryClient.invalidateQueries({ queryKey: ['camera-event-count'] });
          queryClient.invalidateQueries({ queryKey: ['camera-events-unack-count'] });
          dispatchWindowEvent(
            new CustomEvent('freesdn:camera-event', { detail: data }),
          );
        } else if (eventType.startsWith('camera.status.')) {
          // Camera went online/offline, refresh camera lists so the status
          // badge updates live. Use a DEDICATED event (not freesdn:camera-event)
          // so a benign status change doesn't fire the smart-detection alert
          // toast (whose consumers read data.event_type and would render
          // "unknown") or the wall alert sound.
          queryClient.invalidateQueries({ queryKey: ['cameras'] });
          dispatchWindowEvent(
            new CustomEvent('freesdn:camera-status', {
              detail: {
                ...(data as Record<string, unknown>),
                status: (data as Record<string, unknown>).new_status,
              },
            }),
          );
        } else if (eventType.startsWith('camera.')) {
          // Other camera write events (PTZ, motion-config, …), keep camera
          // lists fresh without a toast.
          queryClient.invalidateQueries({ queryKey: ['cameras'] });
        } else if (eventType.startsWith('nvr.')) {
          // NVR-level events (reboot, status), refresh NVR + camera lists.
          queryClient.invalidateQueries({ queryKey: ['cameras'] });
          queryClient.invalidateQueries({ queryKey: ['devices'] });
        } else {
          // Everything ELSE the bus publishes used to fall off the end of
          // this chain and vanish.
          //
          // The backend publishes ~48 distinct event_type values. Exactly
          // three families were routed: pbx.sync.*, camera.* and nvr.*. So an
          // alert firing, a device being adopted, a staged change being
          // applied, a VLAN or SSID changing, an SLA breach, a VPN peer going
          // down, a fabric distribution finishing -- all of them arrived on a
          // live socket, were unwrapped, matched nothing, and were dropped.
          //
          // The pages built on those events did not know they were stale;
          // they waited on their own refetchInterval instead. Which is why
          // this looked like "the UI is a bit slow to update" rather than a
          // bug: the realtime layer was carrying the news and throwing it
          // away at the last step.
          const invalidate = (...keys: string[]) => {
            for (const key of keys) queryClient.invalidateQueries({ queryKey: [key] });
          };

          if (eventType.startsWith('alert.')) {
            invalidate(
              'alerts',
              'alert-instances',
              'alert-instances-all',
              'dashboard-alerts',
              'alert-rules-stats',
            );
          } else if (eventType.startsWith('notification.')) {
            invalidate('in-app-notifications');
          } else if (eventType.startsWith('device.')) {
            invalidate('devices', 'discovered-hosts');
          } else if (eventType.startsWith('discovery.')) {
            invalidate('discovery', 'discovered-hosts');
          } else if (eventType.startsWith('controller.change.')) {
            // A change staged or applied elsewhere (another operator, another
            // tab, a Fabric run) must move the Pending Changes badge here.
            invalidate('pending-changes', 'controllers');
          } else if (eventType.startsWith('network.vlan.')) {
            invalidate('vlans', 'devices');
          } else if (eventType.startsWith('network.wifi.')) {
            invalidate('wifi-networks');
          } else if (eventType.startsWith('sla.')) {
            invalidate('sla-summary', 'sla-breaches', 'sla-policies');
          } else if (eventType.startsWith('fabric.')) {
            invalidate('fabric-connections', 'fabric-runs');
          } else if (eventType.startsWith('vpn.') || eventType.startsWith('overlay.')) {
            invalidate('vpn', 'vpnConnections', 'site-vpn', 'tailscaleStatus');
          } else if (eventType.startsWith('gateway.')) {
            invalidate('gateways', 'gateway', 'fw-gateways');
          } else if (eventType.startsWith('backup.')) {
            invalidate('backups', 'backup-schedules');
          } else if (eventType.startsWith('omada.event.')) {
            invalidate('controllers');
          } else if (import.meta.env.DEV) {
            // Loud in dev so a NEW event family cannot quietly join the set
            // that gets dropped -- which is exactly how the original three
            // ended up being the only ones handled.
            console.warn('Unrouted bus event family:', eventType);
          }
        }

        // Every bus event also goes out as a generic window event, so a page
        // can subscribe to something specific without this switch having to
        // know about it. Dispatched for routed families too -- routing and
        // observation are different jobs.
        dispatchWindowEvent(
          new CustomEvent('freesdn:bus-event', {
            detail: { type: eventType, data },
          }),
        );
        break;
      }

      case 'connected':
      case 'connection_established':
        // Connection acknowledgment from server - ignore
        break;

      case 'subscribed':
      case 'unsubscribed':
      case 'filters_set':
        // Subscription confirmations - ignore
        break;

      default:
        // Only log truly unknown message types in development
        if (import.meta.env.DEV) {
          console.log('Unknown WebSocket message type:', msg.type);
        }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queryClient, opts.onMessage]);

  // Start heartbeat
  const startHeartbeat = useCallback(() => {
    if (heartbeatTimerRef.current) {
      clearInterval(heartbeatTimerRef.current);
    }

    lastActivityRef.current = Date.now();
    heartbeatTimerRef.current = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        // Half-open detection: the server answers our ping with 'pong' and
        // pushes events, so ANY inbound frame stamps lastActivity. If we've
        // heard NOTHING for >2.5 heartbeats, the socket is silently dead
        // (laptop sleep, NAT/conntrack idle-drop, WAN flap) while readyState
        // still says OPEN, close it so onclose fires and we reconnect, instead
        // of flapping 'online' on a zombie that never delivers.
        if (Date.now() - lastActivityRef.current > opts.heartbeatInterval * 2.5) {
          wsRef.current.close();
          return;
        }
        wsRef.current.send(JSON.stringify({ type: 'ping' }));
      }
    }, opts.heartbeatInterval);
  }, [opts.heartbeatInterval]);

  // Connect to WebSocket
  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    // Check for active session via CSRF cookie (httpOnly access cookie
    // is sent automatically during the WebSocket handshake)
    const hasCsrf = !!getCookie('freesdn_csrf');
    if (!hasCsrf) {
      console.warn('WebSocket: No active session, skipping connection');
      updateStatus('offline');
      return;
    }

    updateStatus('connecting');

    try {
      // httpOnly cookies are sent automatically during the WebSocket
      // HTTP upgrade handshake · no need to send token explicitly.
      const ws = new WebSocket(opts.url);
      wsRef.current = ws;

      ws.onopen = () => {
        updateStatus('online');
        // Do NOT reset backoff here: the server accept()s the socket BEFORE it
        // verifies auth, so a doomed (expired-cookie) connection fires onopen
        // then 1008-closes ~10s later. Resetting now lets that accept→close
        // cycle defeat exponential backoff and hammer the server forever. Reset
        // only once the socket has stayed open past that window.
        if (stableTimerRef.current) clearTimeout(stableTimerRef.current);
        stableTimerRef.current = setTimeout(() => { reconnectCountRef.current = 0; }, 15000);
        startHeartbeat();

        // Start batch processing
        batchTimerRef.current = setInterval(processBatch, opts.batchInterval);

        // Default subscription firehose, ask the server for every
        // event family the UI knows how to render. The backend's
        // ws_rbac filter narrows this to what the current user is
        // actually allowed to see (e.g. ``audit.*`` is dropped for
        // non-auditors). Without this, every connection starts with
        // ``subscriptions=set()`` and ``_should_receive`` rejects
        // every event, the symptom is "WS shows online but nothing
        // ever updates", which is exactly what the PBX-sync case hit.
        // Any new ``<adapter>.*`` family added to ws_rbac should also
        // be added here so detail pages don't each need to subscribe.
        const defaultSubs = opts.subscriptions ?? [
          'device.*', 'controller.*', 'discovery.*',
          'alert.*', 'sla.*',
          'pbx.*', 'camera.*', 'nvr.*', 'vpn.*',
        ];
        for (const sub of defaultSubs) subscriptionsRef.current.add(sub);
        ws.send(JSON.stringify({
          type: 'subscribe',
          subscriptions: Array.from(subscriptionsRef.current),
        }));
        if (siteFiltersRef.current && siteFiltersRef.current.length > 0) {
          ws.send(JSON.stringify({
            type: 'set_filters',
            site_ids: siteFiltersRef.current,
          }));
        }
      };

      ws.onmessage = (event) => {
        lastActivityRef.current = Date.now();  // half-open watchdog
        // Add to batch instead of processing immediately
        batchRef.current.add(event.data);
      };

      ws.onclose = (event) => {
        if (import.meta.env.DEV) {
          console.log('WebSocket closed:', event.code, event.reason);
        }
        updateStatus('offline');
        cleanup();

        // Attempt reconnection with exponential backoff
        if (reconnectCountRef.current < opts.reconnectAttempts) {
          const delay = Math.min(
            opts.reconnectInterval * Math.pow(2, reconnectCountRef.current),
            30000 // Max 30 seconds
          );
          const jitter = Math.random() * 3000; // Random jitter 0-3s
          // 1008 (policy violation) = the access cookie was missing/expired at
          // the handshake (e.g. a tab open past the 30-min token TTL). Re-mint it
          // via /auth/refresh BEFORE reconnecting, otherwise we loop
          // accept→1008→reconnect forever and realtime stays dead app-wide. If
          // refresh fails (refresh token also gone), stop and go offline rather
          // than hammer the server.
          const wasAuthClose = event.code === 1008;
          reconnectTimerRef.current = setTimeout(async () => {
            reconnectCountRef.current++;
            if (wasAuthClose) {
              try {
                const ok = await useAuthStore.getState().refreshSession();
                if (!ok) { updateStatus('offline'); return; }
              } catch {
                updateStatus('offline');
                return;
              }
            }
            connect();
          }, delay + jitter);
        }
      };

      ws.onerror = () => {
        // Suppress noisy error log · onclose always fires after onerror
        // and handles the reconnection logic.
      };
    } catch (error) {
      console.error('Failed to connect WebSocket:', error);
      updateStatus('offline');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [opts.url, opts.reconnectAttempts, opts.reconnectInterval, opts.batchInterval, startHeartbeat, processBatch, updateStatus]);

  // Cleanup function
  const cleanup = useCallback(() => {
    if (stableTimerRef.current) {
      clearTimeout(stableTimerRef.current);
      stableTimerRef.current = null;
    }
    if (heartbeatTimerRef.current) {
      clearInterval(heartbeatTimerRef.current);
      heartbeatTimerRef.current = null;
    }
    if (batchTimerRef.current) {
      clearInterval(batchTimerRef.current);
      batchTimerRef.current = null;
    }
  }, []);

  // Disconnect
  const disconnect = useCallback(() => {
    cleanup();
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  }, [cleanup]);

  // Send message
  //
  // NOTE: tracks subscribe / unsubscribe / set_filters payloads so the
  // hook can replay them after a reconnection (see ``ws.onopen``). The
  // tracking happens even if the socket isn't currently open, that way
  // a caller who subscribes during the offline window will get their
  // subscription installed as soon as the socket comes back.
  const send = useCallback((message: Record<string, unknown>) => {
    const type = message.type as string | undefined;
    if (type === 'subscribe' && Array.isArray(message.subscriptions)) {
      for (const sub of message.subscriptions as unknown[]) {
        if (typeof sub === 'string') subscriptionsRef.current.add(sub);
      }
    } else if (type === 'unsubscribe' && Array.isArray(message.subscriptions)) {
      for (const sub of message.subscriptions as unknown[]) {
        if (typeof sub === 'string') subscriptionsRef.current.delete(sub);
      }
    } else if (type === 'set_filters') {
      const siteIds = message.site_ids;
      siteFiltersRef.current = Array.isArray(siteIds) ? (siteIds as string[]) : null;
    }
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    }
  }, []);

  // Connect on mount (if enabled), cleanup on unmount
  useEffect(() => {
    if (isDemoMode) {
      updateStatus(opts.enabled ? 'online' : 'offline');
      return () => {
        disconnect();
      };
    }

    if (opts.enabled) {
      connect();
    } else {
      // When not enabled, set status to offline and disconnect
      updateStatus('offline');
      disconnect();
    }

    return () => {
      disconnect();
    };
  }, [opts.enabled, connect, disconnect, updateStatus]);

  return {
    connect,
    disconnect,
    send,
  };
}
