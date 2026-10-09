// SPDX-License-Identifier: AGPL-3.0-only
/** Validate the API document and initiate a file download without caching secrets. */
const MAX_BYTES = 16 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function saveGatewayConfiguration(value: unknown, gatewayId: string): void {
  const invalid = () => new Error('Configuration download is unavailable');
  if (!UUID.test(gatewayId) || !record(value)
    || typeof value.gateway_id !== 'string'
    || value.gateway_id.toLowerCase() !== gatewayId.toLowerCase()
    || !record(value.config)) throw invalid();

  const config = value.config;
  let blob: Blob;
  let extension: string;
  if ('config_xml' in config && !('backup_data' in config)) {
    const content = config.config_xml;
    if (typeof content !== 'string' || !content.trim() || content.length > MAX_BYTES) throw invalid();
    const bytes = new TextEncoder().encode(content);
    if (bytes.length > MAX_BYTES || new TextDecoder('utf-8', { ignoreBOM: true }).decode(bytes) !== content) throw invalid();
    blob = new Blob([bytes], { type: 'application/xml' });
    extension = 'xml';
  } else if ('backup_data' in config && !('config_xml' in config)) {
    const encoded = config.backup_data;
    if (config.encoding !== 'base64' || config.format !== 'tar.gz' || (config.scope !== '/etc/config/' && config.scope !== 'sysupgrade')
      || typeof encoded !== 'string' || !encoded || encoded.length > Math.ceil(MAX_BYTES / 3) * 4
      || encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) throw invalid();
    const raw = atob(encoded);
    if (!raw.length || raw.length > MAX_BYTES || btoa(raw) !== encoded) throw invalid();
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    blob = new Blob([bytes], { type: 'application/gzip' });
    extension = 'tar.gz';
  } else {
    throw invalid();
  }

  const url = URL.createObjectURL(blob);
  const revoke = URL.revokeObjectURL.bind(URL);
  const link = document.createElement('a');
  let started = false;
  try {
    link.href = url;
    link.download = `freesdn-gateway-${gatewayId.toLowerCase()}-config.${extension}`;
    link.hidden = true;
    link.rel = 'noopener';
    document.body.append(link);
    link.click();
    started = true;
  } finally {
    link.remove();
    // Give the browser time to acquire the blob; do not retain an export URL.
    if (started) setTimeout(() => revoke(url), 1000);
    else revoke(url);
  }
}
