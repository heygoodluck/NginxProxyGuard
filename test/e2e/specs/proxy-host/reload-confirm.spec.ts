import { test, expect } from '@playwright/test';
import { spawnSync } from 'child_process';
import * as net from 'net';
import { APIHelper } from '../../utils/api-helper';

/**
 * A reload nginx refuses is reported (409 nginx_reload_rejected) instead of
 * passing as applied, and a host's rate limit zone no longer makes nginx
 * refuse reloads when its exception list goes from empty to non-empty and
 * back.
 */
test.describe.configure({ mode: 'serial' });

const API = 'http://127.0.0.1:19080';
const PROXY_CONTAINER = process.env.NPG_TEST_PROXY_CONTAINER || 'npg-test-proxy';
// Hosts this file creates. The sweep in afterAll deletes only these: the
// other spec file using the r1- prefix may be running in parallel.
const OWN_HOST_PREFIXES = ['r1-stream-', 'r1-rl-'];

/**
 * The nginx container's log since `since`. nginx writes its error log, where
 * [emerg] lines are, to stderr and the access log to stdout, and docker logs
 * keeps the two apart, so both are read.
 */
function nginxLogSince(since: string): string {
  const out = spawnSync('docker', ['logs', '--since', since, PROXY_CONTAINER], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (out.error) throw out.error;
  if (out.status !== 0) throw new Error(`docker logs ${PROXY_CONTAINER} failed: ${out.stderr}`);
  return `${out.stdout}\n${out.stderr}`;
}

/**
 * Listen on port from this process. nginx shares the host network, so this
 * socket makes its bind() of the port fail. Connections are closed at once:
 * the socket only holds the port.
 */
function holdPort(port: number): Promise<net.Server> {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => socket.destroy());
    server.once('error', (err) => reject(new Error(`port ${port} must be free before the test: ${err.message}`)));
    server.listen(port, '0.0.0.0', () => resolve(server));
  });
}

async function eventually(fn: () => Promise<boolean> | boolean, what: string, ms = 15000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`never: ${what}`);
}

test.describe('Reload confirmation (v2.62.0)', () => {
  let api: APIHelper;
  let headers: Record<string, string>;
  // The port the stream test holds. Closed in its finally, and here too: a
  // test that times out is abandoned without running its finally.
  let blocker: net.Server | undefined;
  const releasePort = () => {
    if (blocker?.listening) blocker.close();
    blocker = undefined;
  };

  test.beforeEach(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
    headers = { Authorization: `Bearer ${await api.getToken()}` };
  });

  test.afterEach(() => releasePort());

  test.afterAll(async ({ playwright }) => {
    // Hosts a failed or refused save kept, such as one whose create threw
    // before the test could note its id.
    const ctx = await playwright.request.newContext({ baseURL: API });
    try {
      const helper = new APIHelper(ctx);
      await helper.login();
      for (const h of await helper.getProxyHosts()) {
        if (OWN_HOST_PREFIXES.some((p) => h.domain_names?.[0]?.startsWith(p))) {
          await helper.deleteProxyHost(h.id).catch(() => undefined);
        }
      }
    } finally {
      await ctx.dispose();
    }
  });

  test('a stream host on a port in use is refused by nginx and reported as 409', async ({ request }) => {
    // While this host's file is on disk nginx refuses every reload, so a test
    // running in parallel would see 409s. Run it alone: E2E_RELOAD_REJECT=1
    // npx playwright test specs/proxy-host/reload-confirm.spec.ts --workers=1
    test.skip(
      !(process.env.E2E_RELOAD_REJECT === '1' && test.info().config.workers === 1),
      'refuses every reload while it runs; run alone with E2E_RELOAD_REJECT=1 and --workers=1'
    );
    const port = 18998;
    blocker = await holdPort(port);
    const since = new Date().toISOString();
    const deleted: number[] = [];
    try {
      const res = await request.post(`${API}/api/v1/proxy-hosts`, {
        headers,
        data: {
          domain_names: [`r1-stream-${Date.now()}`],
          forward_host: '127.0.0.1',
          forward_port: 19080,
          forward_scheme: 'tcp',
          proxy_type: 'stream',
          stream_listen_port: port,
          stream_protocol: 'tcp',
          enabled: true,
        },
      });
      expect(res.status()).toBe(409);
      const body = await res.json();
      expect(body.code).toBe('nginx_reload_rejected');
      expect(body.details).toContain('bind()');
      const kept = (await api.getProxyHosts()).filter((h) => h.stream_listen_port === port);
      expect(kept, 'a refused reload keeps the saved host').toHaveLength(1);
    } finally {
      try {
        // nginx retries the port for a few seconds and logs each try. Delete
        // only after it has given up, so the delete's own reload is not judged
        // by those lines.
        await eventually(() => /still could not bind\(\)/.test(nginxLogSince(since)), 'nginx gives up on the port').catch(
          () => undefined
        );
        for (const h of (await api.getProxyHosts()).filter((h) => h.stream_listen_port === port)) {
          // The file goes with the host, so nginx loads the next config again.
          deleted.push((await request.delete(`${API}/api/v1/proxy-hosts/${h.id}`, { headers })).status());
        }
      } finally {
        releasePort();
      }
    }
    expect(deleted, 'deleting the refused host reloads nginx cleanly').toEqual([204]);
    expect((await api.getProxyHosts()).filter((h) => h.stream_listen_port === port)).toHaveLength(0);
  });

  test('adding the first rate limit exception is applied without a restart', async ({ request }) => {
    const since = new Date().toISOString();
    const host = await api.createProxyHost({
      domain_names: [`r1-rl-${Date.now()}.example.com`],
      forward_scheme: 'http',
      forward_host: '127.0.0.1',
      forward_port: 19080,
      enabled: true,
    });
    try {
      // A rate limit save reloads nginx before it answers: a refused reload is a 409.
      for (const whitelist of ['', '203.0.113.5', '']) {
        const res = await request.put(`${API}/api/v1/proxy-hosts/${host.id}/rate-limit`, {
          headers,
          data: {
            enabled: true,
            requests_per_second: 10,
            burst_size: 20,
            zone_size: '10m',
            limit_by: 'ip',
            limit_response: 429,
            whitelist_ips: whitelist,
          },
        });
        expect(res.status(), `save with exceptions "${whitelist}": ${await res.text()}`).toBe(200);
      }
      expect(nginxLogSince(since)).not.toMatch(/\[emerg\][^\n]*key while previously/);
    } finally {
      await api.deleteProxyHost(host.id).catch(() => undefined);
    }
  });
});
