// Real-browser regression: Node 24+, Go, Chromium, and the existing esbuild dependency.
// Run from cloud: node test/unlock-ui.mjs (CHROMIUM may override the executable).
// All account data is synthetic; the HTTP fixture only listens on loopback.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { build } from 'esbuild';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const cloud = join(root, 'cloud');
const scratch = await mkdtemp(join(tmpdir(), 'sshm-unlock-ui-'));
const phrase = 'synthetic-browser-unlock-phrase';
let browser, socket, server, closing = false;
const browserErrors = [], unexpectedRequests = [], requestBodies = [];

async function run(command, args, options = {}) {
  const child = spawn(command, args, { cwd: root, ...options, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', b => output += b);
  child.stderr.on('data', b => output += b);
  const [code] = await once(child, 'exit');
  assert.equal(code, 0, `${command} failed:\n${output}`);
}

async function bundle(path, platform, format) {
  const result = await build({ entryPoints: [join(cloud, path)], bundle: true, write: false, platform, format });
  return result.outputFiles[0].text;
}

async function connectBrowser() {
  browser = spawn(process.env.CHROMIUM || '/usr/bin/chromium', [
    '--headless', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
    '--disable-background-networking', '--no-first-run', '--no-default-browser-check',
    '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
    `--user-data-dir=${join(scratch, 'profile')}`, 'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  const endpoint = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(Error(`Chromium startup timed out: ${stderr}`)), 20000);
    browser.once('error', reject);
    browser.once('exit', code => { clearTimeout(timeout); reject(Error(`Chromium exited ${code}: ${stderr}`)); });
    browser.stderr.on('data', chunk => {
      stderr += chunk;
      const match = stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (match) { clearTimeout(timeout); resolve(match[1]); }
    });
  });
  const targets = await (await fetch(`http://${new URL(endpoint).host}/json/list`)).json();
  socket = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl);
  await once(socket, 'open');
  let next = 0;
  const pending = new Map();
  socket.addEventListener('close', () => {
    for (const call of pending.values()) { clearTimeout(call.timeout); call.reject(Error('CDP connection closed')); }
    pending.clear();
  });
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.method === 'Runtime.exceptionThrown') browserErrors.push(message.params.exceptionDetails);
    const call = pending.get(message.id);
    if (!call) return;
    pending.delete(message.id);
    clearTimeout(call.timeout);
    if (message.error) call.reject(Error(JSON.stringify(message.error)));
    else call.resolve(message.result);
  });
  return (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++next;
    const timeout = setTimeout(() => { pending.delete(id); reject(Error(`CDP timeout: ${method}`)); }, 45000);
    pending.set(id, { resolve, reject, timeout });
    socket.send(JSON.stringify({ id, method, params }));
  });
}

try {
  const fixture = join(scratch, 'vault.json');
  await run('go', ['test', './internal/cloudsync', '-run', '^TestWriteBrowserFixture$', '-count=1'], {
    env: { ...process.env, SSHM_CLOUD_BROWSER_FIXTURE: fixture },
  });
  const snapshot = JSON.parse(await readFile(fixture, 'utf8'));
  const [pageModule, accountScript] = await Promise.all([
    bundle('src/page.ts', 'node', 'esm'), bundle('src/browser/account.js', 'browser', 'iife'),
  ]);
  const { page } = await import(`data:text/javascript;base64,${Buffer.from(pageModule).toString('base64')}`);
  const accountPath = page.match(/<script src="([^"]+)" defer><\/script>/)?.[1];
  assert.ok(accountPath, 'production page must reference its browser script');
  const now = Date.now();
  const client = { id: 'synthetic_device', kind: 'cli', label: 'Synthetic client', platform: 'linux',
    group: '', tags: [], version: '0.7.1', installed_version: '0.7.1', created: now, last_seen: now, job_seen: now };
  const clients = [client,
    { ...client, id: 'unsupported_device', label: 'No SSH capability', version: '0.9.0' },
    { ...client, id: 'offline_device', label: 'Offline device', last_seen: now - 120000 },
  ];
  const job = { id: 'synthetic_job', device: client.id, action: 'sync', status: 'succeeded',
    code: 'synced', count: 1, created: now, receipt: Buffer.alloc(64).toString('base64url') };
  let signedIn = true;
  server = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    if (body) requestBodies.push(body);
    const path = new URL(req.url, 'http://localhost').pathname;
    const send = (data, type = 'application/json', status = 200) => {
      res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' });
      res.end(type === 'application/json' ? JSON.stringify(data) : data);
    };
    if (['/', '/servers', '/devices', '/settings'].includes(path)) return send(page, 'text/html');
    if (path === accountPath) return send(accountScript, 'text/javascript');
    if (path === '/favicon.ico') return send('', 'image/x-icon');
    if (path === '/downloads/release.json') return send({ error: 'synthetic fixture has no signed release' }, 'application/json', 404);
    if (path === '/v1/web/logout' && req.method === 'POST') { signedIn = false; return send({ ok: true }); }
    if (path.startsWith('/v1/') && !signedIn) {
      unexpectedRequests.push(`${req.method} ${path} after logout`);
      return send({ error: 'signed out' }, 'application/json', 401);
    }
    if (path === '/v1/web/me') return send({ username: 'browser-interop', device: { id: 'synthetic_browser' } });
    if (path === '/v1/devices') return send({ devices: clients });
    if (path === '/v1/agents') return send({ agents: [
      { device_id: client.id, runtime_version: '0.7.1', ssh_targets: true },
      { device_id: 'unsupported_device', runtime_version: '0.9.0', ssh_targets: false },
      { device_id: 'offline_device', runtime_version: '0.7.1', ssh_targets: true },
    ] });
    if (path === '/v1/links') return send({ requests: [] });
    if (path === '/v1/jobs') return send({ jobs: [job] });
    if (path === '/v1/vault' && req.method === 'GET') return send(snapshot);
    if (path === '/v1/heartbeat' && req.method === 'POST') return send({ ok: true });
    unexpectedRequests.push(`${req.method} ${path}`);
    send({ error: 'unexpected fixture request' }, 'application/json', 404);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;
  const cdp = await connectBrowser();
  await cdp('Runtime.enable');
  await cdp('Page.enable');
  // Restrict page traffic to the fixture, including accidental production fetches.
  await cdp('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  socket.addEventListener('message', async event => {
    const message = JSON.parse(event.data);
    if (message.method !== 'Fetch.requestPaused') return;
    const { requestId, request } = message.params;
    try {
      if (request.url.startsWith(origin + '/')) await cdp('Fetch.continueRequest', { requestId });
      else {
        unexpectedRequests.push(request.url);
        await cdp('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' });
      }
    } catch (error) {
      // Navigation may cancel an old document's intercepted request first.
      if (!closing && !error.message.includes('Invalid InterceptionId')) browserErrors.push(error.message);
    }
  });
  const evaluate = async expression => {
    const result = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result.value;
  };
  const waitFor = async (expression, description, timeout = 30000) => {
    const until = Date.now() + timeout;
    while (Date.now() < until) {
      if (await evaluate(expression)) return;
      await delay(50);
    }
    throw Error(`Timed out: ${description}; browser errors: ${JSON.stringify(browserErrors)}`);
  };
  const visible = selector => evaluate(`Boolean(document.querySelector(${JSON.stringify(selector)})?.checkVisibility())`);
  const click = async selector => {
    assert.ok(await visible(selector), `${selector} must be visible to the user`);
    const point = await evaluate(`(() => {
      const element = document.querySelector(${JSON.stringify(selector)});
      if (element.disabled) throw Error('Button is disabled');
      element.scrollIntoView({block: 'center'});
      const r = element.getBoundingClientRect(), x = r.x + r.width / 2, y = r.y + r.height / 2;
      if (!element.contains(document.elementFromPoint(x, y))) throw Error('Button is obscured or inert');
      return {x, y};
    })()`);
    await cdp('Input.dispatchMouseEvent', { type: 'mousePressed', ...point, button: 'left', clickCount: 1 });
    await cdp('Input.dispatchMouseEvent', { type: 'mouseReleased', ...point, button: 'left', clickCount: 1 });
  };
  const fill = async (selector, value) => {
    await evaluate(`document.querySelector(${JSON.stringify(selector)}).focus()`);
    await cdp('Input.insertText', { text: value });
  };
  const openPrompt = async (selector, path) => {
    await click(selector);
    await waitFor(`document.querySelector('#action-unlock-dialog').open`, 'inline unlock dialog opens');
    assert.equal(await evaluate('location.pathname'), path, 'unlock must preserve the current route');
  };
  const unlock = async () => {
    await fill('#action-unlock-form [name=phrase]', phrase);
    await click('#action-unlock-form button.primary');
    await waitFor(`!document.querySelector('#action-unlock-dialog').open`, 'correct phrase unlocks');
    await waitFor(`!document.querySelector('#action-unlock-form button.primary').disabled`, 'unlock continuation completes');
  };
  const navigate = async path => {
    await cdp('Page.navigate', { url: origin + path });
    await waitFor(`document.querySelector('#account-chip')?.checkVisibility() && document.querySelector('#job-rows')?.children.length === 1`, 'signed-in fixture loads');
  };
  const checkTerminalCapability = async () => {
    await click('#server-rows .row-menu-button');
    await evaluate(`([...document.querySelectorAll('.row-menu button')].find(b => b.textContent === '连接终端')).id = 'fixture-terminal'`);
    await click('#fixture-terminal');
    await waitFor(`document.querySelector('#server-terminal-dialog').open`, 'server terminal chooser opens');
    assert.equal(await evaluate(`document.querySelector('#server-terminal-form button.primary').disabled`), false,
      'stable 0.7.1 agent declaring ssh_targets must enable server terminal');
    assert.deepEqual(await evaluate(`[...document.querySelector('#server-terminal-form').elements.device.options].map(o => o.value)`),
      ['synthetic_device'], 'only online devices whose agents declare SSH targets are selectable');
    await click('#server-terminal-dialog [data-close]');
    console.log('PASS: terminal eligibility uses agent capabilities, including stable 0.7.1');
  };

  await navigate('/servers');
  assert.ok(await visible('#add-server'), 'Locked server page must show the Add Server button');
  await openPrompt('#add-server', '/servers');
  await click('#action-unlock-form [data-close]');
  assert.equal(await evaluate(`document.querySelector('#server-dialog').open`), false, 'cancel must not resume Add Server');
  await openPrompt('#add-server', '/servers');
  await fill('#action-unlock-form [name=phrase]', 'definitely-wrong-synthetic-phrase');
  await click('#action-unlock-form button.primary');
  await waitFor(`!document.querySelector('#action-unlock-form button.primary').disabled`, 'wrong phrase finishes');
  assert.equal(await evaluate(`document.querySelector('#action-unlock-dialog').open`), true, 'wrong phrase keeps prompt open');
  assert.match(await evaluate(`document.querySelector('#action-unlock-error').textContent`), /无法解锁/);
  assert.equal(await evaluate(`document.querySelector('#server-dialog').open`), false);
  assert.equal(await evaluate(`document.querySelector('#action-unlock-form [name=phrase]').value`), '', 'phrase is cleared after failure');
  await unlock();
  await waitFor(`document.querySelector('#server-dialog').open`, 'Add Server resumes after unlock');
  assert.equal(await evaluate('location.pathname'), '/servers');
  await click('#server-dialog [data-close]');
  await delay(150);
  assert.equal(await evaluate(`document.querySelector('#server-dialog').open`), false, 'continuation must not reopen the editor');
  assert.match(await evaluate(`document.querySelector('#server-rows').textContent`), /synthetic-host/, 'real Go fixture is decrypted');
  await click('#vault-lock');
  assert.ok(await visible('#add-server'), 'relocking preserves Add Server access');
  await openPrompt('#unlock-vault', '/servers');
  await unlock();
  assert.ok(await visible('#vault-content'), 'main unlock button opens the same working modal');
  assert.equal(await evaluate(`document.querySelector('#server-dialog').open`), false, 'cancelled Add Server does not leak into later unlock');
  console.log('PASS: Add Server, cancellation, wrong phrase, retry, relock, and main unlock');
  await checkTerminalCapability();

  await navigate('/devices');
  await click('#add-device');
  await openPrompt('#unlock-install', '/devices');
  assert.equal(await evaluate(`document.querySelector('#add-dialog').open`), true, 'installation dialog stays open behind unlock');
  await click('#action-unlock-form [data-close]');
  assert.equal(await evaluate(`document.querySelector('#add-dialog').open`), true, 'cancel returns to installation');
  await openPrompt('#unlock-install', '/devices');
  await unlock();
  assert.equal(await evaluate(`document.querySelector('#add-dialog').open`), true);
  assert.match(await evaluate(`document.querySelector('#install-login').textContent`), /cloud link --username browser-interop --root-public \S+ --import-local/);
  await click('#add-dialog [data-close]');
  console.log('PASS: install command unlock keeps installation context');

  await navigate('/devices');
  await click('#job-history summary');
  const receiptButton = await evaluate(`(() => {
    const buttons = [...document.querySelectorAll('#job-rows button')];
    return buttons.findIndex(b => b.textContent === '解锁并验证');
  })()`);
  assert.notEqual(receiptButton, -1, 'locked job receipt must offer an actionable verification button');
  await evaluate(`document.querySelectorAll('#job-rows button')[${receiptButton}].id = 'fixture-receipt-unlock'`);
  await openPrompt('#fixture-receipt-unlock', '/devices');
  await unlock();
  await waitFor(`document.querySelector('#job-rows').textContent.includes('回执签名无效')`, 'receipt verification refreshes after unlock');
  console.log('PASS: receipt unlock verifies the signature in place');

  await navigate('/devices');
  await openPrompt('#dispatch-jobs', '/devices');
  await unlock();
  await waitFor(`document.querySelector('#job-dialog').open`, 'existing device dispatch resumes');
  assert.equal(await evaluate('location.pathname'), '/devices');
  assert.equal(await evaluate(`document.querySelectorAll('#job-targets input').length`), 3);
  console.log('PASS: existing device task dispatch still resumes after unlock');

  await navigate('/servers');
  await cdp('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: false });
  await openPrompt('#unlock-vault', '/servers');
  assert.ok(await visible('#action-unlock-form [name=phrase]'), 'unlock phrase field remains visible on narrow screens');
  assert.equal(await evaluate(`(() => {
    const dialog = document.querySelector('#action-unlock-dialog'), bounds = dialog.getBoundingClientRect();
    return bounds.left >= 0 && bounds.right <= innerWidth && dialog.scrollWidth <= dialog.clientWidth;
  })()`), true, 'unlock dialog fits a 390px viewport without horizontal overflow');
  await click('#action-unlock-form [data-close]');
  await cdp('Emulation.clearDeviceMetricsOverride');
  await click('#top-logout');
  await waitFor(`document.querySelector('#top-login').checkVisibility() && !document.querySelector('#account-chip').checkVisibility()`, 'logout returns to signed-out UI');
  await delay(100);
  assert.equal(await visible('#flash'), false, 'logout must not flash an expired-session error');
  console.log('PASS: narrow-screen unlock and clean logout');
  assert.deepEqual(browserErrors, [], 'no uncaught browser exceptions');
  assert.deepEqual(unexpectedRequests, [], 'all requests stay within the synthetic fixture');
  assert.ok(requestBodies.every(body => !body.includes(phrase)), 'unlock phrase never appears in HTTP request bodies');
} finally {
  closing = true;
  socket?.close();
  if (browser && browser.exitCode === null) {
    browser.kill('SIGTERM');
    await Promise.race([once(browser, 'exit'), delay(3000)]);
    if (browser.exitCode === null) browser.kill('SIGKILL');
  }
  if (server?.listening) {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
  await rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
