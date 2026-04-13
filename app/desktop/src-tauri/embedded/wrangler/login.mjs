/**
 * TapChat Cloudflare OAuth Login
 *
 * Minimal OAuth implementation for Cloudflare authorization.
 * This replaces the need for full wrangler installation.
 *
 * Usage: node login.mjs
 * Output: JSON with accessToken, refreshToken, accountId, accountName
 */

import http from 'http';
import { spawn } from 'child_process';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

// Cloudflare OAuth configuration (wrangler's official client_id)
const CLIENT_ID = '54d11594-84e4-41f6-923c-5e63c7af5a3d';
const REDIRECT_PORT = 8976;
const REDIRECT_PATH = '/oauth/callback';
const TOKEN_URL = 'https://dash.cloudflare.com/oauth2/token';
const AUTH_URL = 'https://dash.cloudflare.com/oauth2/authorize';

// Required scopes for Workers deployment
const SCOPES = [
  'account:read',
  'account:write',
  'workers:write',
  'workers:tail',
  'workers:r2:read',
  'workers:r2:write',
  'user:read',
].join(' ');

/**
 * Open browser URL cross-platform
 */
function openBrowser(url) {
  const platform = process.platform;

  if (platform === 'win32') {
    // Windows: use start command
    spawn('cmd', ['/c', 'start', '', url.replace(/&/g, '^&')], { detached: true });
  } else if (platform === 'darwin') {
    // macOS: use open command
    spawn('open', [url], { detached: true });
  } else if (platform === 'linux') {
    // Linux: try multiple browser commands
    const browsers = ['xdg-open', 'google-chrome', 'firefox', 'chromium'];
    for (const browser of browsers) {
      try {
        spawn(browser, [url], { detached: true });
        break;
      } catch {
        continue;
      }
    }
  }
}

/**
 * Wait for OAuth callback on local server
 */
async function waitForCallback(server) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      server.close();
      reject(new Error('OAuth timeout: no response within 120 seconds'));
    }, 120000);

    server.on('request', (req, res) => {
      if (!req.url.startsWith(REDIRECT_PATH)) {
        res.writeHead(404);
        res.end('Not found');
        return;
      }

      const url = new URL(req.url, `http://localhost:${REDIRECT_PORT}`);
      const code = url.searchParams.get('code');
      const error = url.searchParams.get('error');

      if (error) {
        res.writeHead(400);
        res.end(`<html><body><h1>Authorization Failed</h1><p>${error}</p><script>window.close();</script></body></html>`);
        server.close();
        clearTimeout(timeout);
        reject(new Error(`OAuth error: ${error}`));
        return;
      }

      if (!code) {
        res.writeHead(400);
        res.end('<html><body><h1>Missing authorization code</h1><script>window.close();</script></body></html>');
        server.close();
        clearTimeout(timeout);
        reject(new Error('Missing authorization code'));
        return;
      }

      // Success response
      res.writeHead(200);
      res.end(`
        <html>
          <head><title>TapChat Authorization Success</title></head>
          <body style="font-family: system-ui; text-align: center; padding: 40px;">
            <h1 style="color: #10b981;">✓ Authorization Successful</h1>
            <p>You can close this window and return to TapChat.</p>
            <script>setTimeout(() => window.close(), 1000);</script>
          </body>
        </html>
      `);
      server.close();
      clearTimeout(timeout);
      resolve(code);
    });

    server.on('error', (err) => {
      clearTimeout(timeout);
      reject(new Error(`Server error: ${err.message}`));
    });
  });
}

/**
 * Exchange authorization code for tokens
 */
async function exchangeCodeForToken(code) {
  const redirectUri = `http://localhost:${REDIRECT_PORT}${REDIRECT_PATH}`;

  const response = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      redirect_uri: redirectUri,
    }).toString(),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Token exchange failed (${response.status}): ${text}`);
  }

  return response.json();
}

/**
 * Get account information using access token
 */
async function getAccountInfo(accessToken) {
  const response = await fetch('https://api.cloudflare.com/client/v4/user/accounts', {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to get accounts (${response.status})`);
  }

  const data = await response.json();

  if (!data.success || !data.result || data.result.length === 0) {
    throw new Error('No Cloudflare accounts found');
  }

  // Use first account (or could prompt user to select)
  const account = data.result[0];
  return {
    accountId: account.id,
    accountName: account.name,
  };
}

/**
 * Save tokens to wrangler config location for compatibility
 */
function saveTokens(accessToken, refreshToken, accountId) {
  const configDir = join(homedir(), '.wrangler', 'config');
  const configFile = join(configDir, 'default.toml');

  if (!existsSync(configDir)) {
    mkdirSync(configDir, { recursive: true });
  }

  const tomlContent = `
# TapChat OAuth tokens
oauth_token = "${accessToken}"
refresh_token = "${refreshToken}"
account_id = "${accountId}"
`.trim();

  writeFileSync(configFile, tomlContent, 'utf8');

  return configFile;
}

/**
 * Main login flow
 */
async function login() {
  const redirectUri = `http://localhost:${REDIRECT_PORT}${REDIRECT_PATH}`;

  // Build authorization URL
  const authUrl = new URL(AUTH_URL);
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', SCOPES);
  authUrl.searchParams.set('state', Date.now().toString());

  console.log(JSON.stringify({
    status: 'starting',
    message: 'Starting OAuth login flow',
    authUrl: authUrl.toString(),
  }));

  // Create local server for callback
  const server = http.createServer();
  server.listen(REDIRECT_PORT, '127.0.0.1');

  console.log(JSON.stringify({
    status: 'browser',
    message: `Opening browser for authorization`,
    redirectUri,
  }));

  // Open browser
  openBrowser(authUrl.toString());

  // Wait for callback
  const code = await waitForCallback(server);

  console.log(JSON.stringify({
    status: 'token',
    message: 'Exchanging authorization code for tokens',
  }));

  // Exchange code for tokens
  const tokens = await exchangeCodeForToken(code);

  console.log(JSON.stringify({
    status: 'account',
    message: 'Retrieving account information',
  }));

  // Get account info
  const accountInfo = await getAccountInfo(tokens.access_token);

  // Save tokens
  const configFile = saveTokens(tokens.access_token, tokens.refresh_token, accountInfo.accountId);

  // Output final result
  const result = {
    success: true,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    expiresIn: tokens.expires_in,
    accountId: accountInfo.accountId,
    accountName: accountInfo.accountName,
    configFile,
  };

  console.log(JSON.stringify(result));
  return result;
}

// Run login if executed directly
login().catch((error) => {
  console.log(JSON.stringify({
    success: false,
    error: error.message,
  }));
  process.exit(1);
});