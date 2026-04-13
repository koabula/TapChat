/**
 * TapChat Cloudflare OAuth Login
 *
 * Minimal OAuth implementation for Cloudflare authorization.
 * Uses PKCE (Proof Key for Code Exchange) as required by wrangler 4.x.
 *
 * Usage: node login.mjs
 * Output: JSON with accessToken, refreshToken, accountId, accountName
 */

import http from 'http';
import crypto from 'crypto';
import { spawn } from 'child_process';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

// Cloudflare OAuth configuration (wrangler's official client_id - updated 2025)
const CLIENT_ID = '54d11594-84e4-41aa-b438-e81b8fa78ee7';
const REDIRECT_PORT = 8976;
const REDIRECT_PATH = '/oauth/callback';
const TOKEN_URL = 'https://dash.cloudflare.com/oauth2/token';
const AUTH_URL = 'https://dash.cloudflare.com/oauth2/authorize';

// Required scopes for Workers deployment (updated to match wrangler 4.x)
const SCOPES = [
  'account:read',
  'user:read',
  'workers:write',
  'workers_kv:write',
  'workers_scripts:write',
  'workers_tail:read',
  'd1:write',
  'offline_access',
].join(' ');

/**
 * Generate a random code_verifier for PKCE
 * Must be 43-128 characters, using unreserved characters: A-Z, a-z, 0-9, -, ., _, ~
 */
function generateCodeVerifier() {
  // Generate 32 random bytes (256 bits) and base64url encode
  const randomBytes = crypto.randomBytes(32);
  return base64urlEncode(randomBytes);
}

/**
 * Compute code_challenge from code_verifier using SHA256
 */
function generateCodeChallenge(codeVerifier) {
  const hash = crypto.createHash('sha256').update(codeVerifier).digest();
  return base64urlEncode(hash);
}

/**
 * Base64url encoding (no padding, URL-safe characters)
 */
function base64urlEncode(buffer) {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

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
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`
        <html>
          <head><title>TapChat Authorization Success</title></head>
          <body style="font-family: system-ui; text-align: center; padding: 40px;">
            <h1 style="color: #10b981;">Authorization Successful</h1>
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
 * Exchange authorization code for tokens (with PKCE)
 */
async function exchangeCodeForToken(code, codeVerifier) {
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
      code_verifier: codeVerifier,
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
  // Correct endpoint: /accounts (not /user/accounts)
  const response = await fetch('https://api.cloudflare.com/client/v4/accounts', {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    const text = await response.text();
    console.log(JSON.stringify({
      status: 'error',
      message: `getAccountInfo failed (${response.status}): ${text}`,
    }));
    throw new Error(`Failed to get accounts (${response.status}): ${text}`);
  }

  const data = await response.json();

  if (!data.success || !data.result || data.result.length === 0) {
    console.log(JSON.stringify({
      status: 'error',
      message: `No accounts found: ${JSON.stringify(data)}`,
    }));
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
 * Main login flow with PKCE
 */
async function login() {
  const redirectUri = `http://localhost:${REDIRECT_PORT}${REDIRECT_PATH}`;

  // Generate PKCE code_verifier and code_challenge
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  // Build authorization URL with PKCE parameters
  const authUrl = new URL(AUTH_URL);
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', SCOPES);
  authUrl.searchParams.set('state', Date.now().toString());
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  console.log(JSON.stringify({
    status: 'starting',
    message: 'Starting OAuth login flow with PKCE',
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

  // Exchange code for tokens (with code_verifier)
  const tokens = await exchangeCodeForToken(code, codeVerifier);

  console.log(JSON.stringify({
    status: 'account',
    message: 'Retrieving account information',
  }));

  // Get account info
  const accountInfo = await getAccountInfo(tokens.access_token);

  // Save tokens
  const configFile = saveTokens(tokens.access_token, tokens.refresh_token, accountInfo.accountId);

  // Output final result with snake_case field names (matching Rust struct)
  const result = {
    success: true,
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_in: tokens.expires_in,
    account_id: accountInfo.accountId,
    account_name: accountInfo.accountName,
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