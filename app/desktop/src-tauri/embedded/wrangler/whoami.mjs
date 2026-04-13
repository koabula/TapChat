/**
 * TapChat Cloudflare Whoami
 *
 * Check authentication status and retrieve account information.
 * Uses stored OAuth tokens from wrangler config.
 *
 * Usage: node whoami.mjs
 * Output: JSON with accountId, accountName, email, status
 */

import { readFileSync, existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

const WRANGLER_CONFIG_FILE = join(homedir(), '.wrangler', 'config', 'default.toml');

/**
 * Parse simple TOML file (handles key = "value" format)
 */
function parseSimpleToml(content) {
  const result = {};
  const lines = content.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('[')) {
      continue;
    }

    const match = trimmed.match(/^(\w+)\s*=\s*"(.*)"/);
    if (match) {
      result[match[1]] = match[2];
    }
  }

  return result;
}

/**
 * Load stored OAuth token
 */
function loadStoredToken() {
  if (!existsSync(WRANGLER_CONFIG_FILE)) {
    return null;
  }

  try {
    const content = readFileSync(WRANGLER_CONFIG_FILE, 'utf8');
    const config = parseSimpleToml(content);

    return {
      accessToken: config.oauth_token,
      refreshToken: config.refresh_token,
      accountId: config.account_id,
    };
  } catch {
    return null;
  }
}

/**
 * Get user information
 */
async function getUserInfo(accessToken) {
  const response = await fetch('https://api.cloudflare.com/client/v4/user', {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    return null;
  }

  const data = await response.json();

  if (!data.success) {
    return null;
  }

  return {
    email: data.result.email,
    firstName: data.result.first_name,
    lastName: data.result.last_name,
  };
}

/**
 * Get account information
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
    return null;
  }

  const data = await response.json();

  if (!data.success || !data.result) {
    return null;
  }

  // Use snake_case field names for Rust compatibility
  return data.result.map(account => ({
    account_id: account.id,
    account_name: account.name,
  }));
}

/**
 * Main whoami flow
 */
async function whoami() {
  // Load stored token
  const stored = loadStoredToken();

  if (!stored || !stored.accessToken) {
    console.log(JSON.stringify({
      authenticated: false,
      message: 'Not logged in. Run login.mjs first.',
    }));
    return;
  }

  // Verify token is still valid
  const userInfo = await getUserInfo(stored.accessToken);

  if (!userInfo) {
    console.log(JSON.stringify({
      authenticated: false,
      message: 'Token expired or invalid. Please login again.',
    }));
    return;
  }

  // Get accounts
  const accounts = await getAccountInfo(stored.accessToken);

  if (!accounts || accounts.length === 0) {
    console.log(JSON.stringify({
      authenticated: true,
      email: userInfo.email,
      message: 'Authenticated but no accounts found.',
    }));
    return;
  }

  // Output result with snake_case field names for Rust compatibility
  console.log(JSON.stringify({
    authenticated: true,
    email: userInfo.email,
    name: `${userInfo.firstName || ''} ${userInfo.lastName || ''}`.trim() || undefined,
    accounts,
    active_account_id: stored.accountId || accounts[0].account_id,
  }));
}

// Run whoami if executed directly
whoami().catch((error) => {
  console.log(JSON.stringify({
    authenticated: false,
    error: error.message,
  }));
  process.exit(1);
});