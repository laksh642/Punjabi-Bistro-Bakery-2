import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

const ADMIN_TOKEN_KEY = 'pb_admin_session_token';
const ADMIN_CUSTOM_CREDS_KEY = 'pb_admin_custom_creds';

const DEFAULT_ADMIN_RECORD = {
  username: 'admin',
  password_hash:
    'pbkdf2$sha512$100000$7271b90bd310a70b46264654db1fac0d$ee29d413ac5356e2487e4001130cac1e6d0498bfd7c1271e1e1865c7b01944fade2d997939ca3bea9a2b8ea84f1f7a96a1a2ff174ece25a1ceca6497efb6cef2',
  security_key_hash:
    'pbkdf2$sha512$100000$8cc2246d3fe92307ee6a425bcb4097ae$2189c883b0a74ffbbd8f25c6312cae4ec6b73905e2de6095af59782b69470bbe1e9a4c7da7a2c580523795aaaec02c11ae8386fcfc3d79e2785850a0890329e9',
};

async function verifyClientPBKDF2(plainText: string, storedHash: string): Promise<boolean> {
  try {
    if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) {
      return false;
    }
    const parts = storedHash.split('$');
    if (parts.length !== 5 || parts[0] !== 'pbkdf2' || parts[1] !== 'sha512') {
      return false;
    }
    const iterations = parseInt(parts[2], 10);
    const saltHex = parts[3];
    const originalDerivedHex = parts[4];

    const saltBytes = new Uint8Array(
      saltHex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );

    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      encoder.encode(plainText),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations,
        hash: 'SHA-512',
      },
      keyMaterial,
      512
    );

    const derivedArray = Array.from(new Uint8Array(derivedBits));
    const derivedHex = derivedArray
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    return derivedHex.toLowerCase() === originalDerivedHex.toLowerCase();
  } catch (err) {
    console.error('Client PBKDF2 check notice:', err);
    return false;
  }
}

function decodeTokenPayload(token: string): any | null {
  try {
    const [payloadB64] = token.split('.');
    if (!payloadB64) return null;
    let b64 = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const jsonStr = atob(b64);
    return JSON.parse(jsonStr);
  } catch {
    return null;
  }
}

function createClientSessionToken(username: string): string {
  const randomBytes = new Uint8Array(16);
  if (typeof window !== 'undefined' && window.crypto) {
    window.crypto.getRandomValues(randomBytes);
  }
  const sessionId = Array.from(randomBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const now = Date.now();
  const expiresAt = now + 8 * 60 * 60 * 1000;
  const payload = {
    sessionId,
    username,
    role: 'owner',
    createdAt: now,
    expiresAt,
  };

  const payloadB64 = btoa(JSON.stringify(payload))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  const dummySig = btoa('cloudflare_static_session')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return `${payloadB64}.${dummySig}`;
}

interface AdminAuthContextType {
  isAuthenticated: boolean;
  adminUsername: string | null;
  isLoading: boolean;
  authError: string | null;
  login: (username: string, password: string, securityKey: string) => Promise<boolean>;
  logout: () => Promise<void>;
  refreshSession: () => Promise<void>;
  getAuthToken: () => string | null;
  // Aliases for backwards-compatibility
  isAuthorized: boolean;
  signOut: () => Promise<void>;
  user: { email: string } | null;
  adminRole: string | null;
}

const AdminAuthContext = createContext<AdminAuthContextType | undefined>(undefined);

export const AdminAuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [adminUsername, setAdminUsername] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [authError, setAuthError] = useState<string | null>(null);

  const getAuthToken = useCallback((): string | null => {
    try {
      return localStorage.getItem(ADMIN_TOKEN_KEY);
    } catch {
      return null;
    }
  }, []);

  const verifySession = useCallback(async () => {
    const token = getAuthToken();
    if (!token) {
      setIsAuthenticated(false);
      setAdminUsername(null);
      setIsLoading(false);
      return;
    }

    try {
      const res = await fetch('/api/admin/session', {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const contentType = res.headers.get('content-type') || '';
      if (res.ok && contentType.includes('application/json')) {
        const data = await res.json();
        if (data.authenticated && data.username) {
          setIsAuthenticated(true);
          setAdminUsername(data.username);
          setAuthError(null);
          return;
        }
      }

      // If server returned 401 explicitly, token was revoked or expired on server
      if (res.status === 401 && contentType.includes('application/json')) {
        try {
          localStorage.removeItem(ADMIN_TOKEN_KEY);
        } catch {}
        setIsAuthenticated(false);
        setAdminUsername(null);
        return;
      }

      // In Cloudflare static deployment without edge functions, verify local payload expiration
      const payload = decodeTokenPayload(token);
      if (payload && payload.username && Date.now() < payload.expiresAt) {
        setIsAuthenticated(true);
        setAdminUsername(payload.username);
        setAuthError(null);
        return;
      }

      try {
        localStorage.removeItem(ADMIN_TOKEN_KEY);
      } catch {}
      setIsAuthenticated(false);
      setAdminUsername(null);
    } catch {
      // Offline / network fallback
      const payload = decodeTokenPayload(token);
      if (payload && payload.username && Date.now() < payload.expiresAt) {
        setIsAuthenticated(true);
        setAdminUsername(payload.username);
        setAuthError(null);
      } else {
        setIsAuthenticated(false);
        setAdminUsername(null);
      }
    } finally {
      setIsLoading(false);
    }
  }, [getAuthToken]);

  // Check existing session on mount
  useEffect(() => {
    verifySession();
  }, [verifySession]);

  const login = async (
    username: string,
    password: string,
    securityKey: string
  ): Promise<boolean> => {
    setAuthError(null);

    const cleanUsername = username.trim();
    if (!cleanUsername || !password || !securityKey) {
      setAuthError('All login fields are required.');
      return false;
    }

    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: cleanUsername,
          password,
          securityKey,
        }),
      });

      const contentType = res.headers.get('content-type') || '';

      // If server/edge function responded with JSON
      if (contentType.includes('application/json')) {
        const data = await res.json().catch(() => ({}));

        if (!res.ok) {
          const errorMsg = data.error || 'Invalid login details.';
          setAuthError(errorMsg);
          setIsAuthenticated(false);
          setAdminUsername(null);
          return false;
        }

        if (data.success && data.token) {
          try {
            localStorage.setItem(ADMIN_TOKEN_KEY, data.token);
          } catch {}
          setIsAuthenticated(true);
          setAdminUsername(data.username || cleanUsername);
          setAuthError(null);
          return true;
        }
      }

      // If server responded with HTML (e.g. Cloudflare Pages static rewrite to index.html) or 404:
      // Perform resilient client-side PBKDF2 verification against stored admin credentials
      let targetRecord = DEFAULT_ADMIN_RECORD;
      try {
        const custom = localStorage.getItem(ADMIN_CUSTOM_CREDS_KEY);
        if (custom) {
          const parsed = JSON.parse(custom);
          if (parsed.username && parsed.password_hash && parsed.security_key_hash) {
            targetRecord = parsed;
          }
        }
      } catch {}

      const isUserMatch =
        cleanUsername.toLowerCase() === targetRecord.username.toLowerCase();

      if (isUserMatch) {
        const isPassValid = await verifyClientPBKDF2(
          password,
          targetRecord.password_hash
        );
        const isKeyValid = await verifyClientPBKDF2(
          securityKey,
          targetRecord.security_key_hash
        );

        if (isPassValid && isKeyValid) {
          const clientToken = createClientSessionToken(targetRecord.username);
          try {
            localStorage.setItem(ADMIN_TOKEN_KEY, clientToken);
          } catch {}
          setIsAuthenticated(true);
          setAdminUsername(targetRecord.username);
          setAuthError(null);
          return true;
        }
      }

      setAuthError('Invalid login details.');
      setIsAuthenticated(false);
      return false;
    } catch {
      // In case of total network disconnect or local static run:
      let targetRecord = DEFAULT_ADMIN_RECORD;
      try {
        const custom = localStorage.getItem(ADMIN_CUSTOM_CREDS_KEY);
        if (custom) {
          const parsed = JSON.parse(custom);
          if (parsed.username && parsed.password_hash && parsed.security_key_hash) {
            targetRecord = parsed;
          }
        }
      } catch {}

      const isUserMatch =
        cleanUsername.toLowerCase() === targetRecord.username.toLowerCase();

      if (isUserMatch) {
        const isPassValid = await verifyClientPBKDF2(
          password,
          targetRecord.password_hash
        );
        const isKeyValid = await verifyClientPBKDF2(
          securityKey,
          targetRecord.security_key_hash
        );

        if (isPassValid && isKeyValid) {
          const clientToken = createClientSessionToken(targetRecord.username);
          try {
            localStorage.setItem(ADMIN_TOKEN_KEY, clientToken);
          } catch {}
          setIsAuthenticated(true);
          setAdminUsername(targetRecord.username);
          setAuthError(null);
          return true;
        }
      }

      setAuthError('Invalid login details.');
      setIsAuthenticated(false);
      return false;
    }
  };

  const logout = async (): Promise<void> => {
    const token = getAuthToken();
    try {
      if (token) {
        await fetch('/api/admin/logout', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
      }
    } catch {
      // ignore
    } finally {
      try {
        localStorage.removeItem(ADMIN_TOKEN_KEY);
      } catch {
        // ignore
      }
      setIsAuthenticated(false);
      setAdminUsername(null);
      setAuthError(null);
    }
  };

  return (
    <AdminAuthContext.Provider
      value={{
        isAuthenticated,
        adminUsername,
        isLoading,
        authError,
        login,
        logout,
        refreshSession: verifySession,
        getAuthToken,
        // Aliases for compatibility
        isAuthorized: isAuthenticated,
        signOut: logout,
        user: isAuthenticated && adminUsername ? { email: adminUsername } : null,
        adminRole: isAuthenticated ? 'owner' : null,
      }}
    >
      {children}
    </AdminAuthContext.Provider>
  );
};

export const useAdminAuth = (): AdminAuthContextType => {
  const context = useContext(AdminAuthContext);
  if (!context) {
    throw new Error('useAdminAuth must be used within an AdminAuthProvider');
  }
  return context;
};
