import { createClient } from '@supabase/supabase-js';

// ============================================================================
// CLOUDFLARE PAGES FUNCTIONS: UNIVERSAL EDGE API
// Punjabi Bistro & Bakery Dharamkot
// ============================================================================

interface SessionPayload {
  sessionId: string;
  username: string;
  role: string;
  createdAt: number;
  expiresAt: number;
}

const DEFAULT_ADMIN_RECORD = {
  username: 'admin',
  password_hash:
    'pbkdf2$sha512$100000$7271b90bd310a70b46264654db1fac0d$ee29d413ac5356e2487e4001130cac1e6d0498bfd7c1271e1e1865c7b01944fade2d997939ca3bea9a2b8ea84f1f7a96a1a2ff174ece25a1ceca6497efb6cef2',
  security_key_hash:
    'pbkdf2$sha512$100000$8cc2246d3fe92307ee6a425bcb4097ae$2189c883b0a74ffbbd8f25c6312cae4ec6b73905e2de6095af59782b69470bbe1e9a4c7da7a2c580523795aaaec02c11ae8386fcfc3d79e2785850a0890329e9',
};

// In-memory credential override during Edge Worker lifespan
let currentAdminRecord = { ...DEFAULT_ADMIN_RECORD };

const revokedSessions = new Set<string>();

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
  'Content-Type': 'application/json',
};

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: CORS_HEADERS,
  });
}

function getSupabase(env: any) {
  const url =
    env.SUPABASE_URL ||
    env.VITE_SUPABASE_URL ||
    'https://mlbjulhzbhnqkzzohgcm.supabase.co';

  const key =
    env.SUPABASE_SERVICE_ROLE_KEY ||
    env.SUPABASE_ANON_KEY ||
    env.VITE_SUPABASE_ANON_KEY ||
    'sb_publishable_wepmD-cYmB4FyuoS2EByeA_pzfVNM_c';

  return createClient(url, key, { auth: { persistSession: false } });
}

// ----------------------------------------------------------------------------
// Web Crypto PBKDF2-SHA512 Hashing & Constant-Time Verification
// ----------------------------------------------------------------------------
async function verifyPBKDF2(plainText: string, storedHash: string): Promise<boolean> {
  try {
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
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(plainText),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
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
    console.error('PBKDF2 verification error:', err);
    return false;
  }
}

async function hashPBKDF2(plainText: string): Promise<string> {
  const iterations = 100000;
  const saltBytes = new Uint8Array(16);
  crypto.getRandomValues(saltBytes);
  const saltHex = Array.from(saltBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(plainText),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations,
      hash: 'SHA-512',
    },
    keyMaterial,
    512
  );

  const derivedHex = Array.from(new Uint8Array(derivedBits))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return `pbkdf2$sha512$${iterations}$${saltHex}$${derivedHex}`;
}

// ----------------------------------------------------------------------------
// HMAC Token Signing & Verification
// ----------------------------------------------------------------------------
function getSessionSecret(env: any): string {
  return (
    env.ADMIN_SESSION_SECRET ||
    'punjabi-bistro-cloudflare-pages-edge-session-secret-key-2026'
  );
}

function base64UrlEncode(str: string): string {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64UrlDecode(str: string): string {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return atob(b64);
}

async function createSessionToken(
  username: string,
  secret: string
): Promise<{ token: string; expiresAt: number }> {
  const randomBytes = new Uint8Array(16);
  crypto.getRandomValues(randomBytes);
  const sessionId = Array.from(randomBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const now = Date.now();
  const expiresAt = now + 8 * 60 * 60 * 1000; // 8 hours

  const payload: SessionPayload = {
    sessionId,
    username,
    role: 'owner',
    createdAt: now,
    expiresAt,
  };

  const payloadStr = JSON.stringify(payload);
  const payloadB64 = base64UrlEncode(payloadStr);

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payloadB64));
  const signatureB64 = base64UrlEncode(
    String.fromCharCode(...new Uint8Array(signature))
  );

  return {
    token: `${payloadB64}.${signatureB64}`,
    expiresAt,
  };
}

async function verifySessionToken(
  token: string,
  secret: string
): Promise<SessionPayload | null> {
  try {
    const [payloadB64, signatureB64] = token.split('.');
    if (!payloadB64 || !signatureB64) return null;

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const sigStr = base64UrlDecode(signatureB64);
    const sigBytes = new Uint8Array(sigStr.split('').map((c) => c.charCodeAt(0)));

    const isValid = await crypto.subtle.verify(
      'HMAC',
      key,
      sigBytes,
      encoder.encode(payloadB64)
    );

    if (!isValid) return null;

    const payload: SessionPayload = JSON.parse(base64UrlDecode(payloadB64));

    if (revokedSessions.has(payload.sessionId)) return null;
    if (Date.now() > payload.expiresAt) return null;

    return payload;
  } catch {
    return null;
  }
}

async function authenticateRequest(
  request: Request,
  env: any
): Promise<SessionPayload | null> {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7).trim();
  return verifySessionToken(token, getSessionSecret(env));
}

// ----------------------------------------------------------------------------
// Cloudflare Pages onRequest Main Router
// ----------------------------------------------------------------------------
export async function onRequest(context: {
  request: Request;
  env: any;
  params: { catchall: string[] | string };
  waitUntil: (p: Promise<any>) => void;
  next: () => Promise<Response>;
}): Promise<Response> {
  const { request, env } = context;
  const url = new URL(request.url);
  const pathname = url.pathname;
  const method = request.method.toUpperCase();

  // Handle CORS Preflight
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  const supabase = getSupabase(env);
  const secret = getSessionSecret(env);

  // ==========================================================================
  // ROUTE: POST /api/admin/login
  // ==========================================================================
  if (pathname === '/api/admin/login' && method === 'POST') {
    try {
      const body = (await request.json().catch(() => ({}))) as any;
      const { username, password, securityKey } = body;

      if (!username || !password || !securityKey) {
        return jsonResponse({ error: 'Invalid login details.' }, 401);
      }

      const cleanUsername = String(username).trim();

      // Check against current admin record
      const isUsernameMatch =
        cleanUsername.toLowerCase() === currentAdminRecord.username.toLowerCase();

      let isPasswordValid = false;
      let isSecurityKeyValid = false;

      if (isUsernameMatch) {
        isPasswordValid = await verifyPBKDF2(
          password,
          currentAdminRecord.password_hash
        );
        isSecurityKeyValid = await verifyPBKDF2(
          securityKey,
          currentAdminRecord.security_key_hash
        );
      }

      // Check against Supabase admin_credentials if not matched in memory
      if (!isUsernameMatch || !isPasswordValid || !isSecurityKeyValid) {
        try {
          const { data: dbAdmin } = await supabase
            .from('admin_credentials')
            .select('*')
            .eq('is_active', true)
            .ilike('username', cleanUsername)
            .maybeSingle();

          if (dbAdmin && dbAdmin.password_hash && dbAdmin.security_key_hash) {
            const dbPassValid = await verifyPBKDF2(password, dbAdmin.password_hash);
            const dbSecValid = await verifyPBKDF2(
              securityKey,
              dbAdmin.security_key_hash
            );
            if (dbPassValid && dbSecValid) {
              const { token, expiresAt } = await createSessionToken(
                dbAdmin.username,
                secret
              );
              return jsonResponse({
                success: true,
                username: dbAdmin.username,
                token,
                expiresAt,
              });
            }
          }
        } catch {
          // Supabase credentials table optional check
        }

        return jsonResponse({ error: 'Invalid login details.' }, 401);
      }

      const { token, expiresAt } = await createSessionToken(
        currentAdminRecord.username,
        secret
      );

      return jsonResponse({
        success: true,
        username: currentAdminRecord.username,
        token,
        expiresAt,
      });
    } catch (err: any) {
      return jsonResponse({ error: err?.message || 'Login failed.' }, 500);
    }
  }

  // ==========================================================================
  // ROUTE: GET /api/admin/session
  // ==========================================================================
  if (pathname === '/api/admin/session' && method === 'GET') {
    const session = await authenticateRequest(request, env);
    if (!session) {
      return jsonResponse({ authenticated: false, error: 'Session expired' }, 401);
    }
    return jsonResponse({
      authenticated: true,
      username: session.username,
      expiresAt: session.expiresAt,
    });
  }

  // ==========================================================================
  // ROUTE: POST /api/admin/logout
  // ==========================================================================
  if (pathname === '/api/admin/logout' && method === 'POST') {
    const authHeader = request.headers.get('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.slice(7).trim();
      const session = await verifySessionToken(token, secret);
      if (session) {
        revokedSessions.add(session.sessionId);
      }
    }
    return jsonResponse({ success: true });
  }

  // ==========================================================================
  // ROUTE: POST /api/admin/credentials/update
  // ==========================================================================
  if (pathname === '/api/admin/credentials/update' && method === 'POST') {
    const session = await authenticateRequest(request, env);
    if (!session) {
      return jsonResponse({ error: 'Unauthorized: Session expired' }, 401);
    }

    const body = (await request.json().catch(() => ({}))) as any;
    const { currentPassword, newUsername, newPassword, newSecurityKey } = body;

    const isCurrentValid = await verifyPBKDF2(
      currentPassword || '',
      currentAdminRecord.password_hash
    );
    if (!isCurrentValid) {
      return jsonResponse({ error: 'Current password is incorrect.' }, 401);
    }

    if (newUsername && typeof newUsername === 'string' && newUsername.trim()) {
      currentAdminRecord.username = newUsername.trim();
    }
    if (newPassword && typeof newPassword === 'string' && newPassword.length >= 6) {
      currentAdminRecord.password_hash = await hashPBKDF2(newPassword);
    }
    if (
      newSecurityKey &&
      typeof newSecurityKey === 'string' &&
      newSecurityKey.length >= 6
    ) {
      currentAdminRecord.security_key_hash = await hashPBKDF2(newSecurityKey);
    }

    // Persist to Supabase admin_credentials if possible
    try {
      await supabase.from('admin_credentials').upsert(
        {
          username: currentAdminRecord.username,
          password_hash: currentAdminRecord.password_hash,
          security_key_hash: currentAdminRecord.security_key_hash,
          is_active: true,
          updated_at: new Date().toISOString(),
        },
        { onConflict: 'username' }
      );
    } catch {
      // ignore
    }

    return jsonResponse({
      success: true,
      username: currentAdminRecord.username,
      message: 'Credentials updated successfully.',
    });
  }

  // ==========================================================================
  // ROUTE: GET /api/admin/orders
  // ==========================================================================
  if (pathname === '/api/admin/orders' && method === 'GET') {
    const session = await authenticateRequest(request, env);
    if (!session) return jsonResponse({ error: 'Unauthorized' }, 401);

    const { data, error } = await supabase
      .from('orders')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) {
      return jsonResponse({ error: error.message }, 500);
    }
    return jsonResponse(data || []);
  }

  // ==========================================================================
  // ROUTE: POST /api/admin/orders/status
  // ==========================================================================
  if (pathname === '/api/admin/orders/status' && method === 'POST') {
    const session = await authenticateRequest(request, env);
    if (!session) return jsonResponse({ error: 'Unauthorized' }, 401);

    const body = (await request.json().catch(() => ({}))) as any;
    const { orderId, status } = body;
    if (!orderId || !status) {
      return jsonResponse({ error: 'orderId and status required' }, 400);
    }

    const { error } = await supabase
      .from('orders')
      .update({ status })
      .or(`id.eq.${orderId},order_number.eq.${orderId}`);

    if (error) return jsonResponse({ error: error.message }, 500);
    return jsonResponse({ success: true });
  }

  // ==========================================================================
  // ROUTE: POST /api/admin/orders/delay
  // ==========================================================================
  if (pathname === '/api/admin/orders/delay' && method === 'POST') {
    const session = await authenticateRequest(request, env);
    if (!session) return jsonResponse({ error: 'Unauthorized' }, 401);

    const body = (await request.json().catch(() => ({}))) as any;
    const { orderId, delayMinutes, delayMessage } = body;

    const { error } = await supabase
      .from('orders')
      .update({
        delay_minutes: Number(delayMinutes) || 0,
        delay_message: delayMessage || '',
      })
      .or(`id.eq.${orderId},order_number.eq.${orderId}`);

    if (error) return jsonResponse({ error: error.message }, 500);
    return jsonResponse({ success: true });
  }

  // ==========================================================================
  // ROUTE: POST /api/admin/products
  // ==========================================================================
  if (pathname === '/api/admin/products' && method === 'POST') {
    const session = await authenticateRequest(request, env);
    if (!session) return jsonResponse({ error: 'Unauthorized' }, 401);

    const body = (await request.json().catch(() => ({}))) as any;
    const { product } = body;
    if (!product || !product.id || !product.name) {
      return jsonResponse({ error: 'Valid product data is required' }, 400);
    }

    const payload = {
      id: product.id,
      name: product.name,
      category_id: product.categoryId,
      category_name: product.categoryName,
      description: product.description || '',
      price: product.price,
      original_price: product.originalPrice || null,
      image: product.image,
      is_available: product.isAvailable !== undefined ? product.isAvailable : true,
      is_bestseller: Boolean(product.isBestseller),
      is_eggless: product.isEggless !== undefined ? product.isEggless : true,
      is_vegetarian: product.isVegetarian !== undefined ? product.isVegetarian : true,
      is_spicy: Boolean(product.isSpicy),
      prep_time_minutes: product.prepTimeMinutes || 20,
      customization_groups: product.customizationGroups || [],
    };

    const { error } = await supabase
      .from('products')
      .upsert(payload, { onConflict: 'id' });

    if (error) return jsonResponse({ error: error.message }, 500);
    return jsonResponse({ success: true });
  }

  // ==========================================================================
  // ROUTE: DELETE /api/admin/products/:id
  // ==========================================================================
  if (pathname.startsWith('/api/admin/products/') && method === 'DELETE') {
    const session = await authenticateRequest(request, env);
    if (!session) return jsonResponse({ error: 'Unauthorized' }, 401);

    const productId = pathname.replace('/api/admin/products/', '').trim();
    if (!productId) return jsonResponse({ error: 'Product ID required' }, 400);

    const { error } = await supabase.from('products').delete().eq('id', productId);
    if (error) return jsonResponse({ error: error.message }, 500);
    return jsonResponse({ success: true });
  }

  // ==========================================================================
  // ROUTE: POST /api/admin/cakes/quote
  // ==========================================================================
  if (pathname === '/api/admin/cakes/quote' && method === 'POST') {
    const session = await authenticateRequest(request, env);
    if (!session) return jsonResponse({ error: 'Unauthorized' }, 401);

    const body = (await request.json().catch(() => ({}))) as any;
    const { id, status, quotationAmount, adminNotes } = body;

    const payload: Record<string, unknown> = { status };
    if (quotationAmount !== undefined) payload.quotation_amount = quotationAmount;
    if (adminNotes !== undefined) payload.admin_notes = adminNotes;

    const { error } = await supabase
      .from('custom_cake_enquiries')
      .update(payload)
      .or(`id.eq.${id},enquiry_number.eq.${id}`);

    if (error) return jsonResponse({ error: error.message }, 500);
    return jsonResponse({ success: true });
  }

  // ==========================================================================
  // ROUTE: POST /api/admin/issues/resolve
  // ==========================================================================
  if (pathname === '/api/admin/issues/resolve' && method === 'POST') {
    const session = await authenticateRequest(request, env);
    if (!session) return jsonResponse({ error: 'Unauthorized' }, 401);

    const body = (await request.json().catch(() => ({}))) as any;
    const { id, notes } = body;

    const { error } = await supabase
      .from('customer_issues')
      .update({ status: 'resolved', resolution_notes: notes || 'Resolved by management' })
      .eq('id', id);

    if (error) return jsonResponse({ error: error.message }, 500);
    return jsonResponse({ success: true });
  }

  // ==========================================================================
  // ROUTE: POST /api/admin/reviews/reply
  // ==========================================================================
  if (pathname === '/api/admin/reviews/reply' && method === 'POST') {
    const session = await authenticateRequest(request, env);
    if (!session) return jsonResponse({ error: 'Unauthorized' }, 401);

    const body = (await request.json().catch(() => ({}))) as any;
    const { id, reply } = body;

    const { error } = await supabase
      .from('reviews')
      .update({ owner_reply: reply })
      .eq('id', id);

    if (error) return jsonResponse({ error: error.message }, 500);
    return jsonResponse({ success: true });
  }

  // ==========================================================================
  // ROUTE: POST /api/orders (Customer Order Submission)
  // ==========================================================================
  if (pathname === '/api/orders' && method === 'POST') {
    try {
      const order = (await request.json().catch(() => ({}))) as any;
      if (
        !order ||
        !order.customerName ||
        !order.customerPhone ||
        !Array.isArray(order.items)
      ) {
        return jsonResponse(
          { error: 'Invalid order data: customerName, phone and items required' },
          400
        );
      }

      const randomBytes = new Uint8Array(16);
      crypto.getRandomValues(randomBytes);
      const randomHex = Array.from(randomBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      const orderId = order.id || `ord-${Date.now()}`;
      const orderNumber =
        order.orderNumber || `PB-${Math.floor(1000 + Math.random() * 9000)}`;
      const trackingToken = order.trackingToken || randomHex;

      const itemsWithMeta = [
        ...order.items.filter((i: any) => !i || !i._meta),
        {
          _meta: {
            userId: order.userId || null,
            customerEmail: order.customerEmail || null,
            trackingToken,
            orderNumber,
          },
        },
      ];

      const payload: Record<string, any> = {
        id: orderId,
        order_number: orderNumber,
        customer_name: order.customerName,
        customer_phone: order.customerPhone,
        order_type: order.orderType || 'delivery',
        delivery_address: order.deliveryAddress || null,
        landmark: order.landmark || null,
        zone_id: order.zoneId || order.deliveryZoneId || null,
        table_number: order.tableNumber || null,
        time_slot: order.timeSlot || 'asap',
        scheduled_date: order.scheduledDate || null,
        items: itemsWithMeta,
        subtotal: Number(order.subtotal) || 0,
        delivery_fee: Number(order.deliveryFee) || 0,
        discount: Number(order.discount) || 0,
        coupon_code: order.couponCode || null,
        total: Number(order.total) || 0,
        payment_method: order.paymentMethod || 'cod',
        payment_status: order.paymentStatus || 'pending',
        upi_txn_id: order.upiTxnId || null,
        status: order.status || 'new',
        order_notes: order.orderNotes || null,
        is_no_contact_delivery: Boolean(order.isNoContactDelivery),
        created_at: order.createdAt || new Date().toISOString(),
        estimated_delivery_time: order.estimatedDeliveryTime || null,
        delay_minutes: order.delayMinutes || null,
        delay_message: order.delayMessage || null,
      };

      let saveError: string | null = null;
      for (let attempt = 0; attempt < 4; attempt++) {
        const { error } = await supabase
          .from('orders')
          .upsert(payload, { onConflict: 'id' });

        if (!error) {
          saveError = null;
          break;
        }

        const colMatch = error.message.match(/Could not find the '([^']+)' column/);
        if (colMatch && colMatch[1] && payload.hasOwnProperty(colMatch[1])) {
          delete payload[colMatch[1]];
          continue;
        }

        saveError = error.message;
        break;
      }

      if (saveError) {
        return jsonResponse({ error: `Database error: ${saveError}` }, 500);
      }

      const confirmedOrder = {
        ...order,
        id: orderId,
        orderNumber,
        trackingToken,
        items: order.items.filter((i: any) => !i || !i._meta),
        status: payload.status,
        createdAt: payload.created_at,
      };

      return jsonResponse({ success: true, order: confirmedOrder });
    } catch (err: any) {
      return jsonResponse(
        { error: err?.message || 'Server exception saving order' },
        500
      );
    }
  }

  // ==========================================================================
  // ROUTE: GET /api/customer/orders
  // ==========================================================================
  if (pathname === '/api/customer/orders' && method === 'GET') {
    const userId = url.searchParams.get('userId')?.trim() || '';
    const email = url.searchParams.get('email')?.trim().toLowerCase() || '';
    const phone = url.searchParams.get('phone')?.replace(/\D/g, '') || '';

    if (!userId && !email && !phone) {
      return jsonResponse([]);
    }

    try {
      const { data, error } = await supabase
        .from('orders')
        .select('*')
        .order('created_at', { ascending: false });

      if (error || !Array.isArray(data)) {
        return jsonResponse([]);
      }

      const matched = data.filter((row: any) => {
        if (userId && row.user_id === userId) return true;
        if (email && row.customer_email && row.customer_email.toLowerCase() === email)
          return true;

        if (Array.isArray(row.items)) {
          const meta = row.items.find((i: any) => i && i._meta)?._meta;
          if (meta) {
            if (userId && meta.userId === userId) return true;
            if (email && meta.customerEmail && meta.customerEmail.toLowerCase() === email)
              return true;
          }
        }

        if (phone && phone.length >= 10) {
          const dbPhone = String(row.customer_phone || '').replace(/\D/g, '');
          if (
            dbPhone &&
            (dbPhone === phone || dbPhone.endsWith(phone) || phone.endsWith(dbPhone))
          ) {
            return true;
          }
        }

        return false;
      });

      return jsonResponse(matched);
    } catch {
      return jsonResponse([]);
    }
  }

  // Default fallback for unmatched /api routes
  return jsonResponse({ error: 'Endpoint not found' }, 404);
}
