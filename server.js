require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const Stripe = require('stripe');
const db = require('./db');

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();

// Railway sits in front of this service as a reverse proxy, so without
// this, req.ip returns Railway's internal proxy address for every request
// instead of the real client IP — which would make the per-IP signup
// throttle below useless (every signup would appear to come from the same
// "IP"). Trusting the proxy chain makes Express read the real client IP
// from X-Forwarded-For instead.
app.set('trust proxy', true);

// Auth uses bearer tokens (not cookies), so CORS doesn't need credentials
// mode and there's no security reason to lock this to one exact origin —
// doing so was actually breaking sign-in whenever the site got redeployed
// under a second Railway domain (a random name Railway assigns if the
// intended service name is taken), since the browser's Origin header no
// longer matched this single hardcoded value and the request got silently
// blocked before it ever reached these routes. Reflecting any origin keeps
// things working regardless of which domain the frontend is served from.
app.use(cors());

// CLIENT_URL is still used later (Stripe success/cancel/portal redirect
// URLs) — keep it set in Railway variables to your primary frontend domain.
/**
 * Stripe webhook — must be registered BEFORE express.json(),
 * because Stripe needs the raw, unparsed request body to verify the signature.
 */
app.post(
  '/api/stripe-webhook',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error('⚠️  Webhook signature verification failed:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        console.log('✅ Checkout complete:', session.customer_email, session.customer);
        const userId = session.client_reference_id;
        const plan = session.metadata && session.metadata.plan;
        if (userId && plan) {
          const data = db.readDB();
          const user = data.users.find(u => u.id === userId);
          if (user) {
            user.plan = plan;
            user.stripeCustomerId = session.customer;
            db.writeDB(data);
            console.log(`   → user ${user.email} upgraded to ${plan}`);
          }
        } else {
          console.log('   ⚠️ No client_reference_id/plan on session — user was likely not signed in at checkout.');
        }
        break;
      }

      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        console.log('🔄 Subscription cancelled:', sub.id);
        const data = db.readDB();
        const user = data.users.find(u => u.stripeCustomerId === sub.customer);
        if (user) {
          user.plan = 'free';
          db.writeDB(data);
          console.log(`   → user ${user.email} moved back to free plan`);
        }
        break;
      }

      case 'customer.subscription.updated': {
        const sub = event.data.object;
        console.log('🔄 Subscription updated:', sub.id, sub.status);
        // TODO: if you support upgrades/downgrades via the customer portal,
        //       read sub.items to figure out the new plan and update the user.
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        console.log('❌ Payment failed for customer', invoice.customer);
        // TODO: email the user, and/or flag their account as past_due
        //       so your frontend can show a "update payment method" banner.
        break;
      }

      default:
        // Unhandled event type — safe to ignore.
        break;
    }

    res.json({ received: true });
  }
);

app.use(express.json());

// ---------------------------------------------------------------------------
// Auth — bearer tokens, not cookies.
//
// This was originally built on cookie sessions (express-session), which
// works fine when frontend and backend share a domain. Once deployed,
// though, they live on different Railway subdomains — a cross-site
// situation from the browser's point of view. Getting cross-site cookies
// right (SameSite=None; Secure) technically works, but modern browsers
// increasingly block third-party cookies by default regardless of those
// settings, which silently broke login in production (every /api/me call
// looked logged-out even right after a successful signup).
//
// Bearer tokens sidestep the problem entirely: the frontend stores the
// token (localStorage) and sends it explicitly via the Authorization
// header, so there's no cookie for the browser's third-party-cookie policy
// to block. Each user gets one active token, stored alongside them in
// data.json — fine at this scale; move to a real token/session table (with
// expiry) if this needs to scale past one server instance.
// ---------------------------------------------------------------------------
function issueToken(user){
  user.authToken = crypto.randomBytes(32).toString('hex');
  return user.authToken;
}

// Free plan: a one-time signup bonus, NOT a recurring weekly refill.
// This is deliberate — a recurring free allowance makes multi-accounting
// (sign up again with a new email once you've used your free tier) far
// more valuable to abuse. A one-time bonus, paired with the signup
// throttling below, makes repeat-signup abuse much less worth the effort.
const FREE_TRIES = 1;
const FREE_MB = 10;

// Very small, dependency-free anti-abuse layer for the free-tier signup
// bonus. Two independent checks, both best-effort (this is a single-
// instance file-based app, not a full fraud stack):
//   1) Disposable/throwaway email domains are rejected outright.
//   2) Signups are throttled per IP address — a real person doesn't need
//      more than a couple of free accounts from the same connection.
// Neither is bulletproof (VPNs, mobile carrier NAT, etc. all exist), but
// together they raise the cost of farming free accounts well above what
// a casual abuser will bother with.
const DISPOSABLE_EMAIL_DOMAINS = new Set([
  'mailinator.com', 'guerrillamail.com', 'guerrillamail.info', '10minutemail.com',
  '10minutemail.net', 'tempmail.com', 'temp-mail.org', 'throwawaymail.com',
  'yopmail.com', 'trashmail.com', 'getnada.com', 'dispostable.com',
  'sharklasers.com', 'fakeinbox.com', 'maildrop.cc', 'mintemail.com',
  'mohmal.com', 'moakt.com', 'emailondeck.com', 'spamgourmet.com',
]);

const SIGNUPS_PER_IP_LIMIT = 2;      // max free-tier signups from one IP...
const SIGNUPS_PER_IP_WINDOW_MS = 30 * 24 * 60 * 60 * 1000; // ...per rolling 30 days

function isDisposableEmail(email){
  const domain = (email.split('@')[1] || '').toLowerCase();
  return DISPOSABLE_EMAIL_DOMAINS.has(domain);
}

function getClientIp(req){
  // req.ip respects Express's `trust proxy` setting (enabled below), so
  // this reads the real client IP from X-Forwarded-For on Railway instead
  // of Railway's internal proxy IP.
  return req.ip || req.connection?.remoteAddress || 'unknown';
}

function signupsFromIpRecently(data, ip){
  const cutoff = Date.now() - SIGNUPS_PER_IP_WINDOW_MS;
  return data.users.filter(u => u.signupIp === ip && new Date(u.createdAt).getTime() >= cutoff).length;
}

function requireAuth(req, res, next){
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if(!token) return res.status(401).json({ error: 'Not signed in' });

  const data = db.readDB();
  const user = data.users.find(u => u.authToken === token);
  if(!user) return res.status(401).json({ error: 'Not signed in' });

  req.user = user;
  next();
}

// includeToken: signup/login need to hand the token back to the frontend
// once, right after auth; /api/me shouldn't re-send it on every poll.
function publicUser(user, includeToken){
  const out = {
    id: user.id,
    email: user.email,
    plan: user.plan,
    freeTriesRemaining: user.freeTriesRemaining,
    freeMbRemaining: user.freeMbRemaining,
    createdAt: user.createdAt,
  };
  if(includeToken) out.token = user.authToken;
  return out;
}

app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  if(!email || !password || password.length < 8){
    return res.status(400).json({ error: 'Enter a valid email and a password with at least 8 characters' });
  }
  if(isDisposableEmail(email)){
    return res.status(400).json({ error: 'Please sign up with a permanent email address' });
  }

  const data = db.readDB();
  const existing = data.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if(existing) return res.status(400).json({ error: 'An account with that email already exists' });

  const ip = getClientIp(req);
  if(signupsFromIpRecently(data, ip) >= SIGNUPS_PER_IP_LIMIT){
    return res.status(429).json({ error: "Too many free accounts created from this connection recently — subscribe to keep going, or try again later." });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: crypto.randomUUID(),
    email,
    passwordHash,
    plan: 'free',
    freeTriesRemaining: FREE_TRIES,
    freeMbRemaining: FREE_MB,
    signupIp: ip,
    stripeCustomerId: null,
    createdAt: new Date().toISOString(),
  };
  issueToken(user);
  data.users.push(user);
  db.writeDB(data);

  res.json(publicUser(user, true));
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const data = db.readDB();
  const user = data.users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
  if(!user) return res.status(401).json({ error: 'Incorrect email or password' });

  const valid = await bcrypt.compare(password || '', user.passwordHash);
  if(!valid) return res.status(401).json({ error: 'Incorrect email or password' });

  issueToken(user);
  db.writeDB(data);
  res.json(publicUser(user, true));
});

app.post('/api/logout', requireAuth, (req, res) => {
  const data = db.readDB();
  const user = data.users.find(u => u.id === req.user.id);
  if(user){ delete user.authToken; db.writeDB(data); }
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const data = db.readDB();
  const user = data.users.find(u => u.id === req.user.id);
  if(!user) return res.status(401).json({ error: 'Not signed in' });
  res.json(publicUser(user));
});

/**
 * Deducts one "try" and some MB from a user's one-time free-tier bonus.
 * Call this once per completed render for free-plan users (mbUsed = the
 * total size of the clip(s) that render produced). Free tier is a
 * one-time 2-tries/10MB signup bonus, NOT a recurring allowance — once
 * either runs out, the user has to subscribe. Paid plans aren't metered
 * against this at all; adjust here if you want paid-plan usage caps later.
 */
app.post('/api/consume-usage', requireAuth, (req, res) => {
  const mbUsed = Number(req.body.mbUsed) || 0;
  if (mbUsed < 0) return res.status(400).json({ error: 'mbUsed must not be negative' });

  const data = db.readDB();
  const user = data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(401).json({ error: 'Not signed in' });

  if (user.plan === 'free') {
    const triesLeft = user.freeTriesRemaining ?? 0;
    const mbLeft = user.freeMbRemaining ?? 0;
    if (triesLeft <= 0 || mbLeft <= 0) {
      return res.status(402).json({
        error: 'Your free trial is used up — subscribe to keep rendering.',
        freeTriesRemaining: Math.max(0, triesLeft),
        freeMbRemaining: Math.max(0, mbLeft),
      });
    }
    user.freeTriesRemaining = Math.max(0, triesLeft - 1);
    user.freeMbRemaining = Math.max(0, mbLeft - mbUsed);
  }

  db.writeDB(data);
  res.json(publicUser(user));
});

// Map (plan + billing period) -> the Stripe Price ID you create in the Dashboard.
const PRICE_IDS = {
  starter_monthly: process.env.PRICE_STARTER_MONTHLY,
  starter_yearly: process.env.PRICE_STARTER_YEARLY,
  pro_monthly: process.env.PRICE_PRO_MONTHLY,
  pro_yearly: process.env.PRICE_PRO_YEARLY,
  elite_monthly: process.env.PRICE_ELITE_MONTHLY,
  elite_yearly: process.env.PRICE_ELITE_YEARLY,
};

/**
 * Creates a Stripe Checkout session for a subscription and
 * returns the URL the frontend should redirect the browser to.
 */
app.post('/api/create-checkout-session', async (req, res) => {
  try {
    const { plan, billing } = req.body; // plan: starter|pro|elite, billing: monthly|yearly
    const key = `${plan}_${billing}`;
    const priceId = PRICE_IDS[key];

    if (!priceId) {
      return res.status(400).json({ error: `Unknown plan/billing combo: ${key}` });
    }

    // Optional: attach the signed-in user if a valid token was sent, so the
    // webhook can link this payment back to an account. Checkout also works
    // signed-out (userId stays undefined), matching the original behavior.
    let customerEmail;
    let userId;
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (token) {
      const data = db.readDB();
      const user = data.users.find(u => u.authToken === token);
      if (user) { userId = user.id; customerEmail = user.email; }
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      customer_email: customerEmail,
      client_reference_id: userId, // lets the webhook link this payment back to a user
      metadata: { plan, billing },
      allow_promotion_codes: true,
      success_url: `${process.env.CLIENT_URL}/?checkout=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_URL}/?checkout=cancelled`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Error creating checkout session:', err);
    res.status(500).json({ error: 'Could not create checkout session' });
  }
});

/**
 * Lets a subscribed user manage or cancel their plan via
 * Stripe's hosted Billing Portal, instead of you building that UI yourself.
 */
app.post('/api/create-portal-session', async (req, res) => {
  try {
    const { customerId } = req.body;
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: process.env.CLIENT_URL,
    });
    res.json({ url: portalSession.url });
  } catch (err) {
    console.error('Error creating portal session:', err);
    res.status(500).json({ error: 'Could not create portal session' });
  }
});

const PORT = process.env.PORT || 4242;
app.listen(PORT, () => console.log(`Clipsmith backend listening on port ${PORT}`));
