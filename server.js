require('dotenv').config();
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const Stripe = require('stripe');
const db = require('./db');

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();

// CLIENT_URL is your deployed frontend's origin (set in .env / Railway
// variables). Falls back to localhost for local dev. This must be a real
// origin (not '*') because credentials:true requires an explicit origin,
// and the frontend calls this API with credentials:'include'.
const CLIENT_ORIGIN = process.env.CLIENT_URL || 'http://localhost:3000';
app.use(cors({
  origin: CLIENT_ORIGIN,
  credentials: true
}));
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

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-only-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
    httpOnly: true,
    // Frontend and backend live on different domains once deployed (e.g.
    // Netlify + Railway), so this is a cross-site fetch from the browser's
    // point of view. SameSite=Lax cookies are NOT sent on cross-site
    // fetch/XHR (only on top-level navigations), which would silently
    // break login — every /api/me call would look logged-out. SameSite=None
    // fixes that, but requires Secure (HTTPS-only), which is why it's
    // conditional on NODE_ENV=production; local dev over plain http keeps
    // 'lax' since Secure cookies are dropped over http by the browser.
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    secure: process.env.NODE_ENV === 'production', // requires HTTPS in production
  },
}));
// NOTE: this uses express-session's default in-memory store, which is fine
// for local development but resets on every restart and won't scale across
// multiple server instances. For production, swap in a real session store
// (e.g. connect-pg-simple if you're on Postgres, or connect-redis).

const FREE_TRIAL_SECONDS = 60 * 60; // 1 free hour for every new account

function requireAuth(req, res, next){
  if(!req.session.userId) return res.status(401).json({ error: 'Not signed in' });
  next();
}

function publicUser(user){
  return {
    id: user.id,
    email: user.email,
    plan: user.plan,
    freeSecondsRemaining: user.freeSecondsRemaining,
    createdAt: user.createdAt,
  };
}

app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  if(!email || !password || password.length < 8){
    return res.status(400).json({ error: 'Enter a valid email and a password with at least 8 characters' });
  }

  const data = db.readDB();
  const existing = data.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if(existing) return res.status(400).json({ error: 'An account with that email already exists' });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: crypto.randomUUID(),
    email,
    passwordHash,
    plan: 'free',
    freeSecondsRemaining: FREE_TRIAL_SECONDS,
    stripeCustomerId: null,
    createdAt: new Date().toISOString(),
  };
  data.users.push(user);
  db.writeDB(data);

  req.session.userId = user.id;
  res.json(publicUser(user));
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const data = db.readDB();
  const user = data.users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
  if(!user) return res.status(401).json({ error: 'Incorrect email or password' });

  const valid = await bcrypt.compare(password || '', user.passwordHash);
  if(!valid) return res.status(401).json({ error: 'Incorrect email or password' });

  req.session.userId = user.id;
  res.json(publicUser(user));
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', requireAuth, (req, res) => {
  const data = db.readDB();
  const user = data.users.find(u => u.id === req.session.userId);
  if(!user) return res.status(401).json({ error: 'Not signed in' });
  res.json(publicUser(user));
});

/**
 * Deducts render time from a user's free-hour balance. Call this whenever
 * your product actually renders something for a free-plan user. Paid plans
 * should be metered differently (or not at all, depending on your model) —
 * this endpoint only touches freeSecondsRemaining, so it's a no-op cost
 * center for paid users unless you choose to call it for them too.
 */
app.post('/api/consume-time', requireAuth, (req, res) => {
  const seconds = Number(req.body.seconds) || 0;
  if (seconds <= 0) return res.status(400).json({ error: 'seconds must be a positive number' });

  const data = db.readDB();
  const user = data.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: 'Not signed in' });

  // Paid plans aren't metered against freeSecondsRemaining at all — only
  // free-plan users hit this wall. Adjust here if you want paid plans to
  // have their own usage caps later.
  if (user.plan === 'free' && (user.freeSecondsRemaining || 0) <= 0) {
    return res.status(402).json({ error: 'Free hour used up — subscribe to keep rendering.', freeSecondsRemaining: 0 });
  }

  user.freeSecondsRemaining = Math.max(0, (user.freeSecondsRemaining || 0) - seconds);
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

    let customerEmail;
    let userId = req.session.userId || undefined;
    if (userId) {
      const data = db.readDB();
      const user = data.users.find(u => u.id === userId);
      if (user) customerEmail = user.email;
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
