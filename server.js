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

// Free plan: uploads only, RECURRING every 4 days (not a one-time signup
// bonus anymore) — 10 uploads, then it refills 4 days after the window
// started. Cheap to offer this generously since uploads never touch the
// paid residential proxy (just Deepgram transcription + render compute).
// YouTube-link pasting stays paid-plans-only regardless of plan or window —
// see /api/consume-usage below, that's the one that actually costs real
// money per job and free users are rejected outright for it, no tries
// consumed either way.
const FREE_UPLOAD_LIMIT_PER_WINDOW = 10;
const FREE_UPLOAD_WINDOW_MS = 4 * 24 * 60 * 60 * 1000; // 4 days

// Very small, dependency-free anti-abuse layer for the free-tier signup
// bonus. Two independent checks, both best-effort (this is a single-
// instance file-based app, not a full fraud stack):
//   1) Disposable/throwaway email domains are rejected outright.
//   2) Signups are throttled per IP address — a real person doesn't need
//      more than a couple of free accounts from the same connection.
// Neither is bulletproof (VPNs, mobile carrier NAT, etc. all exist), but
// together they raise the cost of farming free accounts well above what
// a casual abuser will bother with. Worth even more now that the free
// upload allowance recurs every 4 days instead of being a one-time thing.
const DISPOSABLE_EMAIL_DOMAINS = new Set([
  'mailinator.com', 'guerrillamail.com', 'guerrillamail.info', '10minutemail.com',
  '10minutemail.net', 'tempmail.com', 'temp-mail.org', 'throwawaymail.com',
  'yopmail.com', 'trashmail.com', 'getnada.com', 'dispostable.com',
  'sharklasers.com', 'fakeinbox.com', 'maildrop.cc', 'mintemail.com',
  'mohmal.com', 'moakt.com', 'emailondeck.com', 'spamgourmet.com',
]);

const SIGNUPS_PER_IP_LIMIT = 2;      // max free-tier signups from one IP...
const SIGNUPS_PER_IP_WINDOW_MS = 30 * 24 * 60 * 60 * 1000; // ...per rolling 30 days

// ---------------------------------------------------------------------------
// Email verification + marketing opt-in.
//
// Free-tier signup previously required nothing but any string with an "@" in
// it, so anyone could type a random unowned address and start burning the
// free-upload allowance. Every new account now gets a one-time verify link
// (24h expiry) mailed to the address they gave; free-plan usage is blocked
// until they click it (see the emailVerified check in /api/consume-usage).
// Paid accounts already prove address ownership indirectly via Stripe/card
// billing, so the gate below only applies to the free plan.
//
// Sends via Resend (resend.com) — 3,000 free emails/month, no card needed.
// Set RESEND_API_KEY in Railway to activate; if it's unset, sendEmail()
// just logs and skips instead of throwing, so signup still works end-to-end
// without a provider configured (verification just can't complete until one
// is). Set RESEND_FROM_EMAIL once you've verified a domain in Resend — until
// then the default onboarding@resend.dev sender only delivers to the email
// address on the Resend account itself (Resend's anti-abuse restriction for
// unverified domains), which is fine for testing but not for real users.
// ---------------------------------------------------------------------------
const EMAIL_VERIFY_TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const VERIFICATION_EMAIL_MIN_INTERVAL_MS = 2 * 60 * 1000; // resend throttle

const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESEND_FROM_EMAIL = process.env.RESEND_FROM_EMAIL || 'ViralCut <onboarding@resend.dev>';
// Base URL the verify link points back to (this backend, not the frontend —
// it does the verify + redirect). RAILWAY_PUBLIC_DOMAIN is auto-injected by
// Railway for every service; API_URL overrides it if you're on a custom
// domain or running locally.
const API_BASE_URL = (process.env.API_URL || (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : `http://localhost:${process.env.PORT || 4242}`)).replace(/\/$/, '');

async function sendEmail(to, subject, html){
  if(!RESEND_API_KEY){
    console.log(`[email] RESEND_API_KEY not set — skipping send to ${to}: "${subject}"`);
    return false;
  }
  try{
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: RESEND_FROM_EMAIL, to, subject, html }),
    });
    if(!resp.ok){
      const errText = await resp.text().catch(() => '');
      console.error(`[email] Resend API error (${resp.status}) sending to ${to}: ${errText}`);
      return false;
    }
    return true;
  }catch(err){
    console.error(`[email] Failed to send to ${to}:`, err.message);
    return false;
  }
}

function buildVerifyEmailHtml(user){
  const link = `${API_BASE_URL}/api/verify-email?token=${user.emailVerifyToken}`;
  return `
    <div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;color:#222;">
      <h2 style="margin-bottom:4px;">Verify your email</h2>
      <p style="color:#555;">Confirm this address to unlock your free uploads on ViralCut.</p>
      <p><a href="${link}" style="display:inline-block;padding:12px 22px;background:#6c6cff;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;">Verify email</a></p>
      <p style="color:#888;font-size:13px;">Or paste this link into your browser:<br>${link}</p>
      <p style="color:#888;font-size:13px;">This link expires in 24 hours.</p>
    </div>`;
}

// Monthly source-video minute caps per paid plan — mirrors the copy on the
// pricing page ("150 min of source video / month" etc). Applies to total
// source video processed (uploads AND YouTube links both count — the cap
// exists because of transcription/render cost, not just proxy bandwidth).
// Free plan has no minute cap; it's limited by the recurring free-upload
// window instead. Resets on the calendar month, not each user's actual
// Stripe billing date — good enough for a solo-founder-scale app, and
// avoids an extra Stripe API call per usage check.
// Repriced Aug 2026 to sit ~15-20% below Crayo's equivalent tiers
// ($19/$39/$79) while still clearing a healthy margin — see PLAN_PRICES
// and PLAN_EST_COST below for the profit math this was built against.
const PLAN_MONTHLY_MINUTES = { starter: 100, pro: 350, elite: 1200 };

// Monthly proxy-bandwidth (Decodo) cap per paid plan, in MB. YouTube-link
// jobs pull the source video through a paid residential proxy — the
// minute cap above bounds this indirectly, but a single unusually
// high-bitrate video could still blow through the proxy budget the profit
// model assumes without ever hitting the minute cap. This is a direct
// second gate on the actual cost driver, derived straight from the same
// assumption the profit model spreadsheet uses (clipsmith_profit_model.xlsx,
// "Cost Inputs" tab: "Downloaded video size, 1080p source" = 6 MB/minute)
// applied to each plan's own minute cap — so it lines up with what the
// pricing was actually built to cover, not an arbitrary number.
const PROXY_MB_PER_SOURCE_MINUTE = 6;

// The pipeline now caches a downloaded source video by URL for 24h (see
// SOURCE_CACHE_DIR in pipeline.py) and tries a free/self-hosted proxy tier
// before ever touching the paid one — both cut REAL proxy spend well below
// the naive "every minute costs 6MB" assumption above. PROXY_CACHE_SAVINGS_
// FACTOR is a conservative estimate of that reduction (0.6 = expect actual
// usage to run ~40% below the uncached full-price number), applied to both
// the per-plan proxy cap and the Decodo line item in PLAN_EST_COST below.
// This is a placeholder until there's real usage data — tighten or relax it
// once /api/admin/stats has a few months of actual proxyMb numbers to look at.
const PROXY_CACHE_SAVINGS_FACTOR = 0.6;
const PLAN_PROXY_MB_LIMITS = Object.fromEntries(
  Object.entries(PLAN_MONTHLY_MINUTES).map(([plan, minutes]) => [
    plan,
    Math.round(minutes * PROXY_MB_PER_SOURCE_MINUTE * PROXY_CACHE_SAVINGS_FACTOR),
  ])
);

// Site-wide (not per-user) monthly ceiling on actual Decodo/proxy spend —
// same "hard dollar cap regardless of how many users sign up" pattern as
// GEMINI_MONTHLY_IMAGE_BUDGET_USD below. The per-plan MB caps above bound
// what one user can burn; this bounds the total bill. $3.00/GB mirrors the
// profit-model spreadsheet's Decodo rate. Defaults conservative ($40/mo)
// until real usage data justifies raising it — set PROXY_MONTHLY_BUDGET_USD
// in Railway to override.
const DECODO_COST_PER_GB_USD = 3.0;
const PROXY_MONTHLY_BUDGET_USD = Number(process.env.PROXY_MONTHLY_BUDGET_USD) || 40;
const PROXY_MONTHLY_MB_CAP_SITEWIDE = (PROXY_MONTHLY_BUDGET_USD / DECODO_COST_PER_GB_USD) * 1024;

// Daily cap on AI Images (Gemini) generations per user. Gemini's free
// tier is ~500 requests/day for the WHOLE site, shared across every
// user — these per-plan caps exist so one account can't burn the day's
// entire shared quota and break the tool for everyone else. Free plan
// isn't listed (0) since AI Images is paid-plans-only already (see
// tools.html). Groq (content ideas) isn't capped the same way — its
// free tier is ~14,400 requests/day, high enough that per-user limits
// aren't worth the complexity yet.
const PLAN_IMAGE_DAILY_LIMITS = { starter: 3, pro: 8, elite: 15 };

// Hard, SITE-WIDE ceiling on Gemini image spend — the per-plan daily caps
// above only bound what one user can burn; they don't bound the total bill,
// which scales with however many paying users sign up. This is the number
// that actually guarantees the monthly Gemini bill can't blow past a fixed
// dollar amount no matter how much the site grows. $0.039/image is Gemini
// 2.5 Flash Image's published per-generation rate (Aug 2026). Budget is a
// Railway env var so it can be raised later as revenue grows, without a
// code change — defaults to a deliberately conservative $50/month if unset.
const GEMINI_IMAGE_COST_USD = 0.039;
const GEMINI_MONTHLY_IMAGE_BUDGET_USD = Number(process.env.GEMINI_MONTHLY_IMAGE_BUDGET_USD) || 50;
const GEMINI_MONTHLY_IMAGE_CAP = Math.floor(GEMINI_MONTHLY_IMAGE_BUDGET_USD / GEMINI_IMAGE_COST_USD);

// Monthly cap on AI Videos (D-ID talking-avatar) generations per user.
// D-ID's free tier is only ~5 minutes of video for the WHOLE SITE per
// month, tracked on D-ID's own dashboard (not something we can read back
// in real time) — without a per-user cap, one person testing this could
// burn the entire month's shared budget in a single sitting and leave
// nothing for anyone else. Starter isn't listed (0) — the budget is too
// small to split three ways and still be useful to anyone.
const PLAN_VIDEO_MONTHLY_LIMITS = { pro: 1, elite: 3 };

function currentPeriod(){
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`; // "2026-08"
}

function todayKey(){
  return new Date().toISOString().slice(0, 10); // "2026-08-10", UTC calendar day
}

// A user's monthlyMinutesUsed only means something if usagePeriod matches
// the current calendar month — otherwise it's a stale count from a prior
// month that just hasn't been touched (and therefore reset) yet. Used for
// read-only reporting (publicUser, admin stats) so those endpoints don't
// need to mutate the DB just to answer "how much has this user used".
function effectiveMonthlyMinutes(user){
  return user.usagePeriod === currentPeriod() ? (user.monthlyMinutesUsed || 0) : 0;
}

// Same idea, for the monthly proxy-MB budget (see PLAN_PROXY_MB_LIMITS
// below) — shares the same usagePeriod/reset as monthlyMinutesUsed since
// both only apply to YouTube-link jobs and reset on the same monthly
// cycle. Kept separate from totalProxyMbUsed, which is all-time and never
// resets (that one's for lifetime reporting, this one's for the cap).
function effectiveProxyMbThisPeriod(user){
  return user.usagePeriod === currentPeriod() ? (user.proxyMbUsedThisPeriod || 0) : 0;
}

// Rolls a user's monthly usage counter over if the calendar month has
// changed since it was last touched. Mutates in place — caller is
// responsible for writing the DB afterward. Only called from the write
// path (/api/consume-usage), not from read-only endpoints.
function ensureCurrentPeriod(user){
  const period = currentPeriod();
  if(user.usagePeriod !== period){
    user.usagePeriod = period;
    user.monthlyMinutesUsed = 0;
    user.proxyMbUsedThisPeriod = 0;
  }
}

// Rolling 4-day window for the free plan's recurring upload allowance.
// Mutates in place — caller writes the DB afterward. A missing
// freeUploadWindowStart (legacy accounts from before this became
// recurring, or a fresh signup) just starts a brand-new window now.
function ensureFreeUploadWindow(user){
  const now = Date.now();
  const startedAt = user.freeUploadWindowStart ? new Date(user.freeUploadWindowStart).getTime() : 0;
  if (!user.freeUploadWindowStart || now - startedAt >= FREE_UPLOAD_WINDOW_MS) {
    user.freeUploadWindowStart = new Date().toISOString();
    user.freeUploadsUsedInWindow = 0;
  }
}

// Read-only version for publicUser() — doesn't mutate, so a stale/expired
// window just reads as "fully refilled" instead of actually rolling over
// (only the write path in /api/consume-usage does that), same split as
// effectiveMonthlyMinutes vs ensureCurrentPeriod above.
function effectiveFreeUploadsRemaining(user){
  const now = Date.now();
  const startedAt = user.freeUploadWindowStart ? new Date(user.freeUploadWindowStart).getTime() : 0;
  const expired = !user.freeUploadWindowStart || now - startedAt >= FREE_UPLOAD_WINDOW_MS;
  const used = expired ? 0 : (user.freeUploadsUsedInWindow || 0);
  return Math.max(0, FREE_UPLOAD_LIMIT_PER_WINDOW - used);
}

// When the current window refills, for the frontend to show "resets in
// X" messaging. Read-only, same non-mutating shape as the helper above.
function freeUploadWindowResetAt(user){
  const startedAt = user.freeUploadWindowStart ? new Date(user.freeUploadWindowStart).getTime() : Date.now();
  return new Date(startedAt + FREE_UPLOAD_WINDOW_MS).toISOString();
}

// Lightweight per-day usage log, kept per user for the last 90 days —
// powers the "Daily Usage" view in the stats Sheet. Not meant as a
// billing source of truth (monthlyMinutesUsed above is), just visibility.
function recordDailyUsage(user, { minutes, proxyMb }){
  const day = todayKey();
  user.dailyUsage = user.dailyUsage || {};
  const entry = user.dailyUsage[day] || { minutes: 0, proxyMb: 0, jobs: 0 };
  entry.minutes = Math.round((entry.minutes + minutes) * 100) / 100;
  entry.proxyMb = Math.round((entry.proxyMb + proxyMb) * 100) / 100;
  entry.jobs += 1;
  user.dailyUsage[day] = entry;

  const cutoff = Date.now() - 90 * 24 * 60 * 60 * 1000;
  for(const key of Object.keys(user.dailyUsage)){
    if(new Date(`${key}T00:00:00Z`).getTime() < cutoff) delete user.dailyUsage[key];
  }
}

// Same "reset if the day rolled over" pattern as ensureCurrentPeriod, but
// for the daily (not monthly) AI Images counter. Mutates in place —
// caller writes the DB afterward.
function ensureImageDay(user){
  const day = todayKey();
  if(user.imagesDate !== day){
    user.imagesDate = day;
    user.imagesUsedToday = 0;
  }
}

// Read-only version for publicUser()/admin stats — doesn't mutate, so a
// stale count from a prior day just reads as 0 instead of actually
// resetting (only the write path in /api/consume-image-generation does
// that), same split as effectiveMonthlyMinutes vs ensureCurrentPeriod.
function effectiveImagesToday(user){
  return user.imagesDate === todayKey() ? (user.imagesUsedToday || 0) : 0;
}

// Site-wide (not per-user) monthly counter backing GEMINI_MONTHLY_IMAGE_CAP
// above — lives on the root data object since it's a shared pool across
// every user, not one account's usage. Same reset-on-rollover pattern as
// the per-user helpers elsewhere in this file.
function ensureGeminiBudget(data){
  const period = currentPeriod();
  if(!data.geminiImageBudget || data.geminiImageBudget.period !== period){
    data.geminiImageBudget = { period, imagesGenerated: 0 };
  }
  return data.geminiImageBudget;
}

function effectiveGeminiImagesThisMonth(data){
  return data.geminiImageBudget && data.geminiImageBudget.period === currentPeriod()
    ? (data.geminiImageBudget.imagesGenerated || 0)
    : 0;
}

// Site-wide monthly proxy-spend circuit breaker — same shape as the Gemini
// budget above, backing PROXY_MONTHLY_MB_CAP_SITEWIDE. This is the one check
// that actually bounds the total Decodo bill regardless of how many paid
// users sign up or how the per-plan caps are tuned; the per-plan MB limits
// only bound what ONE user can burn.
function ensureProxyBudget(data){
  const period = currentPeriod();
  if(!data.proxyBudget || data.proxyBudget.period !== period){
    data.proxyBudget = { period, mbUsed: 0 };
  }
  return data.proxyBudget;
}

function effectiveProxyMbThisMonthSitewide(data){
  return data.proxyBudget && data.proxyBudget.period === currentPeriod()
    ? (data.proxyBudget.mbUsed || 0)
    : 0;
}

// Same reset-on-rollover pattern as ensureCurrentPeriod, but for the
// monthly AI Videos counter — separate from monthlyMinutesUsed since video
// generations and source-video minutes are unrelated budgets.
function ensureVideoMonth(user){
  const period = currentPeriod();
  if(user.videosPeriod !== period){
    user.videosPeriod = period;
    user.videosUsedThisMonth = 0;
  }
}

function effectiveVideosThisMonth(user){
  return user.videosPeriod === currentPeriod() ? (user.videosUsedThisMonth || 0) : 0;
}

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
    // Field name kept as freeUploadTriesRemaining for frontend compat —
    // the underlying meaning changed from a one-time pool to a recurring
    // 4-day window (see effectiveFreeUploadsRemaining above).
    freeUploadTriesRemaining: effectiveFreeUploadsRemaining(user),
    freeUploadWindowResetAt: user.plan === 'free' ? freeUploadWindowResetAt(user) : null,
    totalProxyMbUsed: user.totalProxyMbUsed || 0,
    proxyMbUsedThisPeriod: Math.round(effectiveProxyMbThisPeriod(user) * 10) / 10,
    proxyMbCap: PLAN_PROXY_MB_LIMITS[user.plan] || null,
    monthlyMinutesUsed: Math.round(effectiveMonthlyMinutes(user) * 10) / 10,
    monthlyMinutesCap: PLAN_MONTHLY_MINUTES[user.plan] || null,
    imagesUsedToday: effectiveImagesToday(user),
    imagesDailyCap: PLAN_IMAGE_DAILY_LIMITS[user.plan] || null,
    videosUsedThisMonth: effectiveVideosThisMonth(user),
    videosMonthlyCap: PLAN_VIDEO_MONTHLY_LIMITS[user.plan] || null,
    emailVerified: !!user.emailVerified,
    marketingOptIn: !!user.marketingOptIn,
    createdAt: user.createdAt,
  };
  if(includeToken) out.token = user.authToken;
  return out;
}

app.post('/api/signup', async (req, res) => {
  const { email, password, marketingOptIn } = req.body;
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
    freeUploadWindowStart: new Date().toISOString(),
    freeUploadsUsedInWindow: 0,
    totalProxyMbUsed: 0,
    usagePeriod: currentPeriod(),
    monthlyMinutesUsed: 0,
    dailyUsage: {},
    imagesDate: todayKey(),
    imagesUsedToday: 0,
    signupIp: ip,
    stripeCustomerId: null,
    // Opt-in defaults to false (unchecked on the signup form) — genuine
    // opt-in rather than a pre-checked box, for GDPR/CAN-SPAM hygiene.
    marketingOptIn: !!marketingOptIn,
    emailVerified: false,
    emailVerifyToken: crypto.randomBytes(32).toString('hex'),
    emailVerifyTokenExpiresAt: new Date(Date.now() + EMAIL_VERIFY_TOKEN_TTL_MS).toISOString(),
    lastVerificationEmailSentAt: new Date().toISOString(),
    createdAt: new Date().toISOString(),
  };
  issueToken(user);
  data.users.push(user);
  db.writeDB(data);

  // Best-effort — a slow/failed email provider should never block signup
  // itself. sendEmail() already swallows its own errors and logs them.
  await sendEmail(user.email, 'Verify your ViralCut email', buildVerifyEmailHtml(user));

  res.json(publicUser(user, true));
});

// Triggered by the link in the verification email — GET, not POST, since
// it's meant to be opened directly from an inbox (same pattern already used
// by /api/admin/set-plan below). Redirects back to the frontend with a
// ?verified= flag so index.html can show a toast; falls back to plain JSON
// if CLIENT_URL isn't set.
app.get('/api/verify-email', (req, res) => {
  const redirectBase = (process.env.CLIENT_URL || '').replace(/\/$/, '');
  const token = req.query.token;
  const goTo = (flag) => redirectBase
    ? res.redirect(`${redirectBase}/?verified=${flag}`)
    : res.status(flag === '1' ? 200 : 400).json({ verified: flag === '1' });

  if(!token) return goTo('0');

  const data = db.readDB();
  const user = data.users.find(u => u.emailVerifyToken === token);
  if(!user) return goTo('0');

  const expiresAt = user.emailVerifyTokenExpiresAt ? new Date(user.emailVerifyTokenExpiresAt).getTime() : 0;
  if(Date.now() > expiresAt) return goTo('expired');

  user.emailVerified = true;
  delete user.emailVerifyToken;
  delete user.emailVerifyTokenExpiresAt;
  db.writeDB(data);
  return goTo('1');
});

// Lets a signed-in-but-unverified user request a fresh link (the first one
// may have expired, landed in spam, or gone to an inbox they checked from a
// different device). Throttled per user so the resend button can't be
// spammed into hammering the email provider.
app.post('/api/resend-verification', requireAuth, async (req, res) => {
  const data = db.readDB();
  const user = data.users.find(u => u.id === req.user.id);
  if(!user) return res.status(401).json({ error: 'Not signed in' });
  if(user.emailVerified) return res.json({ ok: true, alreadyVerified: true });

  const lastSent = user.lastVerificationEmailSentAt ? new Date(user.lastVerificationEmailSentAt).getTime() : 0;
  if(Date.now() - lastSent < VERIFICATION_EMAIL_MIN_INTERVAL_MS){
    return res.status(429).json({ error: 'A verification email was just sent — check your inbox (and spam folder) before requesting another.' });
  }

  user.emailVerifyToken = crypto.randomBytes(32).toString('hex');
  user.emailVerifyTokenExpiresAt = new Date(Date.now() + EMAIL_VERIFY_TOKEN_TTL_MS).toISOString();
  user.lastVerificationEmailSentAt = new Date().toISOString();
  db.writeDB(data);

  const sent = await sendEmail(user.email, 'Verify your ViralCut email', buildVerifyEmailHtml(user));
  res.json({ ok: true, sent });
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
 * Records usage after a completed render and enforces plan limits.
 *
 * source: 'upload' | 'youtube'. Uploads never touch the proxy, so free-
 * plan users get a recurring allowance (10 every 4 days — see
 * FREE_UPLOAD_LIMIT_PER_WINDOW above). YouTube-link jobs always pull
 * bandwidth through the paid residential proxy, so they're paid-plans-only
 * regardless of plan or window — free users are rejected outright, no
 * uploads consumed either way.
 *
 * proxyMbUsed: how much bandwidth THIS job pulled through the proxy (0
 * for uploads, the downloaded source video's size for YouTube links).
 * Accumulated per user regardless of plan, so paid users' proxy usage is
 * visible on the admin stats dashboard below.
 */
app.post('/api/consume-usage', requireAuth, (req, res) => {
  const source = req.body.source === 'youtube' ? 'youtube' : 'upload';
  const proxyMbUsed = Math.max(0, Number(req.body.proxyMbUsed) || 0);
  const sourceMinutes = Math.max(0, Number(req.body.sourceMinutes) || 0);

  const data = db.readDB();
  const user = data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(401).json({ error: 'Not signed in' });

  if (source === 'youtube' && user.plan === 'free') {
    return res.status(402).json({
      error: 'Pasting a YouTube link requires a paid plan — try uploading a file instead (free), or subscribe to unlock links.',
    });
  }

  if (user.plan === 'free' && !user.emailVerified) {
    return res.status(403).json({
      error: 'Verify your email to use your free uploads — check your inbox for the link, or request a new one from your account.',
      needsVerification: true,
    });
  }

  if (user.plan === 'free') {
    ensureFreeUploadWindow(user);
    const used = user.freeUploadsUsedInWindow || 0;
    if (used >= FREE_UPLOAD_LIMIT_PER_WINDOW) {
      return res.status(402).json({
        error: `You've used all ${FREE_UPLOAD_LIMIT_PER_WINDOW} free uploads for this 4-day window — it refills ${freeUploadWindowResetAt(user)}, or subscribe for unlimited uploads plus YouTube-link clipping.`,
        freeUploadTriesRemaining: 0,
        freeUploadWindowResetAt: freeUploadWindowResetAt(user),
      });
    }
    user.freeUploadsUsedInWindow = used + 1;
  } else {
    // Paid plan — enforce the monthly source-video minute cap AND the
    // monthly proxy-MB cap. Both checked (and consumed) after the render
    // completes, same as the free-tier allowance above — this is metering,
    // not a hard pre-flight gate, since neither a source video's length nor
    // its actual downloaded size is known until after the job has already
    // run. The proxy cap exists alongside the minute cap (not instead of
    // it) because an unusually high-bitrate video can blow the proxy
    // budget without ever tripping the minute cap — see
    // PLAN_PROXY_MB_LIMITS above for where the numbers come from.
    ensureCurrentPeriod(user);
    const minutesCap = PLAN_MONTHLY_MINUTES[user.plan];
    if (minutesCap && user.monthlyMinutesUsed + sourceMinutes > minutesCap) {
      return res.status(402).json({
        error: `You've reached your plan's ${minutesCap}-minute monthly limit of source video — upgrade for more, or it resets next month.`,
        monthlyMinutesUsed: Math.round(user.monthlyMinutesUsed * 10) / 10,
        monthlyMinutesCap: minutesCap,
      });
    }
    const proxyCap = PLAN_PROXY_MB_LIMITS[user.plan];
    if (source === 'youtube' && proxyCap && user.proxyMbUsedThisPeriod + proxyMbUsed > proxyCap) {
      return res.status(402).json({
        error: `You've reached your plan's ${proxyCap}MB monthly proxy limit for YouTube-link clipping — upgrade for more, or it resets next month.`,
        proxyMbUsedThisPeriod: Math.round(user.proxyMbUsedThisPeriod * 10) / 10,
        proxyMbCap: proxyCap,
      });
    }
    // Site-wide circuit breaker — checked after the per-user cap so someone
    // who's already hit their own limit sees that message, not this one.
    // This is the one check that bounds the TOTAL Decodo bill no matter how
    // many paid users are active this month (see PROXY_MONTHLY_MB_CAP_
    // SITEWIDE above).
    if (source === 'youtube' && proxyMbUsed > 0) {
      const proxyBudget = ensureProxyBudget(data);
      if (proxyBudget.mbUsed + proxyMbUsed > PROXY_MONTHLY_MB_CAP_SITEWIDE) {
        return res.status(429).json({
          error: `YouTube-link clipping has hit its site-wide monthly proxy budget — it resets on the 1st. This is a cost-safety limit while the site is growing, not a per-user issue. Uploading your own video still works normally.`,
        });
      }
      proxyBudget.mbUsed = Math.round((proxyBudget.mbUsed + proxyMbUsed) * 100) / 100;
    }
    user.monthlyMinutesUsed = Math.round((user.monthlyMinutesUsed + sourceMinutes) * 100) / 100;
    user.proxyMbUsedThisPeriod = Math.round((user.proxyMbUsedThisPeriod + proxyMbUsed) * 100) / 100;
  }

  user.totalProxyMbUsed = (user.totalProxyMbUsed || 0) + proxyMbUsed;
  recordDailyUsage(user, { minutes: sourceMinutes, proxyMb: proxyMbUsed });

  db.writeDB(data);
  res.json(publicUser(user));
});

/**
 * Records one AI Images (Gemini) generation against the user's daily cap.
 * Called by tools.html right after a successful /generate-image call to
 * the pipeline — recorded after the fact (not as a hard pre-flight lock)
 * same as /api/consume-usage above, so a request that's right at the
 * boundary doesn't need a second round-trip before the actual generation.
 * AI Images is paid-plans-only (see tools.html), so free-plan users are
 * rejected here too, not just client-side.
 */
app.post('/api/consume-image-generation', requireAuth, (req, res) => {
  const data = db.readDB();
  const user = data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(401).json({ error: 'Not signed in' });

  if (user.plan === 'free') {
    return res.status(402).json({ error: 'AI Images requires a paid plan — subscribe to unlock it.' });
  }

  ensureImageDay(user);
  const cap = PLAN_IMAGE_DAILY_LIMITS[user.plan] || 0;
  if (user.imagesUsedToday >= cap) {
    return res.status(402).json({
      error: `You've used all ${cap} AI Images generations included in your plan today — it resets tomorrow, or upgrade for more.`,
      imagesUsedToday: user.imagesUsedToday,
      imagesDailyCap: cap,
    });
  }

  // Site-wide hard ceiling — checked after the per-user cap so someone who's
  // hit their own daily limit sees that message, not this one. This is the
  // check that actually bounds the total Gemini bill, regardless of how many
  // paying users are on the site (see GEMINI_MONTHLY_IMAGE_CAP above).
  const budget = ensureGeminiBudget(data);
  if (budget.imagesGenerated >= GEMINI_MONTHLY_IMAGE_CAP) {
    return res.status(429).json({
      error: `AI Images has hit its site-wide monthly budget cap — it resets on the 1st. This is a cost-safety limit while the site is growing, not a per-user issue.`,
    });
  }

  user.imagesUsedToday += 1;
  budget.imagesGenerated += 1;

  db.writeDB(data);
  res.json(publicUser(user));
});

// AI Videos (D-ID) monthly cap — same shape as consume-image-generation
// above, just monthly instead of daily since D-ID's shared free budget is
// only ~5 minutes for the whole site per month. Called after a
// /generate-avatar-video call actually succeeds (see tools.html) so a
// failed/moderation-rejected attempt doesn't cost the user their quota.
app.post('/api/consume-video-generation', requireAuth, (req, res) => {
  const data = db.readDB();
  const user = data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(401).json({ error: 'Not signed in' });

  const cap = PLAN_VIDEO_MONTHLY_LIMITS[user.plan] || 0;
  if (cap === 0) {
    return res.status(402).json({ error: 'AI Videos requires a Pro or Elite plan — upgrade to unlock it.' });
  }

  ensureVideoMonth(user);
  if (user.videosUsedThisMonth >= cap) {
    return res.status(402).json({
      error: `You've used all ${cap} AI Videos included in your plan this month — it resets next month, or upgrade for more.`,
      videosUsedThisMonth: user.videosUsedThisMonth,
      videosMonthlyCap: cap,
    });
  }
  user.videosUsedThisMonth += 1;

  db.writeDB(data);
  res.json(publicUser(user));
});

// ---------------------------------------------------------------------------
// Admin stats — a minimal, live "database view" of paying users and profit,
// gated by a single shared secret (ADMIN_KEY, set in Railway variables).
// Not a real auth system — fine for a solo founder checking numbers, not
// something to hand out to a team. Cost figures mirror the profit-model
// spreadsheet's Pricing Tiers tab (Decodo $3.00/GB + Deepgram + Claude +
// ElevenLabs + Railway + Stripe fee, at $19/$49/$129 pricing) — update
// both places together if pricing or vendor rates change.
// ---------------------------------------------------------------------------
function requireAdmin(req, res, next){
  const key = req.headers['x-admin-key'] || req.query.key;
  if(!process.env.ADMIN_KEY || key !== process.env.ADMIN_KEY){
    return res.status(401).json({ error: 'Not authorized' });
  }
  next();
}

// Repriced Aug 2026 — ~15-20% under Crayo's $19/$39/$79 equivalent tiers.
// PLAN_EST_COST = Deepgram ($0.0043/min) + Decodo ($3/GB, 6MB/min) at each
// plan's full minute cap + Stripe fee (2.9%+$0.30) + ~$1-2 Railway/misc
// overhead + D-ID video cost at full usage. Does NOT include Gemini Images —
// that's a flat $50/mo SITE-WIDE cap (see GEMINI_MONTHLY_IMAGE_BUDGET_USD
// above), not a per-user cost, so it's tracked separately in usageTotals
// rather than folded into each plan's margin here.
const PLAN_PRICES = { starter: 16, pro: 34, elite: 69 };

// PLAN_EST_COST_FULL_PRICE is the original estimate (Deepgram + Decodo AT
// FULL, UNCACHED PRICE + Stripe fee + Railway/misc + D-ID), from before the
// pipeline had a source-video cache or a free-proxy-tier fallback. Actual
// PLAN_EST_COST below subtracts however much of that original Decodo line
// item PROXY_CACHE_SAVINGS_FACTOR (above) says should now be saved — so the
// admin profit numbers reflect the real infra, not the pre-caching estimate.
const PLAN_EST_COST_FULL_PRICE = { starter: 3.95, pro: 11.95, elite: 35.08 };
const PLAN_EST_COST = Object.fromEntries(
  Object.entries(PLAN_EST_COST_FULL_PRICE).map(([plan, fullCost]) => {
    const fullDecodoMb = PLAN_MONTHLY_MINUTES[plan] * PROXY_MB_PER_SOURCE_MINUTE;
    const fullDecodoCostUsd = (fullDecodoMb / 1024) * DECODO_COST_PER_GB_USD;
    const savedUsd = fullDecodoCostUsd * (1 - PROXY_CACHE_SAVINGS_FACTOR);
    return [plan, Math.round((fullCost - savedUsd) * 100) / 100];
  })
);

// Rolls every user's per-day usage log into a single date-sorted table —
// one row per day across the last `days` days, totaled across all users.
// Powers the "Daily Usage" tab in the stats Sheet.
function buildDailyUsageRollup(users, days){
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  const byDay = {};
  for(const u of users){
    if(!u.dailyUsage) continue;
    for(const [day, stats] of Object.entries(u.dailyUsage)){
      if(new Date(`${day}T00:00:00Z`).getTime() < cutoff) continue;
      const row = byDay[day] || { minutes: 0, proxyMb: 0, jobs: 0, activeUsers: 0 };
      row.minutes += stats.minutes || 0;
      row.proxyMb += stats.proxyMb || 0;
      row.jobs += stats.jobs || 0;
      row.activeUsers += 1;
      byDay[day] = row;
    }
  }
  return Object.entries(byDay)
    .map(([date, row]) => ({
      date,
      minutes: Math.round(row.minutes * 10) / 10,
      proxyMb: Math.round(row.proxyMb * 10) / 10,
      jobs: row.jobs,
      activeUsers: row.activeUsers,
    }))
    .sort((a, b) => a.date.localeCompare(b.date));
}

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const data = db.readDB();
  const paidUsers = data.users.filter(u => u.plan && u.plan !== 'free');

  const byPlan = {};
  for(const plan of Object.keys(PLAN_PRICES)){
    const users = paidUsers.filter(u => u.plan === plan);
    byPlan[plan] = {
      count: users.length,
      mrr: Math.round(users.length * PLAN_PRICES[plan] * 100) / 100,
      estMonthlyCost: Math.round(users.length * PLAN_EST_COST[plan] * 100) / 100,
      estMonthlyProfit: Math.round(users.length * (PLAN_PRICES[plan] - PLAN_EST_COST[plan]) * 100) / 100,
    };
  }
  const totals = Object.values(byPlan).reduce((acc, p) => ({
    mrr: acc.mrr + p.mrr,
    estMonthlyCost: acc.estMonthlyCost + p.estMonthlyCost,
    estMonthlyProfit: acc.estMonthlyProfit + p.estMonthlyProfit,
  }), { mrr: 0, estMonthlyCost: 0, estMonthlyProfit: 0 });

  // Site-wide usage totals — sums each paid user's actual usage against
  // the total budget their plan allots them, so "how much proxy/images/
  // video is left across the whole site" is a single glance instead of
  // scrolling every row of the Paying Users sheet and adding it up by hand.
  const usageTotals = paidUsers.reduce((acc, u) => {
    acc.proxyMbUsed += effectiveProxyMbThisPeriod(u);
    acc.proxyMbCap += PLAN_PROXY_MB_LIMITS[u.plan] || 0;
    acc.imagesUsedToday += effectiveImagesToday(u);
    acc.imagesDailyCap += PLAN_IMAGE_DAILY_LIMITS[u.plan] || 0;
    acc.videosUsedThisMonth += effectiveVideosThisMonth(u);
    acc.videosMonthlyCap += PLAN_VIDEO_MONTHLY_LIMITS[u.plan] || 0;
    return acc;
  }, { proxyMbUsed: 0, proxyMbCap: 0, imagesUsedToday: 0, imagesDailyCap: 0, videosUsedThisMonth: 0, videosMonthlyCap: 0 });
  usageTotals.proxyMbUsed = Math.round(usageTotals.proxyMbUsed * 10) / 10;
  usageTotals.proxyMbRemaining = Math.round((usageTotals.proxyMbCap - usageTotals.proxyMbUsed) * 10) / 10;
  usageTotals.imagesRemainingToday = usageTotals.imagesDailyCap - usageTotals.imagesUsedToday;
  usageTotals.videosRemainingThisMonth = usageTotals.videosMonthlyCap - usageTotals.videosUsedThisMonth;

  // Site-wide Gemini spend ceiling (separate from the per-user daily caps
  // above) — lets the admin view show at a glance how close the site is to
  // its hard monthly cost cap, not just each user's own quota.
  const geminiImagesThisMonth = effectiveGeminiImagesThisMonth(data);
  usageTotals.geminiImagesUsedThisMonth = geminiImagesThisMonth;
  usageTotals.geminiImagesMonthlyCap = GEMINI_MONTHLY_IMAGE_CAP;
  usageTotals.geminiImagesRemainingThisMonth = GEMINI_MONTHLY_IMAGE_CAP - geminiImagesThisMonth;
  usageTotals.geminiBudgetUsedUsd = Math.round(geminiImagesThisMonth * GEMINI_IMAGE_COST_USD * 100) / 100;
  usageTotals.geminiBudgetCapUsd = GEMINI_MONTHLY_IMAGE_BUDGET_USD;

  // Site-wide proxy spend circuit breaker (see PROXY_MONTHLY_MB_CAP_SITEWIDE
  // above) — same shape as the Gemini budget fields, so the admin view shows
  // both hard cost ceilings at a glance.
  const proxyMbThisMonthSitewide = effectiveProxyMbThisMonthSitewide(data);
  usageTotals.proxyBudgetUsedUsd = Math.round((proxyMbThisMonthSitewide / 1024) * DECODO_COST_PER_GB_USD * 100) / 100;
  usageTotals.proxyBudgetCapUsd = PROXY_MONTHLY_BUDGET_USD;
  usageTotals.proxyBudgetMbUsedThisMonth = Math.round(proxyMbThisMonthSitewide * 10) / 10;
  usageTotals.proxyBudgetMbCapThisMonth = Math.round(PROXY_MONTHLY_MB_CAP_SITEWIDE * 10) / 10;

  // Email verification + marketing-list visibility — how many accounts are
  // actually confirmed-real, and how many opted into marketing emails (the
  // list you'd actually be allowed to send a campaign to).
  usageTotals.verifiedUsers = data.users.filter(u => u.emailVerified).length;
  usageTotals.unverifiedUsers = data.users.length - usageTotals.verifiedUsers;
  usageTotals.marketingOptInUsers = data.users.filter(u => u.marketingOptIn).length;

  // totals.estMonthlyProfit only nets out each plan's own per-user variable
  // cost (PLAN_EST_COST) — it doesn't touch the SHARED site-wide budgets
  // (Gemini Images, proxy), which are real spend but aren't attributed to
  // any one plan. netEstMonthlyProfit is the more honest "what's actually
  // left over" number: gross MRR, minus per-user variable costs, minus
  // this month's ACTUAL shared spend (not the cap — actual usage, so this
  // stays accurate even on a month nobody maxes either budget out).
  const netEstMonthlyProfit = Math.round(
    (totals.estMonthlyProfit - usageTotals.geminiBudgetUsedUsd - usageTotals.proxyBudgetUsedUsd) * 100
  ) / 100;

  res.json({
    generatedAt: new Date().toISOString(),
    totalUsers: data.users.length,
    freeUsers: data.users.length - paidUsers.length,
    paidUserCount: paidUsers.length,
    paidUsers: paidUsers
      .map(u => ({
        email: u.email,
        plan: u.plan,
        joinedAt: u.createdAt,
        totalProxyMbUsed: Math.round((u.totalProxyMbUsed || 0) * 10) / 10,
        proxyMbUsedThisPeriod: Math.round(effectiveProxyMbThisPeriod(u) * 10) / 10,
        proxyMbCap: PLAN_PROXY_MB_LIMITS[u.plan] || null,
        monthlyMinutesUsed: Math.round(effectiveMonthlyMinutes(u) * 10) / 10,
        monthlyMinutesCap: PLAN_MONTHLY_MINUTES[u.plan] || null,
        imagesUsedToday: effectiveImagesToday(u),
        imagesDailyCap: PLAN_IMAGE_DAILY_LIMITS[u.plan] || null,
        videosUsedThisMonth: effectiveVideosThisMonth(u),
        videosMonthlyCap: PLAN_VIDEO_MONTHLY_LIMITS[u.plan] || null,
      }))
      .sort((a, b) => new Date(b.joinedAt) - new Date(a.joinedAt)),
    byPlan,
    totals: { ...totals, netEstMonthlyProfit },
    usageTotals,
    dailyUsage: buildDailyUsageRollup(data.users, 30),
  });
});

// Manual plan override — for comping/testing an account without a real
// Stripe checkout (e.g. the founder testing their own paid-tier features).
// Gated by its own secret (SET_PLAN_KEY) rather than ADMIN_KEY so it can be
// handed out narrowly. GET (not POST) is deliberate here: this is meant to
// be triggered by opening a link, same as /api/admin/stats already is.
app.get('/api/admin/set-plan', (req, res) => {
  const key = req.query.key;
  if (!process.env.SET_PLAN_KEY || key !== process.env.SET_PLAN_KEY) {
    return res.status(401).json({ error: 'Not authorized' });
  }
  const email = (req.query.email || '').toLowerCase();
  const plan = req.query.plan;
  if (!['free', 'starter', 'pro', 'elite'].includes(plan)) {
    return res.status(400).json({ error: 'plan must be one of free|starter|pro|elite' });
  }
  const data = db.readDB();
  const user = data.users.find(u => u.email.toLowerCase() === email);
  if (!user) {
    return res.status(404).json({ error: `No account found for ${email}` });
  }
  user.plan = plan;
  db.writeDB(data);
  res.json({ ok: true, email: user.email, plan: user.plan });
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
