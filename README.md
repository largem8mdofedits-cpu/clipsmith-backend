# Clipsmith — Stripe backend

This is the minimum backend needed to take real payments on the Clipsmith site:
a Checkout session creator, a webhook listener, and a billing-portal link.
It does **not** include user accounts/auth or the video-processing pipeline —
see the bottom of this file for that.

## 0. What's already working (no setup needed)

Sign up, sign in, sessions, and the dashboard are fully built and tested —
they just need `npm install` and a run, no Stripe keys required for this part:

```bash
cd clipsmith-backend
npm install
cp .env.example .env
# SESSION_SECRET is the only value you need to fill in to test auth —
# generate one with:
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
npm run dev
```

Then open `clipsmith.html` in a browser, click **Sign in → Create account**,
and you'll land on `dashboard.html` with a live free-hour countdown and plan
badge. Accounts are stored in `clipsmith-backend/data.json` (a simple
file-based store — see the comment at the top of `db.js` for the upgrade
path to a real database later). Passwords are hashed with bcrypt, sessions
use signed, httpOnly cookies.

The rest of this file covers Stripe, which is the only piece still using
placeholder keys.

## 1. Create your Stripe account

1. Go to https://dashboard.stripe.com/register and sign up.
2. You'll start in **Test mode** (toggle top-right) — build and test everything
   here first. Nothing charges real cards in test mode.

## 2. Get your API key

1. Dashboard → **Developers → API keys**.
2. Copy the **Secret key** (starts `sk_test_...`).
3. Paste it into `.env` as `STRIPE_SECRET_KEY`.

Never put the secret key in frontend code — it only belongs on this backend.

## 3. Create your products and prices

Dashboard → **Product catalog → Add product**. Create three products:

- **Starter**
- **Pro**
- **Elite**

For each product, add **two prices**: one recurring **monthly**, one recurring
**yearly** (yearly = monthly × 12 × 0.8 for your 20% discount, e.g. Pro
monthly $39 → yearly $374.40, or round to $375).

After saving, each price has an ID like `price_1PxYzABC123`. Copy all six
into your `.env` file (`PRICE_STARTER_MONTHLY`, `PRICE_STARTER_YEARLY`, etc).

## 4. Install and run

```bash
cd clipsmith-backend
npm install
cp .env.example .env   # then fill in your real keys/price IDs
npm run dev             # starts on http://localhost:4242
```

## 5. Test webhooks locally with the Stripe CLI

Webhooks are how Stripe tells your backend "this person paid" or
"this subscription was cancelled" — critical for knowing who has access.

```bash
# install: https://docs.stripe.com/stripe-cli
stripe login
stripe listen --forward-to localhost:4242/api/stripe-webhook
```

This prints a `whsec_...` value — put that in `.env` as `STRIPE_WEBHOOK_SECRET`.
Leave `stripe listen` running while you test.

## 6. Test a full checkout

With the backend running, trigger a test checkout:

```bash
curl -X POST http://localhost:4242/api/create-checkout-session \
  -H "Content-Type: application/json" \
  -d '{"plan":"pro","billing":"monthly"}'
```

You'll get back `{ "url": "https://checkout.stripe.com/..." }`. Open that URL
and pay with Stripe's test card: **4242 4242 4242 4242**, any future expiry,
any CVC, any ZIP. Watch your `stripe listen` terminal — you should see the
`checkout.session.completed` event come through.

## 7. Connect the frontend

In `clipsmith.html`, the pricing buttons now call `startCheckout(plan)`.
Near the top of the `<script>` block, set:

```js
const BACKEND_URL = 'http://localhost:4242'; // swap for your deployed URL later
```

Clicking "Get Pro" etc. will call your backend, get a Checkout URL back, and
redirect the browser there.

## 8. Deploy the backend

Any Node host works — Render, Railway, Fly.io, or a small VPS are the
easiest for a project this size:

1. Push this folder to its own GitHub repo.
2. Connect it to Render/Railway, set the same env vars from `.env` in their
   dashboard (never commit your real `.env` file).
3. Once deployed, go back to Stripe Dashboard → **Developers → Webhooks →
   Add endpoint**, point it at `https://your-backend-url.com/api/stripe-webhook`,
   and select events: `checkout.session.completed`,
   `customer.subscription.updated`, `customer.subscription.deleted`,
   `invoice.payment_failed`. Copy the signing secret it gives you into your
   production env vars as `STRIPE_WEBHOOK_SECRET`.
4. Update `BACKEND_URL` in `clipsmith.html` to your deployed backend URL, and
   `CLIENT_URL` in your backend env to your deployed frontend URL.

## 9. Go live

Once test payments work end-to-end: Dashboard toggle → **Live mode**, repeat
steps 2–3 with your live keys and live price IDs, and update your deployed
env vars. That's it — real cards will now be charged.

---

## What's still missing (and why it's separate)

**User accounts** — ✅ done. Signup/login/sessions/dashboard all work now
(see section 0 above). The one thing intentionally left as a `TODO` in
`server.js` is deducting from `freeSecondsRemaining` as a user actually
renders clips — that needs to be wired up once real video processing exists,
since right now nothing in the app consumes render time yet.

**The actual AI clipping pipeline** — this is the real product, and it's
the one piece that still needs to be built. It needs, at minimum: video
ingestion (yt-dlp or similar for pasted links), storage (S3/R2), a
speech-to-text model (Whisper is the standard open option), a
highlight-detection step, `ffmpeg` for cutting/reframing/caption-burning,
and GPU compute to run it at reasonable speed. This is a multi-week build
on its own — happy to help you scope and build it piece by piece whenever
you're ready.
