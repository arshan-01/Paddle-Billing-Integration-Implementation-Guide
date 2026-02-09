# Paddle Billing Integration — Full Implementation Guide

This document lists **every endpoint**, includes **complete code** for Paddle-related backend and frontend, and describes flows, edge cases, and configuration. Use it as the single reference for all Paddle work.

---

## Table of contents

1. [All endpoints](#1-all-endpoints)
2. [Environment and configuration](#2-environment-and-configuration)
3. [Backend — Paddle service (full code)](#3-backend--paddle-service-full-code)
4. [Backend — Discount service (full code)](#4-backend--discount-service-full-code)
5. [Backend — Subscription routes, schema, controller (code)](#5-backend--subscription-routes-schema-controller-code)
6. [Backend — Webhook (full code)](#6-backend--webhook-full-code)
7. [Backend — Discount routes, controller, model (code)](#7-backend--discount-routes-controller-model-code)
8. [Backend — Models and config](#8-backend--models-and-config)
9. [Frontend — Subscription API (full code)](#9-frontend--subscription-api-full-code)
10. [Frontend — Subscription page (key code)](#10-frontend--subscription-page-key-code)
11. [Edge cases and checklist](#11-edge-cases-and-checklist)

---

## 1. All endpoints

Every Paddle-related endpoint. Base URL is your API root (e.g. `https://api.example.com`). Auth = cookie/session unless noted.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/subscription/plans` | Yes | List plans (free, pro, plus, agency) with prices and features |
| GET | `/api/subscription/current` | Yes | Current subscription + `active_discount`; optional `?channelId=` for billing context |
| GET | `/api/subscription/usage` | Yes | Usage and limits for billing period; optional `?channelId=` |
| POST | `/api/subscription/upgrade` | Yes | Body: `{ plan, interval }`. Returns `checkoutUrl` or in-place result |
| POST | `/api/subscription/cancel` | Yes | Cancel subscription (owner only) |
| GET | `/api/subscription/billing` | Yes | List recent transactions for current user |
| POST | `/api/subscription/billing-portal` | Yes | Returns `{ url }` for Paddle customer portal |
| POST | `/api/subscription/resume` | Yes | Resume subscription scheduled to cancel (owner only) |
| POST | `/api/webhooks/paddle` | No (signature) | Paddle webhook; body must be raw for signature verification |
| GET | `/api/discounts/analytics` | Yes (admin) | Discount conversion analytics by trigger |

**Route mounting (server):**

- Subscription: `apiRouter.use("/subscription", subscriptionRouter)` → paths above under `/api/subscription/*`
- Webhooks: `apiRouter.use("/webhooks", webhookRouter)` + `webhookRouter.post("/paddle", ...)` → `POST /api/webhooks/paddle`
- Webhook raw body: `app.use("/api/webhooks/paddle", express.raw({ type: "application/json" }))` must be registered before `app.use("/api", apiRouter)` so the webhook receives raw body for signature verification.
- Discounts: `apiRouter.use("/discounts", discountRouter)` → `/api/discounts/analytics`

---

## 2. Environment and configuration

**Required:**

- `PADDLE_API_KEY` — API key (sandbox or production)
- `PADDLE_ENVIRONMENT` — `sandbox` or `production`
- `PADDLE_WEBHOOK_SECRET` — Webhook signature verification

**Price IDs (all same environment as API key):**

- `PADDLE_PRICE_PRO`, `PADDLE_PRICE_PRO_YEARLY`
- `PADDLE_PRICE_PLUS`, `PADDLE_PRICE_PLUS_YEARLY`
- `PADDLE_PRICE_AGENCY`
- Optional trial: `PADDLE_PRICE_PRO_TRIAL`, `PADDLE_PRICE_PRO_YEARLY_TRIAL`, `PADDLE_PRICE_PLUS_TRIAL`, `PADDLE_PRICE_PLUS_YEARLY_TRIAL`

**Discount (optional):**

- `DISCOUNT_SYSTEM_ENABLED` — default enabled if not `"false"`
- `DISCOUNT_PERCENT_OFF_USAGE_LIMIT`, `DISCOUNT_PERCENT_OFF_LOCKED_FEATURE`, `DISCOUNT_PERCENT_OFF_ABANDONED`, `DISCOUNT_PERCENT_OFF_INACTIVITY`
- `DISCOUNT_VALIDITY_DAYS`, `DISCOUNT_COOLDOWN_DAYS`

**App:**

- `FRONTEND_BASE_URL` (or `WEB_APP_URL` / `FRONTEND_URL`) — used for checkout success/cancel URLs and billing portal return URL.

---

## 3. Backend — Paddle service (full code)

**File:** `server/src/services/paddle.js`

```javascript
import crypto from "crypto";
import { config } from "../config/env.js";

const SANDBOX_BASE_URL = "https://sandbox-api.paddle.com";
const PROD_BASE_URL = "https://api.paddle.com";
const PROD_PORTAL_HOST = "https://customer-portal.paddle.com";
const SANDBOX_PORTAL_HOST = "https://sandbox-customer-portal.paddle.com";

function getPaddleBaseUrl() {
  const env = (config.paddle?.environment || "production").toLowerCase();
  return env === "sandbox" ? SANDBOX_BASE_URL : PROD_BASE_URL;
}

function isPaddleSandbox() {
  return (config.paddle?.environment || "production").toLowerCase() === "sandbox";
}

function rewritePortalUrlsForEnv(obj) {
  if (!obj || !isPaddleSandbox()) return obj;
  const out = Array.isArray(obj)
    ? obj.map((item) => rewritePortalUrlsForEnv(item))
    : typeof obj === "string"
      ? obj.replace(new RegExp(escapeRegex(PROD_PORTAL_HOST), "g"), SANDBOX_PORTAL_HOST)
      : { ...obj };
  if (!Array.isArray(obj) && typeof obj === "object" && obj !== null) {
    for (const key of Object.keys(obj)) {
      out[key] = rewritePortalUrlsForEnv(obj[key]);
    }
  }
  return out;
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function requirePaddleApiKey() {
  if (!config.paddle?.apiKey) {
    throw new Error("PADDLE_API_KEY is not configured");
  }
  return config.paddle.apiKey;
}

async function paddleRequest(path, { method = "GET", body } = {}) {
  const apiKey = requirePaddleApiKey();
  const baseUrl = getPaddleBaseUrl();
  const url = `${baseUrl}${path}`;
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: body ? JSON.stringify(body) : undefined
  });

  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message = payload?.error?.message || payload?.message || "Paddle API request failed";
    const err = new Error(message);
    err.status = res.status;
    err.payload = payload;
    throw err;
  }

  return payload?.data ?? payload;
}

async function createPaddleCustomer({ email, name }) {
  return paddleRequest("/customers", {
    method: "POST",
    body: { email, name }
  });
}

async function createPaddleDiscount({ percentOff, targetPlan, expiresAt, description, userId }) {
  const restrictTo = getPriceIdsForPlan(targetPlan);
  const body = {
    description: description || `User discount (${percentOff}% off, ${targetPlan})`,
    type: "percentage",
    amount: String(Math.min(100, Math.max(0.01, percentOff))),
    mode: "custom",
    usage_limit: 1,
    recur: false,
    expires_at: expiresAt.toISOString(),
    restrict_to: restrictTo.length > 0 ? restrictTo : null,
    custom_data: { userId: String(userId) }
  };
  const res = await paddleRequest("/discounts", { method: "POST", body });
  const id = res?.id;
  if (!id) throw new Error("Paddle discount creation failed: no ID returned");
  return id;
}

function getPriceIdsForPlan(targetPlan) {
  const ids = [];
  if (targetPlan === "pro") {
    if (config.paddle?.pricePro) ids.push(config.paddle.pricePro);
    if (config.paddle?.priceProYearly) ids.push(config.paddle.priceProYearly);
  } else if (targetPlan === "plus") {
    if (config.paddle?.pricePlus) ids.push(config.paddle.pricePlus);
    if (config.paddle?.pricePlusYearly) ids.push(config.paddle.pricePlusYearly);
  }
  return ids.filter(Boolean);
}

async function createPaddleTransaction({
  customerId,
  priceId,
  quantity = 1,
  customData,
  successUrl,
  cancelUrl,
  discountId
}) {
  const body = {
    items: [{ price_id: priceId, quantity }],
    customer_id: customerId,
    custom_data: customData
  };
  if (discountId) body.discount_id = discountId;
  if (successUrl || cancelUrl) {
    body.checkout = {
      success_url: successUrl,
      cancel_url: cancelUrl
    };
  }
  return paddleRequest("/transactions", { method: "POST", body });
}

async function listPaddleTransactions({ customerId, perPage = 10 }) {
  const params = new URLSearchParams();
  if (customerId) params.set("customer_id", customerId);
  params.set("per_page", String(perPage));
  return paddleRequest(`/transactions?${params.toString()}`);
}

async function createCustomerPortalSession({ customerId, returnUrl, subscriptionIds }) {
  const body = {};
  if (subscriptionIds?.length) body.subscription_ids = subscriptionIds;
  const session = await paddleRequest(`/customers/${customerId}/portal-sessions`, {
    method: "POST",
    body: Object.keys(body).length ? body : undefined
  });
  return rewritePortalUrlsForEnv(session);
}

async function resumePaddleSubscription(subscriptionId) {
  return paddleRequest(`/subscriptions/${subscriptionId}/resume`, {
    method: "POST",
    body: { effective_from: "immediately" }
  });
}

async function cancelPaddleSubscription(subscriptionId, { effectiveFrom = "next_billing_period" } = {}) {
  return paddleRequest(`/subscriptions/${subscriptionId}/cancel`, {
    method: "POST",
    body: { effective_from: effectiveFrom }
  });
}

async function activatePaddleSubscription(subscriptionId) {
  return paddleRequest(`/subscriptions/${subscriptionId}/activate`, { method: "POST" });
}

function updatePaddleSubscription(subscriptionId, body) {
  return paddleRequest(`/subscriptions/${subscriptionId}`, { method: "PATCH", body });
}

function verifyPaddleSignature(rawBody, signatureHeader) {
  if (!config.paddle?.webhookSecret) {
    throw new Error("PADDLE_WEBHOOK_SECRET is not configured");
  }
  if (!signatureHeader) {
    throw new Error("Missing Paddle signature header");
  }
  const parts = signatureHeader.split(/[,;]/).reduce((acc, part) => {
    const [key, value] = part.split("=");
    if (key && value) acc[key.trim()] = value.trim();
    return acc;
  }, {});
  const timestamp = parts.ts;
  const signature = parts.h1;
  if (!timestamp || !signature) throw new Error("Invalid Paddle signature header");
  const signedPayload = `${timestamp}:${rawBody}`;
  const computed = crypto
    .createHmac("sha256", config.paddle.webhookSecret)
    .update(signedPayload)
    .digest("hex");
  if (computed.length !== signature.length) throw new Error("Invalid Paddle webhook signature");
  const isValid = crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(signature));
  if (!isValid) throw new Error("Invalid Paddle webhook signature");
  return true;
}

export {
  createCustomerPortalSession,
  createPaddleCustomer,
  createPaddleDiscount,
  createPaddleTransaction,
  listPaddleTransactions,
  activatePaddleSubscription,
  cancelPaddleSubscription,
  resumePaddleSubscription,
  updatePaddleSubscription,
  verifyPaddleSignature,
  isPaddleSandbox
};
```

---

## 4. Backend — Discount service (full code)

**File:** `server/src/services/discountService.js`

```javascript
import { User } from "../modules/user/user.model.js";
import { Subscription } from "../modules/subscription/subscription.model.js";
import { UserDiscount } from "../modules/discount/discount.model.js";
import { getPlanId } from "../config/limits.js";
import {
  DISCOUNT_COOLDOWN_DAYS,
  DISCOUNT_VALIDITY_DAYS,
  RECENT_DISCOUNT_DAYS,
  getDiscountRule
} from "../config/discountRules.js";
import { logger } from "../config/logger.js";
import { config } from "../config/env.js";
import { enqueueEmailEvent } from "./emailEvents.js";
import { discountOfferEmail, FEATURE_LABELS } from "./emailTemplates.js";
import { createPaddleDiscount } from "./paddle.js";

async function checkEligibility(userId, trigger, context = {}) {
  const user = await User.findById(userId).select("marketingConsent subscriptionPlan deleted").lean();
  if (!user || user.deleted) {
    return { eligible: false, reason: "user_not_found_or_deleted" };
  }

  const subscription = await Subscription.findOne({ userId }).lean();
  const planId = getPlanId(subscription);
  const rule = getDiscountRule(trigger);
  if (!rule) return { eligible: false, reason: "unknown_trigger" };
  const targetPlan = rule.targetPlan || "pro";
  const PLAN_ORDER = ["free", "pro", "plus", "agency"];
  if (PLAN_ORDER.indexOf(planId) >= PLAN_ORDER.indexOf(targetPlan)) {
    return { eligible: false, reason: "already_on_target_plan" };
  }

  if (user.marketingConsent === false) {
    return { eligible: false, reason: "no_marketing_consent" };
  }

  const now = new Date();
  const recentThreshold = new Date(now.getTime() - RECENT_DISCOUNT_DAYS * 24 * 60 * 60 * 1000);
  const cooldownThreshold = new Date(now.getTime() - DISCOUNT_COOLDOWN_DAYS * 24 * 60 * 60 * 1000);

  const existingActive = await UserDiscount.findOne({ userId, status: "active" }).lean();
  if (existingActive) return { eligible: false, reason: "active_discount_exists" };

  const recentOrUsed = await UserDiscount.findOne({
    userId,
    $or: [
      { status: "used", usedAt: { $gte: cooldownThreshold } },
      { status: "expired", updatedAt: { $gte: cooldownThreshold } },
      { createdAt: { $gte: recentThreshold } }
    ]
  }).lean();
  if (recentOrUsed) return { eligible: false, reason: "cooldown_or_recent_discount" };

  if (trigger === "usage_limit_reached" && context.usage !== undefined) {
    const minUsage = rule.minUsageThisPeriod ?? 1;
    if (context.usage < minUsage) return { eligible: false, reason: "insufficient_usage" };
  }

  return { eligible: true };
}

async function evaluateAndCreateDiscount(userId, trigger, context = {}) {
  if (!config.discount?.enabled) {
    logger.debug({ userId, trigger }, "Discount system disabled");
    return { created: false, reason: "system_disabled" };
  }
  const result = await checkEligibility(userId, trigger, context);
  if (!result.eligible) {
    logger.debug({ userId, trigger, reason: result.reason }, "Discount eligibility check failed");
    return { created: false, reason: result.reason };
  }

  const rule = getDiscountRule(trigger);
  if (!rule) return { created: false, reason: "unknown_trigger" };

  const targetPlan = rule.targetPlan || "pro";
  const percentOff = rule.percentOff ?? rule.amountOff ?? 20;
  const expiresAt = new Date(Date.now() + DISCOUNT_VALIDITY_DAYS * 24 * 60 * 60 * 1000);

  let paymentDiscountId;
  try {
    paymentDiscountId = await createPaddleDiscount({
      percentOff,
      targetPlan,
      expiresAt,
      description: `User discount: ${trigger} (${percentOff}% off ${targetPlan})`,
      userId
    });
  } catch (err) {
    logger.error({ userId, trigger, err: err.message }, "Paddle discount creation failed");
    return { created: false, reason: "paddle_discount_failed" };
  }

  if (!paymentDiscountId) {
    logger.error({ userId, trigger }, "Paddle discount creation returned no ID");
    return { created: false, reason: "paddle_discount_failed" };
  }

  try {
    const discount = await UserDiscount.create({
      userId,
      paymentProvider: "paddle",
      paymentDiscountId,
      trigger,
      targetPlan,
      discountType: rule.percentOff ? "percent_off" : "amount_off",
      discountValue: percentOff,
      expiresAt,
      status: "active",
      metadata: context
    });

    logger.info(
      { userId, discountId: discount._id, paymentDiscountId, trigger },
      "Discount created (Paddle + DB)"
    );

    if (paymentDiscountId && discount.status === "active") {
      const user = await User.findById(userId).select("email name").lean();
      if (user?.email) {
        const emailContext =
          trigger === "usage_limit_reached" && context.feature
            ? { ...context, featureLabel: FEATURE_LABELS[context.feature] || context.feature }
            : context;
        const { html, text, subject } = discountOfferEmail(user, trigger, rule, emailContext);
        await enqueueEmailEvent({
          eventId: `discount-offer:${userId}:${discount._id}`,
          type: "discount-offer",
          to: user.email,
          subject,
          text,
          html
        });
      }
    }

    return { created: true, discount };
  } catch (err) {
    const isDuplicateKey =
      err.code === 11000 ||
      err.writeErrors?.some?.((e) => e?.err?.code === 11000);
    if (isDuplicateKey) {
      logger.debug({ userId, trigger }, "Discount already exists (race condition)");
      return { created: false, reason: "already_exists" };
    }
    logger.error({ userId, trigger, err: err.message }, "Failed to create discount");
    return { created: false, reason: "creation_failed" };
  }
}

async function getActiveDiscount(userId) {
  const now = new Date();
  return UserDiscount.findOne({
    userId,
    status: "active",
    expiresAt: { $gt: now }
  }).lean();
}

async function markDiscountUsed(userId, discountId) {
  const discount = await UserDiscount.findOne({
    _id: discountId,
    userId,
    status: "active"
  });
  if (!discount) return false;
  discount.status = "used";
  discount.usedAt = new Date();
  await discount.save();
  logger.info({ userId, discountId, paymentDiscountId: discount.paymentDiscountId }, "Discount marked as used");
  return true;
}

async function markDiscountUsedByPaymentId(userId, paymentDiscountId) {
  const discount = await UserDiscount.findOne({
    userId,
    paymentDiscountId,
    status: "active"
  });
  if (!discount) return false;
  return markDiscountUsed(userId, discount._id);
}

export {
  checkEligibility,
  evaluateAndCreateDiscount,
  getActiveDiscount,
  markDiscountUsed,
  markDiscountUsedByPaymentId
};
```

---

## 5. Backend — Subscription routes, schema, controller (code)

**Routes:** `server/src/modules/subscription/subscription.route.js`

```javascript
import { Router } from "express";
import { validate } from "../../middlewares/validate.js";
import { requireAuth } from "../../middlewares/auth.js";
import { upgradeSubscriptionSchema, cancelSubscriptionSchema } from "./subscription.schema.js";
import { getPlans, getCurrent, upgrade, cancel, getBilling, createBillingPortal, resume, getUsageEndpoint } from "./subscription.controller.js";

const subscriptionRouter = Router();

subscriptionRouter.use(requireAuth);
subscriptionRouter.get("/plans", getPlans);
subscriptionRouter.get("/current", getCurrent);
subscriptionRouter.get("/usage", getUsageEndpoint);
subscriptionRouter.post("/upgrade", validate(upgradeSubscriptionSchema), upgrade);
subscriptionRouter.post("/cancel", validate(cancelSubscriptionSchema), cancel);
subscriptionRouter.get("/billing", getBilling);
subscriptionRouter.post("/billing-portal", createBillingPortal);
subscriptionRouter.post("/resume", resume);

export { subscriptionRouter };
```

**Schema:** `server/src/modules/subscription/subscription.schema.js`

```javascript
import { z } from "zod";

const upgradeSubscriptionSchema = z.object({
  body: z.object({
    plan: z.enum(["free", "pro", "plus", "agency"]),
    interval: z.enum(["monthly", "yearly"]).optional().default("monthly")
  }),
  query: z.object({}).optional(),
  params: z.object({}).optional()
});

const cancelSubscriptionSchema = z.object({
  body: z.object({}).optional(),
  query: z.object({}).optional(),
  params: z.object({}).optional()
});

export { upgradeSubscriptionSchema, cancelSubscriptionSchema };
```

**Controller — getCurrent (with active_discount):**

```javascript
const getCurrent = asyncHandler(async (req, res) => {
  const { billingUserId, billingOwnerName, isSharedContext } = await resolveBillingContext(req);
  const subscription = await Subscription.findOne({ userId: billingUserId }).lean();
  const payload = buildCanonicalSubscriptionResponse(
    subscription,
    billingUserId,
    billingOwnerName,
    isSharedContext
  );
  if (payload && !isSharedContext) {
    const activeDiscount = await getActiveDiscount(billingUserId);
    if (activeDiscount) {
      payload.active_discount = {
        discount_value: activeDiscount.discountValue,
        discount_type: activeDiscount.discountType,
        target_plan: activeDiscount.targetPlan,
        expires_at: activeDiscount.expiresAt
      };
    } else {
      payload.active_discount = null;
    }
  }
  return ok(res, payload, "Current plan fetched");
});
```

**Controller — upgrade (checkout path: attach discount only when plan matches; retry on discount_usage_limit_exceeded):**

```javascript
// No effective subscription: create first subscription via checkout transaction.
const priceIdToUse = hasUsedTrial || !trialPriceId ? paidPriceId : trialPriceId;

const billingUser = await User.findById(billingUserId).select("paddleCustomerId email name").lean();
let customerId = billingUser?.paddleCustomerId;
if (!customerId) {
  const customer = await createPaddleCustomer({
    email: billingUser?.email ?? req.user.email,
    name: billingUser?.name ?? req.user.name
  });
  customerId = customer?.id;
  if (!customerId) {
    throw new AppError("Failed to create Paddle customer", StatusCodes.INTERNAL_SERVER_ERROR);
  }
  await User.findByIdAndUpdate(billingUserId, { paddleCustomerId: customerId });
}

const activeDiscount = await getActiveDiscount(billingUserId);
const selectedPlan = req.body.plan;
const discountAppliesToSelectedPlan = activeDiscount && String(activeDiscount.targetPlan) === String(selectedPlan);
let discountId = discountAppliesToSelectedPlan ? (activeDiscount?.paymentDiscountId || null) : null;
if (discountAppliesToSelectedPlan && activeDiscount && !discountId) {
  logger.warn({ userId: billingUserId, discountId: activeDiscount._id }, "Discount has no paymentDiscountId — checkout will open without discount");
}
const customData = {
  userId: String(billingUserId),
  plan: req.body.plan,
  interval
};
if (discountId && activeDiscount?._id) {
  customData.discountId = String(activeDiscount._id);
}

let transaction;
try {
  transaction = await createPaddleTransaction({
    customerId,
    priceId: priceIdToUse,
    customData,
    discountId,
    successUrl: `${config.app.frontendBaseUrl}/subscription?success=1`,
    cancelUrl: `${config.app.frontendBaseUrl}/subscription?canceled=1`
  });
} catch (err) {
  const code = err?.payload?.error?.code;
  if (code === "discount_usage_limit_exceeded" && activeDiscount?._id) {
    await markDiscountUsed(billingUserId, String(activeDiscount._id));
    logger.info({ userId: billingUserId, discountId: activeDiscount._id }, "Discount exhausted in Paddle — marked used, retrying without discount");
    delete customData.discountId;
    transaction = await createPaddleTransaction({
      customerId,
      priceId: priceIdToUse,
      customData,
      discountId: null,
      successUrl: `${config.app.frontendBaseUrl}/subscription?success=1`,
      cancelUrl: `${config.app.frontendBaseUrl}/subscription?canceled=1`
    });
  } else {
    throw err;
  }
}

const checkoutUrl =
  transaction?.checkout_url ||
  transaction?.checkoutUrl ||
  transaction?.checkout?.url ||
  transaction?.checkout?.checkout_url ||
  transaction?.url;
if (!checkoutUrl) {
  throw new AppError("Paddle checkout URL not available", StatusCodes.INTERNAL_SERVER_ERROR);
}

return ok(res, { checkoutUrl }, "Checkout session created");
```

**Controller — createBillingPortal:**

```javascript
const createBillingPortal = asyncHandler(async (req, res) => {
  const customerId = req.user.paddleCustomerId;
  if (!customerId) {
    throw new AppError(
      "Billing portal is available after your first payment. Complete a subscription to manage billing.",
      StatusCodes.BAD_REQUEST
    );
  }
  const subscription = await Subscription.findOne({ userId: req.user._id }).select("paddleSubscriptionId").lean();
  const subscriptionIds = subscription?.paddleSubscriptionId ? [subscription.paddleSubscriptionId] : undefined;
  const session = await createCustomerPortalSession({
    customerId,
    returnUrl: `${config.app.frontendBaseUrl}/subscription`,
    subscriptionIds
  });
  const url =
    session?.urls?.general?.overview ||
    session?.url ||
    session?.customer_portal_url ||
    session?.portal_url ||
    session?.data?.urls?.general?.overview ||
    session?.data?.url;
  if (!url) {
    throw new AppError("Paddle customer portal URL not available", StatusCodes.INTERNAL_SERVER_ERROR);
  }
  return ok(res, { url }, "Billing portal created");
});
```

---

## 6. Backend — Webhook (full code)

**Route:** `yt-analytics-studio-server/src/modules/webhook/webhook.route.js`

```javascript
import { Router } from "express";
import { handlePaddleWebhook } from "./webhook.controller.js";

const webhookRouter = Router();
webhookRouter.post("/paddle", handlePaddleWebhook);
export { webhookRouter };
```

**Controller (signature, event parsing, transaction.paid/completed with discount mark-used, transaction failed/canceled/expired, subscription events, one-subscription invariant):**

**File:** `server/src/modules/webhook/webhook.controller.js` — behavior summary and critical code:

- **Verification:** Read `req.body` as raw (Buffer/string). Header `paddle-signature` or `Paddle-Signature`. Call `verifyPaddleSignature(rawBody, signature)`. On failure return `400` with message.
- **Parse:** `event = JSON.parse(rawBody)`. `eventType = event?.event_type || event?.eventType || event?.type`. `data = event?.data || {}`, `customData = data?.custom_data || data?.customData || {}`.
- **Resolve userId:** From `customData.userId`, else from `data.customer_id` via User lookup by `paddleCustomerId`, else for subscription.* from Subscription by `paddleSubscriptionId`.
- **Price/plan:** `priceId = data?.items?.[0]?.price_id || ...`. Map priceId to plan/interval via config (e.g. `resolvePlanIntervalFromPriceId`). Prefer inferred plan from price_id over custom_data.plan.
- **One-subscription invariant:** If user has existing effective subscription (active/trialing/cancelled_at_period_end) and `incomingPaddleSubscriptionId !== existingPaddleSubscriptionId`, return `res.json({ received: true, ignored: true })`.
- **transaction.paid / transaction.completed:** Update Subscription (plan, interval, price, currentPeriodEnd, paddleSubscriptionId, paddleTransactionId, status active if price > 0; clear nextPlan when plan matches). Update User (subscriptionPlan, paddleCustomerId). **Discount:** `discountId = customData?.discountId`, `paddleDiscountId = data?.discount_id || data?.discount?.id`. If `discountId` then `markDiscountUsed(userId, discountId)`; else if `paddleDiscountId` then `markDiscountUsedByPaymentId(userId, paddleDiscountId)`.
- **transaction.canceled / transaction.expired / transaction.failed:** Optionally `evaluateAndCreateDiscount(userId, "upgrade_flow_abandoned", { transactionId, plan })` (fire-and-forget).
- **transaction.expired / subscription.expired:** Set subscription to free, clear Paddle IDs.
- **subscription.created / subscription.updated** with status trialing: Do not overwrite if current status is already "active". Else update Subscription (status trialing, trialingEndsAt, plan from custom or existing).
- **subscription.canceled / subscription.updated:** Handle cancelled_at_period_end (nextPlan free, currentPeriodEnd) or immediate cancel (plan free, clear IDs). Also handle resumed/activated (status active, clear nextPlan).

(Full webhook controller is ~330 lines; the logic above is the exact behavior. Refer to `webhook.controller.js` in repo for the complete implementation.)

---

## 7. Backend — Discount routes, controller, model (code)

**Route:** `server/src/modules/discount/discount.route.js`

```javascript
import { Router } from "express";
import { requireAuth, requireAdmin } from "../../middlewares/auth.js";
import { getAnalytics } from "./discount.controller.js";

const discountRouter = Router();
discountRouter.get("/analytics", requireAuth, requireAdmin, getAnalytics);
export { discountRouter };
```

**Controller:** `server/src/modules/discount/discount.controller.js`

```javascript
const getAnalytics = asyncHandler(async (req, res) => {
  const triggers = [
    "usage_limit_reached",
    "locked_feature_accessed",
    "upgrade_flow_abandoned",
    "inactivity_after_usage"
  ];

  const byTrigger = {};
  for (const trigger of triggers) {
    const [created, used] = await Promise.all([
      UserDiscount.countDocuments({ trigger, status: { $in: ["active", "used", "expired"] } }),
      UserDiscount.countDocuments({ trigger, status: "used" })
    ]);
    byTrigger[trigger] = { created, used, conversionRate: created > 0 ? (used / created * 100).toFixed(1) + "%" : "0%" };
  }

  const [totalCreated, totalUsed, activeCount] = await Promise.all([
    UserDiscount.countDocuments({ status: { $in: ["active", "used", "expired"] } }),
    UserDiscount.countDocuments({ status: "used" }),
    UserDiscount.countDocuments({ status: "active", expiresAt: { $gt: new Date() } })
  ]);

  return ok(res, {
    byTrigger,
    summary: {
      totalCreated,
      totalUsed,
      activeCount,
      conversionRate: totalCreated > 0 ? (totalUsed / totalCreated * 100).toFixed(1) + "%" : "0%"
    }
  }, "Discount analytics");
});
```

**Model:** `server/src/modules/discount/discount.model.js`

```javascript
const discountSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    paymentDiscountId: { type: String, index: true },
    paymentProvider: { type: String, enum: ["paddle"], default: "paddle" },
    trigger: {
      type: String,
      enum: [
        "usage_limit_reached",
        "locked_feature_accessed",
        "upgrade_flow_abandoned",
        "inactivity_after_usage"
      ],
      required: true
    },
    targetPlan: { type: String, enum: ["pro", "plus"], required: true },
    discountType: { type: String, enum: ["percent_off", "amount_off"], required: true },
    discountValue: { type: Number, required: true },
    expiresAt: { type: Date, required: true, index: true },
    status: { type: String, enum: ["active", "used", "expired"], default: "active", index: true },
    usedAt: { type: Date },
    metadata: { type: mongoose.Schema.Types.Mixed },
    createdAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

discountSchema.index({ userId: 1, status: 1 });
discountSchema.index({ status: 1, expiresAt: 1 });
discountSchema.index(
  { userId: 1 },
  { unique: true, partialFilterExpression: { status: "active" } }
);

const UserDiscount = mongoose.model("UserDiscount", discountSchema);
```

---

## 8. Backend — Models and config

**Subscription model:** `server/src/modules/subscription/subscription.model.js`

- Fields: `userId`, `plan`, `status` (active, cancelled, cancelled_at_period_end, expired, trialing, canceled), `nextPlan`, `interval`, `price`, `currentPeriodEnd`, `trialingEndsAt`, `paddleSubscriptionId`, `paddleTransactionId`.

**Discount rules:** `server/src/config/discountRules.js`

- `usage_limit_reached`: percentOff (env), targetPlan "pro", minUsageThisPeriod.
- `locked_feature_accessed`: percentOff, targetPlan "pro".
- `upgrade_flow_abandoned`: percentOff, targetPlan "pro".
- `inactivity_after_usage`: percentOff, targetPlan "pro", inactivityDays, minUsagePreviousPeriod.
- Exports: `DISCOUNT_COOLDOWN_DAYS`, `DISCOUNT_VALIDITY_DAYS`, `RECENT_DISCOUNT_DAYS`, `getDiscountRule(trigger)`.

**Env config (paddle + discount):** `server/src/config/env.js`

- `config.paddle`: apiKey, environment, webhookSecret, pricePro, priceProYearly, pricePlus, pricePlusYearly, priceAgency, priceProTrial, priceProYearlyTrial, pricePlusTrial, pricePlusYearlyTrial.
- `config.app.frontendBaseUrl`.
- `config.discount`: enabled, percentOffUsageLimit, percentOffLockedFeature, percentOffAbandoned, percentOffInactivity, validityDays, cooldownDays.

---

## 9. Frontend — Subscription API (full code)

**File:** `client/src/api/subscription.ts`

```typescript
import { apiClient } from "./client";

export interface Plan {
  id: string;
  name: string;
  price: number | null;
  yearlyPrice?: number | null;
  yearlySavings?: number | null;
  popular?: boolean;
  target?: string;
  priceNote?: string;
  contactSales?: boolean;
  comingSoon?: boolean;
  features: string[];
}

export type SubscriptionStatus =
  | "active"
  | "trialing"
  | "cancelled"
  | "cancelled_at_period_end"
  | "expired";

export type PlanId = "free" | "pro" | "plus" | "agency";

export type BillingInterval = "monthly" | "yearly";

export interface ActiveDiscount {
  discount_value: number;
  discount_type: "percent_off" | "amount_off";
  target_plan: string;
  expires_at: string;
}

export interface CurrentSubscriptionResponse {
  current_plan: PlanId;
  subscription_status: SubscriptionStatus;
  next_plan: PlanId | null;
  current_period_end: string | null;
  trialing_ends_at: string | null;
  billing_interval?: BillingInterval | null;
  plan?: string;
  status?: string;
  nextPlan?: string | null;
  currentPeriodEnd?: string | null;
  billingUserId?: string;
  billingOwnerName?: string;
  isSharedContext?: boolean;
  active_discount?: ActiveDiscount | null;
  [key: string]: unknown;
}

export async function fetchSubscriptionPlans() {
  const { data } = await apiClient.get("/subscription/plans");
  return data.data as Plan[];
}

export async function fetchCurrentSubscription(channelId?: string) {
  const { data } = await apiClient.get("/subscription/current", {
    params: channelId ? { channelId } : undefined
  });
  return data.data as CurrentSubscriptionResponse | null;
}

export interface UpgradeSubscriptionResponse {
  checkoutUrl?: string;
  plan?: PlanId;
  currentPlan?: PlanId;
  nextPlan?: PlanId;
  activated?: boolean;
}

export async function upgradeSubscription(plan: string, interval: BillingInterval = "monthly") {
  const { data } = await apiClient.post("/subscription/upgrade", { plan, interval });
  return data.data as UpgradeSubscriptionResponse;
}

export async function cancelSubscription() {
  const { data } = await apiClient.post("/subscription/cancel");
  return data.data as CurrentSubscriptionResponse;
}

export async function createBillingPortal() {
  const { data } = await apiClient.post("/subscription/billing-portal");
  return data.data as { url: string };
}

export async function resumeSubscription() {
  const { data } = await apiClient.post("/subscription/resume");
  return data.data as CurrentSubscriptionResponse;
}

export type UsageEntry = { used: number; limit: number | typeof Infinity | "infinity" };
export type UsageLimits = Record<string, UsageEntry>;

export async function fetchSubscriptionUsage(channelId?: string) {
  const { data } = await apiClient.get("/subscription/usage", {
    params: channelId ? { channelId } : undefined
  });
  return data.data as {
    usage: UsageLimits;
    planId: string;
    billingUserId?: string;
    billingOwnerName?: string;
    isSharedContext?: boolean;
  };
}
```

---

## 10. Frontend — Subscription page (key code)

**File:** `client/src/pages/Subscription.tsx`

**Imports and queries:**

```tsx
import { fetchSubscriptionPlans, fetchCurrentSubscription, upgradeSubscription, createBillingPortal, resumeSubscription, fetchSubscriptionUsage, type Plan, type BillingInterval, type SubscriptionStatus } from '@/api/subscription';

const { data: plans = [], isLoading: isLoadingPlans } = useQuery({
  queryKey: ["subscription", "plans"],
  queryFn: fetchSubscriptionPlans,
  enabled: !!user,
});

const { data: currentSubscription, isLoading: isLoadingCurrent } = useQuery({
  queryKey: ["subscription", "current", contextChannelId ?? "me"],
  queryFn: () => fetchCurrentSubscription(contextChannelId),
  enabled: !!user,
});

const { data: usage } = useQuery({
  queryKey: ["subscription", "usage", contextChannelId ?? "me"],
  queryFn: () => fetchSubscriptionUsage(contextChannelId),
  enabled: !!user,
});

const upgradeMutation = useMutation({
  mutationFn: (vars: { plan: string; interval: BillingInterval }) =>
    upgradeSubscription(vars.plan, vars.interval),
  onSuccess: async () => {
    await queryClient.invalidateQueries({ queryKey: ["subscription"] });
    dispatch(initializeSession());
  },
});

const portalMutation = useMutation({ mutationFn: () => createBillingPortal() });
const resumeMutation = useMutation({
  mutationFn: () => resumeSubscription(),
  onSuccess: async () => {
    await queryClient.invalidateQueries({ queryKey: ['subscription'] });
    dispatch(initializeSession());
    toast.success('Subscription resumed. Your plan will continue as before.');
  },
});
```

**Derived state from current subscription:**

```tsx
const currentPlan = (currentSubscription?.current_plan ?? currentSubscription?.plan ?? user?.subscriptionPlan ?? 'free') as string;
const subscriptionStatus = (currentSubscription?.subscription_status ?? ...) as SubscriptionStatus;
const nextPlan = currentSubscription?.next_plan ?? currentSubscription?.nextPlan ?? null;
const currentPeriodEnd = currentSubscription?.current_period_end ?? currentSubscription?.currentPeriodEnd ?? null;
const trialingEndsAt = currentSubscription?.trialing_ends_at ?? null;
const currentInterval = (currentSubscription?.billing_interval ?? currentSubscription?.interval ?? 'monthly') as BillingInterval;
const activeDiscount = currentSubscription?.active_discount ?? null;
```

**Upgrade handler (redirect to checkout when checkoutUrl returned):**

```tsx
const handleUpgrade = async (plan: Plan) => {
  if (plan.comingSoon) { /* mailto get notified */ return; }
  if (plan.contactSales) { /* mailto contact sales */ return; }
  try {
    const data = await upgradeMutation.mutateAsync({ plan: plan.id, interval: billingInterval });
    if (data?.checkoutUrl) {
      window.location.href = data.checkoutUrl;
      return;
    }
    if (data?.nextPlan != null && data?.currentPlan != null) {
      toast.success('Downgrade scheduled for next billing cycle. Your current plan stays active until then.');
    } else {
      toast.success(`Switched to ${plan.name} plan.`);
    }
  } catch (error) {
    toast.error('Failed to update subscription. Please try again.');
  }
};
```

**Active discount badge and copy (current plan card):**

```tsx
{activeDiscount && (
  <Badge className="bg-emerald-600 ...">
    <Tag className="h-3 w-3" />
    {activeDiscount.discount_type === 'percent_off'
      ? `${activeDiscount.discount_value}% off`
      : `$${activeDiscount.discount_value} off`}{' '}
    on upgrade
  </Badge>
)}
{activeDiscount && (
  <div className="rounded-lg border border-emerald-500/30 ...">
    <p className="font-medium">You have an active discount</p>
    <p className="text-muted-foreground mt-0.5">
      {activeDiscount.discount_type === 'percent_off'
        ? `${activeDiscount.discount_value}% off`
        : `$${activeDiscount.discount_value} off`}{' '}
      when you upgrade to {activeDiscount.target_plan}. Expires{' '}
      {new Date(activeDiscount.expires_at).toLocaleDateString(undefined, { dateStyle: 'medium' })}.
      Applied automatically at checkout — no code needed.
    </p>
  </div>
)}
```

**Billing portal (Manage billing / Payment method):**

```tsx
<Button
  variant="outline"
  size="sm"
  onClick={async () => {
    try {
      const data = await portalMutation.mutateAsync();
      window.location.href = data.url;
    } catch (error: unknown) {
      toast.error(extractErrorMessage(error as any) || 'Failed to open billing portal');
    }
  }}
  disabled={portalMutation.isPending}
>
  Manage billing
</Button>
```

**Resume subscription (when status is cancelled_at_period_end):**

```tsx
<Button
  variant="default"
  size="sm"
  onClick={async () => {
    try {
      await resumeMutation.mutateAsync();
    } catch (error: unknown) {
      toast.error(extractErrorMessage(error as any) || 'Failed to resume subscription');
    }
  }}
  disabled={resumeMutation.isPending}
>
  Resume subscription
</Button>
```

**Plan cards:** Toggle monthly/yearly; for each plan, button calls `handleUpgrade(plan)`. Success/cancel URLs point to `/subscription?success=1` and `/subscription?canceled=1` (configured in backend when creating transaction).

---

## 11. Edge cases and checklist

### Edge cases

- **Sandbox vs production:** Never mix API key, price IDs, or discount IDs between environments.
- **Discount not eligible:** Attach discount only when `req.body.plan === activeDiscount.targetPlan` to avoid Paddle "discount not eligible for items".
- **discount_usage_limit_exceeded:** In upgrade flow, catch this Paddle error, call `markDiscountUsed(userId, activeDiscount._id)`, then retry `createPaddleTransaction` without `discountId`.
- **Webhook discount mark-used:** Prefer `customData.discountId`; fallback to `data.discount_id` or `data.discount?.id` and `markDiscountUsedByPaymentId(userId, paddleDiscountId)`.
- **One subscription per user:** In webhook, if user already has an effective subscription and event is for a different `subscription_id`, return `{ received: true, ignored: true }`.
- **Portal URLs in sandbox:** Backend rewrites production portal host to sandbox portal host when `PADDLE_ENVIRONMENT=sandbox`.

### Checklist for new Paddle work

- [ ] All price IDs and API key match same Paddle environment.
- [ ] Webhook secret set; endpoint receives raw body for signature verification.
- [ ] New discount: create in Paddle first; store `paymentDiscountId`; attach at checkout only when selected plan matches `target_plan`.
- [ ] Webhook marks discount used (by internal ID or Paddle discount ID) on transaction.paid/completed.
- [ ] Handle `discount_usage_limit_exceeded` by marking used and retrying without discount.
- [ ] Frontend: upgrade calls POST `/api/subscription/upgrade`, redirects to `data.checkoutUrl` when present.
- [ ] Success/cancel URLs configured in backend when creating transaction (e.g. `${frontendBaseUrl}/subscription?success=1`).

---

This README plus the repo contains every endpoint and the full code for Paddle subscription, checkout, discounts, and webhooks. When changing behavior, update this file and the relevant source files together.
