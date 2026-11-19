# Paylumo Payment Gateway for Stripe and WooCommerce

A WooCommerce payment gateway that sends customers to a Stripe-hosted Checkout page, with separate Test and Live modes.

Paylumo is an independent plugin. It is not made, endorsed or supported by Stripe, Inc. or WooCommerce. Stripe is a trademark of Stripe, Inc. WooCommerce is a trademark of Automattic Inc.

## Features

- Customers pay on a Stripe-hosted Checkout page, so card details never touch your site.
- An order is marked paid only after Stripe sends a webhook with a verified signature.
- Separate Test and Live modes. Each mode has its own publishable key, secret key (or restricted key), webhook URL and webhook signing secret.
- Works with the classic (shortcode) checkout and the WooCommerce Checkout block.
- Compatible with HPOS (High-Performance Order Storage).
- Full and partial refunds from the WooCommerce order screen, sent to Stripe.
- Secret keys and webhook secrets are stored encrypted in the database and never printed on the settings page.
- An order paid with this gateway cannot be set to Processing or Completed without a confirmed Stripe payment.
- Unpaid checkout orders are cancelled automatically.
- Uses the WordPress HTTP API. No external libraries.

## Requirements

| Requirement | Version |
| --- | --- |
| WordPress | 6.4 or newer |
| WooCommerce | 8.0 or newer |
| PHP | 8.1 or newer, with the sodium extension |
| HTTPS | Required for Live mode |

## Installation

1. Install and activate WooCommerce.
2. Copy the `paylumo-payment-gateway-for-stripe-and-woocommerce` folder to `wp-content/plugins/`.
3. Activate **Paylumo Payment Gateway for Stripe and WooCommerce** on the Plugins page.
4. Click **Settings** under the plugin name, or go to **WooCommerce > Settings > Payments > Paylumo Payment Gateway for Stripe and WooCommerce**.

## Setup

### Test mode

1. Open the **Test settings** tab.
2. Paste your Stripe test publishable key (`pk_test_`) and either your secret key (`sk_test_`) or a restricted key (`rk_test_`).
3. In the Stripe Dashboard (test mode), add a webhook endpoint with the test webhook URL shown on the settings page and select the events listed below.
4. Paste the endpoint's signing secret (`whsec_`).
5. Enable the gateway and save.

### Live mode

1. Activate your Stripe account for live payments.
2. Fill in the **Live settings** tab the same way, using live keys (`pk_live_`, `sk_live_` or `rk_live_`) and a webhook endpoint created in Stripe's live mode.
3. Set **Active mode** to **Live** and save.

The gateway appears at checkout only when the active mode has all its keys. Live mode also requires HTTPS.

### Restricted keys

A restricted key is safer than a secret key because it can only do what you allow. It needs **Write** access to:

- Checkout Sessions
- Refunds

When you save a key, the plugin checks with Stripe that the key works and has these permissions. Each mode keeps only one key, so saving a restricted key removes the saved secret key of that mode, and saving a secret key removes the saved restricted key.

## Webhooks

| Mode | URL |
| --- | --- |
| Test | `https://your-site.com/wp-json/paylumo/v1/webhook/test` |
| Live | `https://your-site.com/wp-json/paylumo/v1/webhook/live` |

The settings page shows the exact URLs for your site, each with a Copy button.

Select these events in Stripe:

- `checkout.session.completed`
- `checkout.session.async_payment_succeeded`
- `checkout.session.async_payment_failed`
- `checkout.session.expired`
- `charge.refunded`

Each URL accepts only events signed with its own mode's secret and with the matching `livemode` value. If an event does not match the order (amount, currency, session or mode), the order is not marked paid. Instead, it gets an order note starting with `MANUAL REVIEW:` and the problem is logged.

## Refunds

Use the normal WooCommerce refund button on the order screen. Full and partial refunds are sent to Stripe with the key of the mode the order was paid in, so test orders can still be refunded after you switch to Live.

## Order protection

For orders that use this gateway:

- Changing the status to Processing or Completed is blocked unless Stripe confirmed the payment. This covers the order screen, bulk actions, the REST API and other plugins.
- Order meta keys starting with `_paylumo_` cannot be changed through the REST API.
- If the customer paid another way, change the order's payment method first. The order can then be marked paid.

## Unpaid orders

- When a Stripe Checkout Session expires (after about 31 minutes), the order is cancelled and the stock is returned.
- An hourly Action Scheduler job (`paylumo_cancel_unpaid_orders`) cancels unpaid checkout orders that have not changed for 60 minutes. It cancels an order only after Stripe confirms that every Checkout Session of the order expired unpaid.
- Orders created by an admin and orders in manual review are never cancelled automatically.
- Delayed payment methods (SEPA, ACH, Bacs) put the order On hold until Stripe confirms or fails the payment.

## Logs

Enable **Debug log** in the gateway settings, then open **WooCommerce > Status > Logs** and choose the source `paylumo-payment-gateway-for-stripe-and-woocommerce`. Manual review problems are always logged, even with Debug log turned off. Keys, secrets and webhook signatures are never logged.

## Uninstall

Deleting the plugin removes its encrypted secret keys, scheduled jobs and temporary data. Gateway settings and order data are kept.

## License

GPL-2.0-or-later. See https://www.gnu.org/licenses/gpl-2.0.html.
