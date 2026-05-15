//go:build unit

package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/payment"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

func TestCrossmintHostedCheckoutPayloadCarriesV2Passthrough(t *testing.T) {
	t.Parallel()

	prov := mustTestCrossmintProvider(t)
	payload := prov.hostedCheckoutPayload(payment.CreatePaymentRequest{
		OrderID: "sub2_order_123",
		Amount:  "25.00",
		Subject: "Codex weekly subscription",
	}, decimal.RequireFromString("25.00"), "USD")

	require.Equal(t, "sub2_order_123", payload["userId"])
	require.Equal(t, map[string]string{"order_id": "sub2_order_123"}, payload["whPassThroughArgs"])
	require.Equal(t, map[string]string{"order_id": "sub2_order_123"}, payload["passThroughArgs"])
}

func TestCrossmintVerifyNotificationV2PurchaseSucceeded(t *testing.T) {
	t.Parallel()

	prov := mustTestCrossmintProvider(t)
	raw := `{
		"type": "purchase.succeeded",
		"data": {
			"id": "cm_order_123",
			"whPassThroughArgs": {"order_id": "sub2_order_123"},
			"quote": {"totalPrice": {"amount": "25.00", "currency": "USD"}}
		}
	}`

	n, err := prov.VerifyNotification(context.Background(), raw, signedCrossmintHeaders(raw, "secret"))
	require.NoError(t, err)
	require.NotNil(t, n)
	require.Equal(t, "cm_order_123", n.TradeNo)
	require.Equal(t, "sub2_order_123", n.OrderID)
	require.Equal(t, payment.NotificationStatusSuccess, n.Status)
	require.InDelta(t, 25.00, n.Amount, 0.0001)
	require.Equal(t, "USD", n.Metadata["currency"])
}

func TestCrossmintVerifyNotificationIgnoresV3OrdersEventWithoutOutTradeNo(t *testing.T) {
	t.Parallel()

	prov := mustTestCrossmintProvider(t)
	raw := `{
		"type": "orders.payment.succeeded",
		"payload": {
			"orderIdentifier": "cm_order_v3_123",
			"totalPrice": {"amount": "99.00", "currency": "USD"}
		}
	}`

	var event crossmintWebhookEvent
	require.NoError(t, json.Unmarshal([]byte(raw), &event))
	require.Equal(t, "", crossmintProviderStatus(event))
	require.Equal(t, "", crossmintWebhookOrderID(event))
	require.Equal(t, "cm_order_v3_123", crossmintWebhookTradeNo(event, "fallback"))
	require.InDelta(t, 99.00, crossmintWebhookAmount(event), 0.0001)
	require.Equal(t, "USD", crossmintWebhookCurrency(event, "CNY"))

	n, err := prov.VerifyNotification(context.Background(), raw, signedCrossmintHeaders(raw, "secret"))
	require.NoError(t, err)
	require.Nil(t, n)
}

func mustTestCrossmintProvider(t *testing.T) *Crossmint {
	t.Helper()
	prov, err := NewCrossmint("1", map[string]string{
		"apiKey":        "key",
		"webhookSecret": "secret",
		"clientId":      "client_123",
		"listingId":     "listing_123",
		"currency":      "USD",
	})
	require.NoError(t, err)
	return prov
}

func signedCrossmintHeaders(rawBody, secret string) map[string]string {
	msgID := "msg_test"
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(msgID + "." + timestamp + "." + rawBody))
	return map[string]string{
		"svix-id":        msgID,
		"svix-timestamp": timestamp,
		"svix-signature": "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil)),
	}
}
