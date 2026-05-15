package provider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/payment"
	"github.com/shopspring/decimal"
)

const (
	crossmintDefaultAPIBase = "https://www.crossmint.com/api"
	crossmintHTTPTimeout    = 15 * time.Second
	crossmintMaxBodySize    = 1 << 20
	crossmintWebhookSkew    = 5 * time.Minute

	crossmintCheckoutPath = "/v1-alpha1/checkout/mint"
)

// Crossmint implements hosted Crossmint checkout. The first pass uses the
// hosted checkout-link API so the existing redirect payment flow can launch it
// without adding a framework-specific Crossmint checkout component.
type Crossmint struct {
	instanceID string
	config     map[string]string
	httpClient *http.Client
}

func NewCrossmint(instanceID string, config map[string]string) (*Crossmint, error) {
	for _, k := range []string{"apiKey", "webhookSecret", "clientId", "listingId"} {
		if strings.TrimSpace(config[k]) == "" {
			return nil, fmt.Errorf("crossmint config missing required key: %s", k)
		}
	}
	cfg := cloneStringMap(config)
	apiBase, err := normalizeCrossmintAPIBase(cfg["apiBase"])
	if err != nil {
		return nil, err
	}
	cfg["apiBase"] = apiBase
	currency, err := payment.NormalizePaymentCurrency(cfg["currency"])
	if err != nil {
		return nil, fmt.Errorf("crossmint config currency: %w", err)
	}
	cfg["currency"] = currency
	if strings.TrimSpace(cfg["paymentMethod"]) == "" {
		cfg["paymentMethod"] = "fiat"
	}
	return &Crossmint{
		instanceID: instanceID,
		config:     cfg,
		httpClient: &http.Client{Timeout: crossmintHTTPTimeout},
	}, nil
}

func normalizeCrossmintAPIBase(raw string) (string, error) {
	base := strings.TrimSpace(raw)
	if base == "" {
		base = crossmintDefaultAPIBase
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("crossmint apiBase must be an HTTPS URL")
	}
	host := strings.ToLower(u.Host)
	if host != "www.crossmint.com" && host != "staging.crossmint.com" {
		return "", fmt.Errorf("crossmint apiBase host must be www.crossmint.com or staging.crossmint.com")
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.RawPath = ""
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path == "" {
		u.Path = "/api"
	}
	if u.Path != "/api" {
		return "", fmt.Errorf("crossmint apiBase path must be /api")
	}
	return u.String(), nil
}

func (c *Crossmint) Name() string        { return "Crossmint" }
func (c *Crossmint) ProviderKey() string { return payment.TypeCrossmint }
func (c *Crossmint) SupportedTypes() []payment.PaymentType {
	return []payment.PaymentType{payment.TypeCrossmint}
}

func (c *Crossmint) MerchantIdentityMetadata() map[string]string {
	if c == nil {
		return nil
	}
	return map[string]string{
		"client_id":  strings.TrimSpace(c.config["clientId"]),
		"listing_id": strings.TrimSpace(c.config["listingId"]),
		"currency":   c.currency(),
	}
}

func (c *Crossmint) currency() string {
	if c == nil {
		return payment.DefaultPaymentCurrency
	}
	currency, err := payment.NormalizePaymentCurrency(c.config["currency"])
	if err != nil {
		return payment.DefaultPaymentCurrency
	}
	return currency
}

func (c *Crossmint) CreatePayment(ctx context.Context, req payment.CreatePaymentRequest) (*payment.CreatePaymentResponse, error) {
	amount, err := decimal.NewFromString(strings.TrimSpace(req.Amount))
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		return nil, fmt.Errorf("crossmint create payment: invalid amount %s", req.Amount)
	}

	currency := c.currency()
	payload := c.hostedCheckoutPayload(req, amount, currency)
	var resp map[string]any
	if err := c.doJSON(ctx, http.MethodPost, crossmintCheckoutPath, payload, &resp); err != nil {
		return nil, fmt.Errorf("crossmint create payment: %w", err)
	}
	payURL := firstString(resp,
		"checkoutUrl", "checkoutURL", "checkout_url",
		"paymentUrl", "paymentURL", "payment_url",
		"url",
	)
	if payURL == "" {
		return nil, fmt.Errorf("crossmint create payment: response missing checkout url")
	}
	tradeNo := firstString(resp, "orderId", "order_id", "id")
	if tradeNo == "" {
		tradeNo = req.OrderID
	}
	return &payment.CreatePaymentResponse{
		TradeNo:  tradeNo,
		PayURL:   payURL,
		Currency: currency,
	}, nil
}

func (c *Crossmint) hostedCheckoutPayload(req payment.CreatePaymentRequest, amount decimal.Decimal, currency string) map[string]any {
	payload := map[string]any{
		"clientId":      strings.TrimSpace(c.config["clientId"]),
		"listingId":     strings.TrimSpace(c.config["listingId"]),
		"userId":        req.OrderID,
		"paymentMethod": strings.TrimSpace(c.config["paymentMethod"]),
		"currency":      currency,
		"totalPrice":    amount.StringFixed(int32(payment.CurrencyMaxFractionDigits(currency))),
		"whPassThroughArgs": map[string]string{
			"order_id": req.OrderID,
		},
		"passThroughArgs": map[string]string{
			"order_id": req.OrderID,
		},
	}
	if req.ReturnURL != "" {
		payload["redirectUrl"] = req.ReturnURL
		payload["successCallbackUrl"] = req.ReturnURL
		payload["failureCallbackUrl"] = req.ReturnURL
	}
	if locale := strings.TrimSpace(c.config["locale"]); locale != "" {
		payload["locale"] = locale
	}
	if emailTo := strings.TrimSpace(c.config["emailTo"]); emailTo != "" {
		payload["emailTo"] = emailTo
	}
	if mintTo := strings.TrimSpace(c.config["mintTo"]); mintTo != "" {
		payload["mintTo"] = mintTo
	}
	payload["mintConfig"] = map[string]any{
		"totalPrice":  amount.StringFixed(int32(payment.CurrencyMaxFractionDigits(currency))),
		"currency":    currency,
		"description": req.Subject,
	}
	if extra := strings.TrimSpace(c.config["extraPayload"]); extra != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(extra), &m); err == nil {
			for k, v := range m {
				payload[k] = v
			}
		}
	}
	return payload
}

func (c *Crossmint) QueryOrder(_ context.Context, tradeNo string) (*payment.QueryOrderResponse, error) {
	if strings.TrimSpace(tradeNo) == "" {
		return nil, fmt.Errorf("crossmint query order: missing trade number")
	}
	// Hosted checkout webhooks are the source of truth. Crossmint hosted link
	// creation does not always return a stable queryable order ID, so manual
	// polling remains pending until the webhook arrives.
	return &payment.QueryOrderResponse{
		TradeNo: strings.TrimSpace(tradeNo),
		Status:  payment.ProviderStatusPending,
		Amount:  0,
		Metadata: map[string]string{
			"currency": c.currency(),
		},
	}, nil
}

func (c *Crossmint) VerifyNotification(_ context.Context, rawBody string, headers map[string]string) (*payment.PaymentNotification, error) {
	if err := verifyCrossmintSvixSignature(c.config["webhookSecret"], rawBody, headers); err != nil {
		return nil, err
	}
	var event crossmintWebhookEvent
	if err := json.Unmarshal([]byte(rawBody), &event); err != nil {
		return nil, fmt.Errorf("crossmint parse webhook: %w", err)
	}
	status := crossmintProviderStatus(event)
	if status == "" {
		return nil, nil
	}
	orderID := crossmintWebhookOrderID(event)
	if orderID == "" {
		return nil, fmt.Errorf("crossmint webhook missing order_id passthrough metadata")
	}
	currency := crossmintWebhookCurrency(event, c.currency())
	return &payment.PaymentNotification{
		TradeNo: crossmintWebhookTradeNo(event, orderID),
		OrderID: orderID,
		Amount:  crossmintWebhookAmount(event),
		Status:  status,
		RawData: rawBody,
		Metadata: map[string]string{
			"currency": currency,
		},
	}, nil
}

func (c *Crossmint) Refund(context.Context, payment.RefundRequest) (*payment.RefundResponse, error) {
	return nil, fmt.Errorf("crossmint refund is not supported by this provider implementation")
}

func (c *Crossmint) doJSON(ctx context.Context, method, path string, payload any, out any) error {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.config["apiBase"], "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", strings.TrimSpace(c.config["apiKey"]))
	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(res.Body, crossmintMaxBodySize))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("crossmint API status %d: %s", res.StatusCode, truncateString(string(data), 512))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return err
		}
	}
	return nil
}

type crossmintWebhookEvent struct {
	Type    string               `json:"type"`
	Data    crossmintWebhookData `json:"data"`
	Payload crossmintWebhookData `json:"payload"`

	OrderID       string            `json:"orderId"`
	OrderIDAlt    string            `json:"order_id"`
	ID            string            `json:"id"`
	Status        string            `json:"status"`
	Amount        any               `json:"amount"`
	TotalPrice    any               `json:"totalPrice"`
	Currency      string            `json:"currency"`
	Metadata      map[string]string `json:"metadata"`
	PassThrough   any               `json:"passThroughArgs"`
	WhPassThrough any               `json:"whPassThroughArgs"`
}

type crossmintWebhookData struct {
	OrderID       string            `json:"orderId"`
	OrderIDAlt    string            `json:"order_id"`
	ID            string            `json:"id"`
	Status        string            `json:"status"`
	Amount        any               `json:"amount"`
	TotalPrice    any               `json:"totalPrice"`
	Currency      string            `json:"currency"`
	Metadata      map[string]string `json:"metadata"`
	PassThrough   any               `json:"passThroughArgs"`
	WhPassThrough any               `json:"whPassThroughArgs"`
	Payment       struct {
		Status string `json:"status"`
	} `json:"payment"`
	Quote struct {
		TotalPrice struct {
			Amount   any    `json:"amount"`
			Currency string `json:"currency"`
		} `json:"totalPrice"`
	} `json:"quote"`
	OrderIdentifier string `json:"orderIdentifier"`
}

func crossmintProviderStatus(event crossmintWebhookEvent) string {
	candidates := []string{event.Type, event.Data.Status, event.Data.Payment.Status, event.Status}
	for _, raw := range candidates {
		status := strings.ToLower(strings.TrimSpace(raw))
		switch status {
		case "purchase.succeeded", "order.completed", "order.succeeded", "order.payment.succeeded", "completed", "succeeded", "success", "paid":
			return payment.ProviderStatusSuccess
		case "purchase.failed", "order.failed", "order.cancelled", "order.canceled", "failed", "cancelled", "canceled":
			return payment.ProviderStatusFailed
		}
	}
	return ""
}

func crossmintWebhookOrderID(event crossmintWebhookEvent) string {
	for _, value := range []string{
		event.Data.Metadata["order_id"],
		event.Data.Metadata["orderId"],
		event.Metadata["order_id"],
		event.Metadata["orderId"],
		crossmintPassThroughOrderID(event.Data.WhPassThrough),
		crossmintPassThroughOrderID(event.Data.PassThrough),
		event.Payload.Metadata["order_id"],
		event.Payload.Metadata["orderId"],
		crossmintPassThroughOrderID(event.Payload.WhPassThrough),
		crossmintPassThroughOrderID(event.Payload.PassThrough),
		crossmintPassThroughOrderID(event.WhPassThrough),
		crossmintPassThroughOrderID(event.PassThrough),
	} {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func crossmintWebhookTradeNo(event crossmintWebhookEvent, fallback string) string {
	for _, value := range []string{
		event.Data.OrderID,
		event.Data.OrderIDAlt,
		event.Data.ID,
		event.Data.OrderIdentifier,
		event.Payload.OrderID,
		event.Payload.OrderIDAlt,
		event.Payload.ID,
		event.Payload.OrderIdentifier,
		event.OrderID,
		event.OrderIDAlt,
		event.ID,
	} {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return fallback
}

func crossmintWebhookAmount(event crossmintWebhookEvent) float64 {
	for _, value := range []any{
		event.Data.Quote.TotalPrice.Amount,
		event.Data.TotalPrice,
		event.Data.Amount,
		event.Payload.Quote.TotalPrice.Amount,
		event.Payload.TotalPrice,
		event.Payload.Amount,
		event.TotalPrice,
		event.Amount,
	} {
		if f, ok := crossmintAnyFloat(value); ok {
			return f
		}
	}
	return 0
}

func crossmintWebhookCurrency(event crossmintWebhookEvent, fallback string) string {
	for _, value := range []string{event.Data.Quote.TotalPrice.Currency, event.Data.Currency, event.Payload.Quote.TotalPrice.Currency, event.Payload.Currency, event.Currency} {
		if currency, err := payment.NormalizePaymentCurrency(value); err == nil && strings.TrimSpace(value) != "" {
			return currency
		}
	}
	for _, value := range []any{event.Data.TotalPrice, event.Payload.TotalPrice, event.TotalPrice} {
		if currency, ok := crossmintAnyCurrency(value); ok {
			return currency
		}
	}
	return fallback
}

func crossmintPassThroughOrderID(raw any) string {
	switch v := raw.(type) {
	case map[string]any:
		for _, key := range []string{"order_id", "orderId", "out_trade_no"} {
			if value, ok := v[key].(string); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
	case map[string]string:
		for _, key := range []string{"order_id", "orderId", "out_trade_no"} {
			if strings.TrimSpace(v[key]) != "" {
				return strings.TrimSpace(v[key])
			}
		}
	case string:
		var m map[string]any
		if err := json.Unmarshal([]byte(v), &m); err == nil {
			return crossmintPassThroughOrderID(m)
		}
	}
	return ""
}

func crossmintAnyFloat(raw any) (float64, bool) {
	switch v := raw.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f, err == nil
	case map[string]any:
		for _, key := range []string{"amount", "value"} {
			if f, ok := crossmintAnyFloat(v[key]); ok {
				return f, true
			}
		}
	}
	return 0, false
}

func crossmintAnyCurrency(raw any) (string, bool) {
	switch v := raw.(type) {
	case map[string]any:
		if currency, ok := v["currency"].(string); ok {
			normalized, err := payment.NormalizePaymentCurrency(currency)
			return normalized, err == nil && strings.TrimSpace(currency) != ""
		}
	}
	return "", false
}

func verifyCrossmintSvixSignature(secret, rawBody string, headers map[string]string) error {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return fmt.Errorf("crossmint webhookSecret not configured")
	}
	msgID := strings.TrimSpace(headers["svix-id"])
	timestamp := strings.TrimSpace(headers["svix-timestamp"])
	signature := strings.TrimSpace(headers["svix-signature"])
	if msgID == "" || timestamp == "" || signature == "" {
		return fmt.Errorf("crossmint webhook missing svix signature headers")
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("crossmint webhook invalid svix timestamp")
	}
	if delta := time.Since(time.Unix(ts, 0)); delta > crossmintWebhookSkew || delta < -crossmintWebhookSkew {
		return fmt.Errorf("crossmint webhook timestamp outside tolerance")
	}
	key := []byte(secret)
	if strings.HasPrefix(secret, "whsec_") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
		if err != nil {
			return fmt.Errorf("crossmint webhook secret is not valid base64")
		}
		key = decoded
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(msgID + "." + timestamp + "." + rawBody))
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	for _, part := range strings.Split(signature, " ") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "v1,")
		if subtle.ConstantTimeCompare([]byte(part), []byte(expected)) == 1 {
			return nil
		}
	}
	return fmt.Errorf("crossmint webhook signature mismatch")
}

func firstString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := m[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func truncateString(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}
