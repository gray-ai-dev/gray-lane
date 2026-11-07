package main

import "strconv"

// The OpenAI-compatible vendors (docs/relay-openai-compatible-vendors.md): vendors whose API key buys an OpenAI
// Chat Completions compatible endpoint on one fixed host. Each is one row of openAICompatibleVendors, the Go copy of
// @gray/lane's table (workers/packages/lane/src/vendors.ts); vendors_test.go holds both to the published
// workers/packages/lane/vendors/openai-compatible-vendors.json. A row gives the vendor:
//
//   - a route `/<id>/` pinned to `host`, its vendor path `pathPrefix` (routes.go routeTable);
//   - its account vendor `<id>` and that route (stack_control.go stackVendors), the API-key credential type
//     (stack_identity.go stackCredentialTypes) sent as `authorization: Bearer <key>`, OpenAI's form;
//   - `/openai`'s header lists: the pass list, the identity's `user-agent` and `accept`, no generated id, Chat's
//     behaviour header `openai-beta` (the entry registers it by protocol; stack_headers.go, stack_identity.go);
//   - one relay route, `open_ai_chat` on `chatPath` (stack_relay.go stackProtocolRoutes), and Chat's account test;
//   - the cooling rules' vendor word (stack_cooling.go coolingVendors);
//   - the vendor's own kept members and tool types on top of Chat's (stack_changes.go, P1 and P2).
//
// Billing is the lane's (Chat's usage); nothing here reads usage.
type openAICompatibleVendor struct {
	id            string
	host          string
	pathPrefix    string
	chatPath      string
	keptMembers   []string
	keptToolTypes []string
}

var openAICompatibleVendors = []openAICompatibleVendor{
	// ai.google.dev/gemini-api/docs/openai: base https://generativelanguage.googleapis.com/v1beta/openai/, Bearer key.
	// extra_body.google carries cached_content (an explicit cache under the account) and the vendor's own options.
	{id: "gemini", host: "generativelanguage.googleapis.com", pathPrefix: "/v1beta/openai/", chatPath: "/v1beta/openai/chat/completions",
		keptMembers: []string{"extra_body"}},
	// api-docs.deepseek.com: https://api.deepseek.com/chat/completions, the reference's only server.
	{id: "deepseek", host: "api.deepseek.com", pathPrefix: "/", chatPath: "/chat/completions"},
	// platform.kimi.ai (international) and platform.kimi.com (China): keys are bound to their region's host.
	{id: "moonshot", host: "api.moonshot.ai", pathPrefix: "/v1/", chatPath: "/v1/chat/completions"},
	{id: "moonshot_cn", host: "api.moonshot.cn", pathPrefix: "/v1/", chatPath: "/v1/chat/completions"},
	// docs.z.ai and docs.bigmodel.cn, pay-as-you-go (the Coding Plan's /api/coding/paas/v4 is not a relay's to sell):
	// tools of type web_search make the vendor search, retrieval reads a knowledge base under the account.
	{id: "zhipu", host: "api.z.ai", pathPrefix: "/api/paas/v4/", chatPath: "/api/paas/v4/chat/completions",
		keptToolTypes: []string{"web_search", "retrieval"}},
	{id: "zhipu_cn", host: "open.bigmodel.cn", pathPrefix: "/api/paas/v4/", chatPath: "/api/paas/v4/chat/completions",
		keptToolTypes: []string{"web_search", "retrieval"}},
	// platform.minimax.io (international) and platform.minimax.cn (China).
	{id: "minimax", host: "api.minimax.io", pathPrefix: "/v1/", chatPath: "/v1/chat/completions"},
	{id: "minimax_cn", host: "api.minimax.cn", pathPrefix: "/v1/", chatPath: "/v1/chat/completions"},
	// alibabacloud.com Model Studio, OpenAI compatible mode, the shared hosts of Singapore and Beijing: enable_search
	// and search_options make the vendor search, enable_code_interpreter runs code under the account.
	{id: "qwen", host: "dashscope-intl.aliyuncs.com", pathPrefix: "/compatible-mode/v1/", chatPath: "/compatible-mode/v1/chat/completions",
		keptMembers: []string{"enable_search", "search_options", "enable_code_interpreter"}},
	{id: "qwen_cn", host: "dashscope.aliyuncs.com", pathPrefix: "/compatible-mode/v1/", chatPath: "/compatible-mode/v1/chat/completions",
		keptMembers: []string{"enable_search", "search_options", "enable_code_interpreter"}},
}

// compatRouteName is the route of an OpenAI-compatible vendor: `/<id>`.
func compatRouteName(id string) string { return "/" + id }

// compatVendorOfRoute is the row whose route is name, or false.
func compatVendorOfRoute(name string) (openAICompatibleVendor, bool) {
	for _, v := range openAICompatibleVendors {
		if compatRouteName(v.id) == name {
			return v, true
		}
	}
	return openAICompatibleVendor{}, false
}

// compatRoutes are the rows' routes, after the first three in routeTable.
func compatRoutes() []route {
	routes := make([]route, 0, len(openAICompatibleVendors))
	for _, v := range openAICompatibleVendors {
		name := compatRouteName(v.id)
		routes = append(routes, route{name: name, prefix: name + "/", host: v.host, vendorPath: v.pathPrefix})
	}
	return routes
}

// withCompat is base with one value per row under its account vendor id (byRoute false) or its route (true).
func withCompat[T any](base map[string]T, byRoute bool, value func(openAICompatibleVendor) T) map[string]T {
	for _, v := range openAICompatibleVendors {
		key := v.id
		if byRoute {
			key = compatRouteName(v.id)
		}
		base[key] = value(v)
	}
	return base
}

// stackCompatBillingCodes are the OpenAI-compatible vendors' own words for a spent balance, read as
// insufficient_balance (S35's billing row): Moonshot's exceeded_current_quota_error (429, platform.kimi.ai errors),
// Zhipu's 1113 (429, docs.z.ai api-code) and DashScope's Arrearage (400, Model Studio error codes). DeepSeek and
// Gemini answer 402, which stackVendorCode reads the same way. readStackErrorBody lower-cases what it reads.
var stackCompatBillingCodes = setOf("exceeded_current_quota_error", "1113", "arrearage")

// compatVendorIDs are the rows' account vendor ids, in the table's order.
func compatVendorIDs() []string {
	ids := make([]string, 0, len(openAICompatibleVendors))
	for _, v := range openAICompatibleVendors {
		ids = append(ids, v.id)
	}
	return ids
}

// compatKeptRefusal is the refusal path of a call on an OpenAI-compatible vendor's route whose forwarded body
// changes one of the vendor's kept members (present with another value, added or removed) or adds or changes a
// tool of a kept type (P1, P2; stack_changes.go's rule for the protocol's own): "" when it keeps them all, on every
// other route, and for a body S18's check already read as no object (it refused it first). Without relay_changes
// S18 refuses any such difference itself; with it this keeps the vendor's limits as the protocol's are kept.
func compatKeptRefusal(routeName string, received, forwarded []byte) string {
	vendor, ok := compatVendorOfRoute(routeName)
	if !ok || (len(vendor.keptMembers) == 0 && len(vendor.keptToolTypes) == 0) {
		return ""
	}
	receivedBody, err := bodyObject(received, stackPartReceived)
	if err != nil {
		return ""
	}
	forwardedBody, err := bodyObject(forwarded, stackPartForwarded)
	if err != nil {
		return ""
	}
	for _, name := range vendor.keptMembers {
		customer, customerHas := receivedBody.members[name]
		relay, relayHas := forwardedBody.members[name]
		if customerHas != relayHas || (customerHas && !sameStackJSON(customer, relay)) {
			return "/" + pointerToken(name)
		}
	}
	if len(vendor.keptToolTypes) == 0 {
		return ""
	}
	forwardedTools, ok := elementsOf(forwardedBody.members["tools"])
	if !ok {
		return ""
	}
	receivedTools, _ := elementsOf(receivedBody.members["tools"])
	used := make([]bool, len(receivedTools))
	for index, tool := range forwardedTools {
		if !keptTool(vendor.keptToolTypes, tool) {
			continue
		}
		found := false
		for candidate, customer := range receivedTools {
			if !used[candidate] && sameStackJSON(customer, tool) {
				used[candidate], found = true, true
				break
			}
		}
		if !found {
			return "/tools/" + strconv.Itoa(index)
		}
	}
	return ""
}
