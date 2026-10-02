# Evidence: Element Web logs in through the built-in OIDC provider — no MAS

The claim under test (#159): with `[auth] builtin_oidc = true`, one
Spindle process is homeserver and OIDC provider at once. An unmodified
client, native to MSC3861, completes a modern login against it with
**no Matrix Authentication Service on any host**. It uses the same release
tarball of Element Web and the same Playwright script skeleton as the
delegated-auth run in [m4-delegated-auth.md](m4-delegated-auth.md). The
only change is that the provider pages where the browser lands are
Spindle's own.

## Setup

- Spindle, release build of this branch, one process:

  ```toml
  [server]
  name = "127.0.0.1:8008"
  bind = "127.0.0.1:8008"
  public_base_url = "http://127.0.0.1:8008"

  [auth]
  builtin_oidc = true
  ```

- Element Web **v1.12.26** (release tarball, static files), with a config
  that points `m.homeserver` at Spindle with
  `"feature_oidc_native_flow": true`.
- `alice` registered beforehand through the ordinary password path.
- Nothing listens on 8080 (where MAS lived in the delegated-auth
  run). The script asserts this before it opens the browser.

## Transcript

```
0. precondition: nothing on 127.0.0.1:8080 — no MAS is running
1. open http://127.0.0.1:8888
2. click "a:has-text('Sign in')"
   url now: http://127.0.0.1:8888/#/login
3. click "button:has-text('Continue')"
   url now: http://127.0.0.1:8008/oauth2/authorize?response_type=code
     &response_mode=fragment&client_id=oc_04831ab54d0430e3129d45eef19d44ec
     &redirect_uri=http%3A%2F%2F127.0.0.1%3A8888%2F%3Fno_universal_links%3Dtrue
     &scope=urn%3Amatrix%3Aclient%3Aapi%3A*+urn%3Amatrix%3Aclient%3Adevice%3AU1ButcRtL4
     &state=xVcXT2J4LfhASxIWBeXSU4YvEuEBHF6P
     &code_challenge_method=S256&code_challenge=9Jq25fIfvlUfQBt1ndeNJF4STH7_MJprPZdqnlB8RYI
4. on SPINDLE's own login page — fill alice's credentials
   url now: http://127.0.0.1:8888/#/home
5. back in Element at http://127.0.0.1:8888/#/home; app shell rendered: True
6. provider traffic Element sent to spindle itself:
   /oauth2/registration
   /oauth2/authorize?response_type=code&response_mode=fragment&client_id=oc_04831ab5…
   /oauth2/authorize
   /oauth2/token
7. Element made 42 client-API calls to spindle
   /_matrix/client/versions
   /_matrix/client/unstable/org.matrix.msc2965/auth_metadata
   …
EVIDENCE: PASS — Element Web signed in through spindle's built-in
OIDC provider (no MAS anywhere) and is syncing
```

Every step of the modern flow is visible in that URL bar and traffic
log, all of it served by the one process:

- **Discovery** (MSC2965): Element fetched `auth_metadata` and accepted
  the document. Its `isValidAuthMetadata` needs `issuer`,
  `authorization_endpoint`, `token_endpoint`, `revocation_endpoint`,
  `registration_endpoint`, both `query` **and** `fragment` response
  modes, both grant types, and `S256`.
- **Dynamic registration** (RFC 7591): `POST /oauth2/registration`
  minted `oc_04831ab54d0430e3129d45eef19d44ec`.
- **Authorization** with mandatory PKCE `S256` and the **stable**
  MSC2967 scope form `urn:matrix:client:api:*` +
  `urn:matrix:client:device:U1ButcRtL4`. Current matrix-js-sdk generates
  this form. The provider also accepts the legacy
  `urn:matrix:org.matrix.msc2967.client:*` form that older bundles send.
- **Fragment response mode**: the code went back in the URL fragment,
  exactly as the SPA asked.
- **Token exchange** at `POST /oauth2/token`. The token that Element
  received is a native Spindle session. The app shell rendered
  ("Welcome @alice:127.0.0.1:8008"). Sync ran against the ordinary
  client API with no introspection hop anywhere.

Element chose the device ID `U1ButcRtL4` and named it in its scope. The
homeserver-side proof that the session is real: afterwards, alice's
device list contains `U1ButcRtL4`, next to her password-login devices:

```
GET /_matrix/client/v3/devices
  DEV83CA8CBA7329AB4C   (password login)
  DEV989FE140D172E362   (registration)
  U1ButcRtL4            (minted by the OAuth code exchange)
```

## What this run does not claim

The built-in provider is the floor for a single-node deployment:
password-backed code flow, refresh, revocation. Upstream identity
providers, SSO, email verification and the account-management UI remain
what `[auth.delegated]` and a real MAS are for. Config validation makes
the two mutually exclusive.
