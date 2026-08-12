# `@liteeagle226/client`

Framework-agnostic browser client for Vallum. It establishes a short-lived,
application-admitted session, signs protected requests, verifies transformed
responses, and returns an ordinary `Response` containing the origin JSON.

```sh
npm install @liteeagle226/client
```

The browser client also requires a trusted same-origin admission broker. Use
`npm install @liteeagle226/admission` for a framework-neutral Node backend, or
use `@liteeagle226/nextjs/server` in a Next.js application.

```ts
import { createVallumClient } from "@liteeagle226/client";

const vallum = await createVallumClient({
  endpoint: window.location.origin,
});

const response = await vallum.fetch("/api/protected");
const data = await response.json();

// Release in-memory session and key references when the owning UI unmounts.
vallum.destroy();
```

The client requires a secure browser context with Fetch, Web Crypto, and the
standard URL/Request/Response APIs. It is import-safe during SSR, but client
creation belongs in a browser lifecycle hook. Do not monkey-patch
`window.fetch`; pass `vallum.fetch` to your application API layer or call
`vallum.wrapFetch(existingFetch)`.

Ordinary objects returned from a cloned response have independent container
graphs. Render-only references are deliberately shared across response clones,
however, so cloning cannot duplicate protected pixels or bypass their one-shot
consumption and heap release.

Protected and session-control requests reject HTTP redirects. Redirecting a
proof-bearing request could disclose its short-lived session headers to a
different origin; call the final same-origin route directly instead.

Before creation, the application must establish its normal authenticated
session. Its trusted backend must expose `POST /.well-known/vallum/admission`;
use `@liteeagle226/admission` or `@liteeagle226/nextjs/server`. Never ship the admission
signing key to this package or any browser bundle.

First-party integrations are available for React, Next.js, Vue/Nuxt, Svelte,
Angular, and zero-build HTML. The repository contains the
[full protocol, deployment, render-only, and security documentation](https://github.com/LiteEagle262/vallum/tree/main/docs).
