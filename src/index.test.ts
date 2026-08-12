import { describe, expect, it, vi } from "vitest";
import { createVallumClient, VallumRenderRef } from "./index";

const encoder = new TextEncoder();
// Smallest valid PNG; the mock only needs a decodable payload.
const onePixelPNG =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

describe("@liteeagle226/client", () => {
  const original = {
    database_host: "prod-db-01.internal",
    nested: { enabled: true, nullable: null, unicode: "東京 🚀" },
    values: [1, false, null, { path: "/admin/v3" }],
  };

  for (const profile of [0, 1, 2]) {
    it(`reconstructs exact nested JSON for profile ${profile}`, async () => {
      const server = await mockServer({ profile, original });
      const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
      const response = await client.fetch("/api/internal/config");
      expect(await response.json()).toEqual(original);
      expect(response.headers.has("X-Vallum-Transform")).toBe(false);
    });
  }

  it("fails safely when ciphertext is tampered", async () => {
    const server = await mockServer({ profile: 0, original, tamper: true });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    await expect(client.fetch("/api/internal/config")).rejects.toThrow("integrity validation failed");
  });

  it("rejects a replayed response", async () => {
    const server = await mockServer({ profile: 1, original, replay: true });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    expect(await (await client.fetch("/api/internal/config")).json()).toEqual(original);
    await expect(client.fetch("/api/internal/config")).rejects.toThrow("replay detected");
  });

  it("rejects a replay after its counter leaves the retained window", async () => {
    const server = await mockServer({ profile: 0, original });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    expect(await (await client.fetch("/api/internal/config")).json()).toEqual(original);

    server.forceNextCounter(1_026);
    expect(await (await client.fetch("/api/internal/config?newer=1")).json()).toEqual(original);
    server.replayFirstResponse();

    await expect(client.fetch("/api/internal/config")).rejects.toThrow("replay detected");
  });

  it("rejects an expired protected response", async () => {
    const server = await mockServer({ profile: 0, original, expiredResponse: true });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    await expect(client.fetch("/api/internal/config")).rejects.toThrow("has expired");
  });

  it("handles concurrent out-of-order responses", async () => {
    const server = await mockServer({ profile: 2, original, outOfOrder: true });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    const responses = await Promise.all([
      client.fetch("/api/internal/config?request=one"),
      client.fetch("/api/internal/config?request=two"),
      client.fetch("/api/internal/config?request=three"),
    ]);
    await expect(Promise.all(responses.map((response) => response.json()))).resolves.toEqual([original, original, original]);
  });

  it("renews short-lived session material before a request", async () => {
    const server = await mockServer({ profile: 0, original, bootstrapTTL: 40 });
    const client = await createVallumClient({
      endpoint: "https://api.local", fetch: server.fetch, renewalWindowMs: 100,
    });
    expect(await (await client.fetch("/api/internal/config")).json()).toEqual(original);
    expect(server.bootstrapCount()).toBe(2);
  });

  it("wraps an existing fetch without changing application decoding", async () => {
    const server = await mockServer({ profile: 0, original });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    const secureFetch = client.wrapFetch(server.fetch);
    expect(await (await secureFetch("/api/internal/config")).json()).toEqual(original);
  });

  it("supports passing the protected fetch function to an API layer", async () => {
    const server = await mockServer({ profile: 0, original });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    const protectedFetch = client.fetch;

    expect(await (await protectedFetch("/api/internal/config")).json()).toEqual(original);
  });

  it("refuses to attach a session or proof to another origin", async () => {
    const server = await mockServer({ profile: 0, original });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });

    await expect(client.fetch("https://attacker.example/api/internal/config"))
      .rejects.toThrow("configured endpoint origin");
    expect(server.protectedCount()).toBe(0);
  });

  it("forbids redirects on control and protected requests", async () => {
    const server = await mockServer({ profile: 0, original });
    const redirects: RequestRedirect[] = [];
    const guardedFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? new Request(input, init) : new Request(input, init);
      redirects.push(request.redirect);
      return server.fetch(request);
    }) as typeof globalThis.fetch;
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: guardedFetch });
    await client.fetch("/api/internal/config");

    expect(redirects).toHaveLength(4);
    expect(redirects.every((redirect) => redirect === "error")).toBe(true);
  });

  it("releases session state and becomes unusable when destroyed", async () => {
    const server = await mockServer({ profile: 0, original });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });

    expect(client.destroyed).toBe(false);
    client.destroy();
    client.destroy();

    expect(client.destroyed).toBe(true);
    expect(() => client.fetch("/api/internal/config")).toThrow("has been destroyed");
    await expect(client.renew()).rejects.toThrow("has been destroyed");
    expect(() => client.wrapFetch(server.fetch)).toThrow("has been destroyed");
    await expect(client.mount({} as Element, new VallumRenderRef({
      png: onePixelPNG,
      width: 1,
      height: 1,
    }))).rejects.toThrow("has been destroyed");
  });

  it("aborts and rejects protected work that is in flight during destroy", async () => {
    const server = await mockServer({ profile: 0, original });
    let protectedSignal: AbortSignal | undefined;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const heldFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? new Request(input, init) : new Request(input, init);
      const response = await server.fetch(request);
      if (new URL(request.url).pathname === "/api/internal/config") {
        protectedSignal = request.signal;
        await gate;
      }
      return response;
    }) as typeof globalThis.fetch;
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: heldFetch });

    const pending = client.fetch("/api/internal/config");
    await vi.waitFor(() => expect(protectedSignal).toBeDefined());
    client.destroy();
    expect(protectedSignal?.aborted).toBe(true);
    release();

    await expect(pending).rejects.toThrow("has been destroyed");
  });

  it("preserves caller cancellation while adding lifecycle cancellation", async () => {
    const server = await mockServer({ profile: 0, original });
    let protectedSignal: AbortSignal | undefined;
    const waitingFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? new Request(input, init) : new Request(input, init);
      if (new URL(request.url).pathname !== "/api/internal/config") return server.fetch(request);
      protectedSignal = request.signal;
      return new Promise<Response>((_resolve, reject) => {
        request.signal.addEventListener("abort", () => reject(request.signal.reason), { once: true });
      });
    }) as typeof globalThis.fetch;
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: waitingFetch });
    const controller = new AbortController();

    const pending = client.fetch("/api/internal/config", { signal: controller.signal });
    await vi.waitFor(() => expect(protectedSignal).toBeDefined());
    controller.abort(new Error("caller cancelled"));

    expect(protectedSignal?.aborted).toBe(true);
    await expect(pending).rejects.toThrow("caller cancelled");
  });

  it("propagates caller cancellation into deferred disclosure", async () => {
    const server = await mockServer({ profile: 0, original, defer: ["database_host"] });
    let disclosureSignal: AbortSignal | undefined;
    let disclosureStarted!: () => void;
    const started = new Promise<void>((resolve) => { disclosureStarted = resolve; });
    const waitingFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? new Request(input, init) : new Request(input, init);
      if (new URL(request.url).pathname !== "/__vallum/disclose") return server.fetch(request);
      disclosureSignal = request.signal;
      disclosureStarted();
      return new Promise<Response>((_resolve, reject) => {
        const abort = () => reject(request.signal.reason);
        if (request.signal.aborted) abort();
        else request.signal.addEventListener("abort", abort, { once: true });
      });
    }) as typeof globalThis.fetch;
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: waitingFetch });
    const controller = new AbortController();

    const pending = client.fetch("/api/internal/config", { signal: controller.signal });
    await started;
    controller.abort(new Error("caller cancelled disclosure"));

    expect(disclosureSignal?.aborted).toBe(true);
    await expect(pending).rejects.toThrow("caller cancelled disclosure");
    expect(server.discloseCount()).toBe(0);
  });

  it("does not swallow caller cancellation while reading a protected body", async () => {
    const server = await mockServer({ profile: 0, original });
    let bodyReadStarted!: () => void;
    const started = new Promise<void>((resolve) => { bodyReadStarted = resolve; });
    const streamingFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? new Request(input, init) : new Request(input, init);
      const response = await server.fetch(request);
      if (new URL(request.url).pathname !== "/api/internal/config") return response;
      const body = await response.text();
      let listening = false;
      const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
          if (listening) return;
          listening = true;
          bodyReadStarted();
          request.signal.addEventListener("abort", () => controller.error(request.signal.reason), { once: true });
          // The body is deliberately held. If cancellation were swallowed,
          // returning this response would expose the raw transport document.
          void body;
        },
      });
      return new Response(stream, { status: response.status, headers: response.headers });
    }) as typeof globalThis.fetch;
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: streamingFetch });
    const controller = new AbortController();

    const pending = client.fetch("/api/internal/config", { signal: controller.signal });
    await started;
    controller.abort(new Error("cancelled body read"));

    await expect(pending).rejects.toThrow("cancelled body read");
  });

  it("serializes an explicit renewal behind an active protected exchange", async () => {
    const server = await mockServer({ profile: 0, original });
    const events: string[] = [];
    let initialized = false;
    let requestStarted!: () => void;
    const started = new Promise<void>((resolve) => { requestStarted = resolve; });
    let releaseRequest!: () => void;
    const release = new Promise<void>((resolve) => { releaseRequest = resolve; });
    const delayedFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? new Request(input, init) : new Request(input, init);
      const path = new URL(request.url).pathname;
      if (initialized && path === "/__vallum/challenge") events.push("renewal");
      if (path === "/api/internal/config") {
        events.push("request");
        requestStarted();
        await release;
        events.push("response");
      }
      return server.fetch(request);
    }) as typeof globalThis.fetch;
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: delayedFetch });
    initialized = true;

    const response = client.fetch("/api/internal/config");
    await started;
    const renewal = client.renew();
    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(events).toEqual(["request"]);

    releaseRequest();
    expect(await (await response).json()).toEqual(original);
    await renewal;
    expect(events).toEqual(["request", "response", "renewal"]);
  });

  it("preserves reconstructed Response metadata on the response and its clones", async () => {
    const server = await mockServer({ profile: 0, original });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    const response = await client.fetch("/api/internal/config?metadata=1");
    const clone = response.clone();

    for (const candidate of [response, clone]) {
      expect(candidate.url).toBe("https://api.local/api/internal/config?metadata=1");
      expect(candidate.type).toBe("basic");
      expect(candidate.redirected).toBe(false);
    }
  });

  it("gives Response clones independent reconstructed JSON graphs", async () => {
    const server = await mockServer({ profile: 0, original });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    const response = await client.fetch("/api/internal/config");
    const clone = response.clone();
    const first = await response.json() as typeof original;
    const second = await clone.json() as typeof original;

    expect(first).not.toBe(second);
    expect(first.nested).not.toBe(second.nested);
    first.nested.enabled = false;
    expect(second.nested.enabled).toBe(true);
  });

  it("rejects cloning a reconstructed Response with a locked body", async () => {
    const server = await mockServer({ profile: 0, original });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    const response = await client.fetch("/api/internal/config");
    const reader = response.body?.getReader();

    expect(() => response.clone()).toThrow(TypeError);
    await reader?.cancel();
    reader?.releaseLock();
  });

   it("reconstructs without depending on an overt transform header and preserves ordinary JSON", async () => {
     const server = await mockServer({ profile: 0, original });
     const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
     expect(await (await client.fetch("/api/internal/config")).json()).toEqual(original);
     const ordinary = await client.fetch("/api/public/status");
     expect(await ordinary.json()).toEqual({ status: "ok" });
   });

   it("signs concurrent requests with valid unique proof identifiers", async () => {
     const server = await mockServer({ profile: 0, original, outOfOrder: true });
     const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
     await Promise.all([
     client.fetch("/api/internal/config?a=1"),
     client.fetch("/api/internal/config?a=2"),
     client.fetch("/api/internal/config?a=3"),
     ]);
     expect(server.proofCount()).toBe(3);
     expect(server.admissionUsedPublicProofOnly()).toBe(true);
   });

   it("renews and retries a proof rejection only for GET", async () => {
     const getServer = await mockServer({ profile: 0, original, rejectFirstProof: true });
     const getClient = await createVallumClient({ endpoint: "https://api.local", fetch: getServer.fetch });
     expect(await (await getClient.fetch("/api/internal/config")).json()).toEqual(original);
     expect(getServer.bootstrapCount()).toBe(2);

     const postServer = await mockServer({ profile: 0, original, rejectFirstProof: true });
     const postClient = await createVallumClient({ endpoint: "https://api.local", fetch: postServer.fetch });
     const response = await postClient.fetch("/api/internal/config", { method: "POST", body: "payload" });
     expect(response.status).toBe(428);
     expect(postServer.bootstrapCount()).toBe(1);
   });

  it("restores withheld values transparently so application code is unchanged", async () => {
    const server = await mockServer({ profile: 0, original, defer: ["database_host", "values"] });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    const response = await client.fetch("/api/internal/config");
    // The application receives the exact origin object. It never sees a
    // handle, and it made one call.
    expect(await response.json()).toEqual(original);
    expect(server.discloseCount()).toBe(1);
    expect(server.redeemedCount()).toBe(2);
  });

  it("does not call the disclosure endpoint when nothing was withheld", async () => {
    const server = await mockServer({ profile: 1, original });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    expect(await (await client.fetch("/api/internal/config")).json()).toEqual(original);
    expect(server.discloseCount()).toBe(0);
  });

  it("restores a withheld value nested inside arrays and objects", async () => {
    const nested = { outer: { inner: [{ secret: "one" }, { secret: "two" }] } };
    const server = await mockServer({ profile: 2, original: nested, defer: ["outer"] });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    expect(await (await client.fetch("/api/internal/config")).json()).toEqual(nested);
  });

  it("fails loudly rather than returning a placeholder when the budget is exhausted", async () => {
    const server = await mockServer({
      profile: 0, original, defer: ["database_host"], disclosureBudget: 0,
    });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    await expect(client.fetch("/api/internal/config")).rejects.toThrow("disclosure budget is exhausted");
  });

  it("fails closed before redemption when a document exceeds the deferred-reference cap", async () => {
    const wide = Object.fromEntries(Array.from({ length: 257 }, (_, index) => [`field_${index}`, `value_${index}`]));
    const server = await mockServer({ profile: 0, original: wide, defer: Object.keys(wide) });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });

    await expect(client.fetch("/api/internal/config")).rejects.toThrow("too many deferred values");
    expect(server.discloseCount()).toBe(0);
  });

  it("signs the disclosure request with a request proof", async () => {
    // The mock rejects any unproved request with 428, so a successful
    // redemption proves the SDK signed it with the session's proof key.
    const server = await mockServer({ profile: 1, original, defer: ["database_host"] });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    expect(await (await client.fetch("/api/internal/config")).json()).toEqual(original);
    expect(server.proofCount()).toBe(2);
  });

  it("fails closed when a handle cannot be redeemed", async () => {
    const server = await mockServer({ profile: 0, original, defer: ["database_host"] });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    expect(await (await client.fetch("/api/internal/config")).json()).toEqual(original);
    // Handles are single-use. A replayed protected body cannot be restored a
    // second time, so the SDK must throw instead of surfacing a placeholder.
    const replayServer = await mockServer({ profile: 0, original, defer: ["database_host"], replay: true });
    const replayClient = await createVallumClient({ endpoint: "https://api.local", fetch: replayServer.fetch });
    expect(await (await replayClient.fetch("/api/internal/config")).json()).toEqual(original);
    await expect(replayClient.fetch("/api/internal/config")).rejects.toThrow();
  });

  it("delivers a render-only value as pixels, never as a string", async () => {
    const server = await mockServer({
      profile: 0, original, defer: ["database_host"], renderOnly: ["database_host"],
    });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    const document = await (await client.fetch("/api/internal/config")).json() as Record<string, unknown>;

    // The live one-shot reference reaches framework adapters, while accidental
    // serialization remains a mask and never includes the underlying pixels.
    expect(client.isRenderOnly(document.database_host)).toBe(true);
    expect(document.database_host).toBeInstanceOf(VallumRenderRef);
    expect(JSON.stringify(document)).not.toContain("prod-db-01.internal");
    // Unrelated fields are untouched.
    expect(document.values).toEqual(original.values);
  });

  it("masks a render-only value if it is accidentally interpolated", async () => {
    const server = await mockServer({
      profile: 1, original, defer: ["database_host"], renderOnly: ["database_host"],
    });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    const response = await client.fetch("/api/internal/config");
    // Text and logging paths receive only the masked JSON body.
    const text = await response.text();
    expect(text).not.toContain("prod-db-01.internal");
    expect(text).toContain("\u2022");
  });

  it("mixes render-only and ordinary deferred values in one batch", async () => {
    const server = await mockServer({
      profile: 2, original, defer: ["database_host", "values"], renderOnly: ["database_host"],
    });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    const document = await (await client.fetch("/api/internal/config")).json() as Record<string, unknown>;
    // One redemption call covers both classes.
    expect(server.discloseCount()).toBe(1);
    // The ordinary deferred value is restored exactly; the render-only one is not text.
    expect(document.values).toEqual(original.values);
    expect(client.isRenderOnly(document.database_host)).toBe(true);
    expect(JSON.stringify(document)).not.toContain("prod-db-01.internal");
  });

  it("preserves live render references through a Response clone", async () => {
    const server = await mockServer({
      profile: 0, original, defer: ["database_host"], renderOnly: ["database_host"],
    });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    const response = await client.fetch("/api/internal/config");
    const clone = response.clone();

    const originalDocument = await response.json() as Record<string, unknown>;
    const clonedDocument = await clone.json() as Record<string, unknown>;
    expect(client.isRenderOnly(originalDocument.database_host)).toBe(true);
    expect(client.isRenderOnly(clonedDocument.database_host)).toBe(true);
    expect(clonedDocument.database_host).toBe(originalDocument.database_host);
    const reference = originalDocument.database_host as VallumRenderRef;
    expect(reference.take()?.png).toBe(onePixelPNG);
    expect((clonedDocument.database_host as VallumRenderRef).consumed).toBe(true);
    expect(clone.bodyUsed).toBe(true);
  });

  it("exposes a render reference that releases its pixels after one read", () => {
    const reference = new VallumRenderRef({ png: onePixelPNG, width: 40, height: 20 });
    expect(reference.consumed).toBe(false);
    expect(reference.width).toBe(40);
    expect(String(reference)).not.toContain("prod-db");
    expect(reference.take()?.png).toBe(onePixelPNG);
    // A later heap or state dump finds nothing.
    expect(reference.consumed).toBe(true);
    expect(reference.take()).toBeUndefined();
  });

  it("does not consume a render reference when an asynchronous paint is cancelled", async () => {
    const server = await mockServer({ profile: 0, original });
    const client = await createVallumClient({ endpoint: "https://api.local", fetch: server.fetch });
    const nativeAtob = globalThis.atob.bind(globalThis);
    const strictAtob = vi.fn((value: string) => {
      if (value.length % 4 !== 0) throw new Error("base64 padding required");
      return nativeAtob(value);
    });
    vi.stubGlobal("atob", strictAtob);
    const reference = new VallumRenderRef({
      png: onePixelPNG.replace(/=+$/, ""),
      width: 40,
      height: 20,
    });
    let resolveBitmap!: (bitmap: ImageBitmap) => void;
    const bitmap = { close: vi.fn() } as unknown as ImageBitmap;
    vi.stubGlobal("createImageBitmap", vi.fn(() => new Promise<ImageBitmap>((resolve) => {
      resolveBitmap = resolve;
    })));
    const controller = new AbortController();

    const pending = client.mount({} as Element, reference, { signal: controller.signal });
    await vi.waitFor(() => expect(resolveBitmap).toEqual(expect.any(Function)));
    controller.abort(new Error("obsolete paint"));
    resolveBitmap(bitmap);

    await expect(pending).rejects.toThrow("obsolete paint");
    expect(reference.consumed).toBe(false);
    expect(bitmap.close).toHaveBeenCalledOnce();
    expect(strictAtob).toHaveBeenCalledWith(expect.stringMatching(/={1,2}$/));
    vi.unstubAllGlobals();
  });

  it("fails closed when the application denies decoding admission", async () => {
    const server = await mockServer({ profile: 0, original, admissionDenied: true });
    await expect(createVallumClient({ endpoint: "https://api.local", fetch: server.fetch }))
      .rejects.toThrow("decoding admission failed (403)");
    expect(server.protectedCount()).toBe(0);
    expect(server.bootstrapCount()).toBe(0);
  });
});

interface ServerOptions {
  profile: number;
  original: unknown;
  tamper?: boolean;
  replay?: boolean;
  expiredResponse?: boolean;
  outOfOrder?: boolean;
  bootstrapTTL?: number;
  admissionDenied?: boolean;
   rejectFirstProof?: boolean;
  /** Top-level members of `original` the proxy withholds from the response. */
  defer?: string[];
  /** Total values this session may redeem before the budget is exhausted. */
  disclosureBudget?: number;
  /** Deferred members returned as pixels instead of text. */
  renderOnly?: string[];
}

async function mockServer(options: ServerOptions): Promise<{
  fetch: typeof globalThis.fetch;
  bootstrapCount(): number;
  protectedCount(): number;
   proofCount(): number;
   admissionUsedPublicProofOnly(): boolean;
  discloseCount(): number;
  redeemedCount(): number;
  forceNextCounter(counter: number): void;
  replayFirstResponse(): void;
}> {
  let state: {
    session: string;
    keyID: string;
    metadataKey: string;
    expiresMS: number;
  key: CryptoKey;
  proofKey: CryptoKey;
  serverNonce: string;
  seenProofs: Set<string>;
  } | undefined;
  let bootstrapCount = 0;
  let counter = 0;
  let protectedCount = 0;
  let replayBody = "";
  let forcedCounter: number | undefined;
  let replayOnNextRequest = false;
  let proofCount = 0;
  let rejectedProof = false;
  let publicProofOnly = false;
  // handle -> withheld value. Redemption removes the entry, so a handle is
  // single-use exactly as the proxy enforces it.
  let withheld = new Map<string, unknown>();
  let renderHandles = new Set<string>();
  let disclosureSpent = 0;
  let discloseCount = 0;
  let redeemedCount = 0;

  const fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const request = input instanceof Request ? new Request(input, init) : new Request(input, init);
    const path = new URL(request.url).pathname;
    if (path === "/__vallum/challenge") {
      return Response.json({
        version: 1, session: `sess_browser_${bootstrapCount + 1}`,
    expires_at: new Date(Date.now() + 60_000).toISOString(), admission_required: true,
    server_nonce: `challenge_nonce_${bootstrapCount + 1}`,
      }, { status: 201 });
    }
    if (path === "/.well-known/vallum/admission") {
      if (options.admissionDenied) return Response.json({ error: "denied" }, { status: 403 });
    const body = await request.json() as { public_key: JsonWebKey; proof_key: JsonWebKey; session: string };
    if (!body.public_key || !body.proof_key || !body.session) return Response.json({ error: "invalid" }, { status: 400 });
    publicProofOnly = body.proof_key.kty === "EC" && body.proof_key.crv === "P-256" && !body.proof_key.d;
      return Response.json({ admission: `signed-admission-${body.session}` }, { status: 201 });
    }
    if (path === "/__vallum/session") {
      bootstrapCount++;
    const body = await request.json() as { public_key: JsonWebKey; proof_key: JsonWebKey; admission: string };
    if (!body.admission || !body.proof_key) return Response.json({ error: "denied" }, { status: 403 });
      const publicKey = await crypto.subtle.importKey(
        "jwk", body.public_key,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false, ["encrypt"],
      );
      const rawKey = randomBytes(32);
      const session = `sess_browser_${bootstrapCount}`;
      const keyID = `epoch_${bootstrapCount}`;
      const label = encoder.encode(`vallum-session-v1:${session}:${keyID}`);
      const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP", label }, publicKey, rawKey);
      const ttl = options.bootstrapTTL ?? 60_000;
    const expiresMS = Date.now() + ttl;
    const serverNonce = encodeBase64URL(randomBytes(18));
    const proofKey = await crypto.subtle.importKey(
    "jwk", body.proof_key, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"],
    );
    state = {
    session, keyID, metadataKey: `__m_${bootstrapCount}`, expiresMS,
    key: await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt"]),
    proofKey, serverNonce, seenProofs: new Set(),
      };
      counter = 0;
      replayBody = "";
      return Response.json({
    version: 1, session, expires_at: new Date(expiresMS).toISOString(), server_nonce: serverNonce,
        key_id: keyID, profile: options.profile, metadata_key: state.metadataKey, view_key: "view_x",
        wrapped_key: encodeBase64URL(new Uint8Array(wrapped)), algorithm: "RSA-OAEP-256+A256GCM",
    session_header: "X-Vallum-Session", proof_header: "X-Vallum-Proof",
      }, { status: 201 });
    }
  if (!state) return Response.json({ error: "no session" }, { status: 428 });
  protectedCount++;
  if (options.rejectFirstProof && !rejectedProof) {
    rejectedProof = true;
    return Response.json({ error: "request proof required", server_nonce: encodeBase64URL(randomBytes(18)) }, {
    status: 428, headers: { "X-Vallum-Proof-Required": "1", "X-Vallum-Nonce": encodeBase64URL(randomBytes(18)) },
    });
  }
  const proofValid = await validateRequestProof(request, state);
  if (!proofValid) {
    return Response.json({ error: "request proof required", server_nonce: encodeBase64URL(randomBytes(18)) }, {
    status: 428, headers: { "X-Vallum-Proof-Required": "1", "X-Vallum-Nonce": encodeBase64URL(randomBytes(18)) },
    });
  }
  proofCount++;
  if (path === "/__vallum/disclose") {
    discloseCount++;
    const body = await request.json() as { handles: string[] };
    const budget = options.disclosureBudget ?? 1_000;
    if (disclosureSpent + body.handles.length > budget) {
      return Response.json({ error: "disclosure budget exhausted" }, { status: 429 });
    }
    disclosureSpent += body.handles.length;
    const results = body.handles.map((handle) => {
      if (!withheld.has(handle)) return { handle, error: "unknown" };
      const value = withheld.get(handle);
      const isRender = renderHandles.has(handle);
      withheld.delete(handle);
      renderHandles.delete(handle);
      redeemedCount++;
      // A render-only field is returned as pixels. The mock emits a 1x1 PNG:
      // the SDK must never turn it back into a string.
      if (isRender) {
        return { handle, render: { png: onePixelPNG, width: 40, height: 20 } };
      }
      return { handle, value };
    });
    return Response.json({ version: 1, session: state.session, results });
  }
  if (path === "/api/public/status") return Response.json({ status: "ok" });
    if ((options.replay || replayOnNextRequest) && replayBody) {
    replayOnNextRequest = false;
    return new Response(replayBody, { headers: { "Content-Type": "application/json" } });
    }
    const responseCounter = forcedCounter ?? counter + 1;
    forcedCounter = undefined;
    counter = Math.max(counter, responseCounter);
    const expiresMS = options.expiredResponse ? Date.now() - 1 : state.expiresMS;
    const routeTag = "route-tag";
    const nonce = randomBytes(12);
    const aad = encoder.encode(`1\n${state.session}\n${state.keyID}\n${responseCounter}\n${expiresMS}\n${options.profile}\n${routeTag}`);
    // Withheld values are removed before encryption, so they are absent from
    // the ciphertext exactly as the proxy produces it.
    let canonical: unknown = options.original;
    if (options.defer?.length) {
      const document = structuredClone(options.original) as Record<string, unknown>;
      for (const field of options.defer) {
        if (!(field in document)) continue;
        const handle = `vdf_${encodeBase64URL(randomBytes(18))}`;
        withheld.set(handle, document[field]);
        if (options.renderOnly?.includes(field)) renderHandles.add(handle);
        document[field] = { $vallum_ref: handle };
      }
      canonical = document;
    }
    const ciphertextBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      state.key,
      encoder.encode(JSON.stringify(canonical)),
    );
    const ciphertext = new Uint8Array(ciphertextBuffer);
    if (options.tamper) ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;
    const metadata = envelopeMetadata(options.profile, state, responseCounter, expiresMS, nonce, routeTag, ciphertext);
    const body = JSON.stringify({ false_value: "plausible", [state.metadataKey]: metadata });
    if (!replayBody) replayBody = body;
    if (options.outOfOrder) await new Promise((resolve) => setTimeout(resolve, (4 - responseCounter) * 4));
    const protectedResponse = new Response(body, {
    headers: { "Content-Type": "application/json" },
    });
    Object.defineProperties(protectedResponse, {
      url: { configurable: true, value: request.url },
      type: { configurable: true, value: "basic" },
      redirected: { configurable: true, value: false },
    });
    return protectedResponse;
  }) as typeof globalThis.fetch;

  return {
    fetch,
    bootstrapCount: () => bootstrapCount,
    protectedCount: () => protectedCount,
    proofCount: () => proofCount,
    admissionUsedPublicProofOnly: () => publicProofOnly,
    discloseCount: () => discloseCount,
    redeemedCount: () => redeemedCount,
    forceNextCounter: (value) => { forcedCounter = value; },
    replayFirstResponse: () => { replayOnNextRequest = true; },
  };
}

async function validateRequestProof(
  request: Request,
  state: { session: string; keyID: string; proofKey: CryptoKey; serverNonce: string; seenProofs: Set<string> },
): Promise<boolean> {
  const raw = request.headers.get("X-Vallum-Proof") ?? "";
  const [payloadText, signatureText, extra] = raw.split(".");
  if (!payloadText || !signatureText || extra) return false;
  let claims: Record<string, unknown>;
  try {
    claims = JSON.parse(new TextDecoder().decode(decodeBase64URL(payloadText))) as Record<string, unknown>;
  } catch {
    return false;
  }
  const url = new URL(request.url);
  const uri = url.pathname + url.search;
  const body = request.body === null ? new ArrayBuffer(0) : await request.clone().arrayBuffer();
  const expectedHash = body.byteLength === 0
    ? "UNSIGNED-PAYLOAD"
    : encodeBase64URL(new Uint8Array(await crypto.subtle.digest("SHA-256", body)));
  if (claims.v !== 1 || claims.s !== state.session || claims.k !== state.keyID ||
    claims.m !== request.method || claims.u !== uri || claims.h !== expectedHash || claims.n !== state.serverNonce ||
    typeof claims.t !== "number" || Math.abs(Date.now() - claims.t) > 25_000 || typeof claims.j !== "string" ||
    state.seenProofs.has(claims.j)) return false;
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, state.proofKey, decodeBase64URL(signatureText),
    encoder.encode(`vallum-request-proof-v1.${payloadText}`),
  );
  if (valid) state.seenProofs.add(claims.j);
  return valid;
}

function envelopeMetadata(
  profile: number,
  state: { session: string; keyID: string },
  counter: number,
  expiresMS: number,
  nonce: Uint8Array<ArrayBuffer>,
  routeTag: string,
  ciphertext: Uint8Array<ArrayBufferLike>,
): unknown {
  const encoded = encodeBase64URL(ciphertext);
  const midpoint = Math.ceil(encoded.length / 2);
  const chunks = [encoded.slice(0, midpoint), encoded.slice(midpoint)];
  const nonceText = encodeBase64URL(nonce);
  if (profile === 1) {
    return [1, state.session, state.keyID, counter, expiresMS, nonceText, routeTag, [["b", chunks[1]], ["a", chunks[0]]]];
  }
  if (profile === 2) {
    return {
      revision: 1, subject: state.session, epoch: state.keyID,
      proof: { counter, until: expiresMS, iv: nonceText }, route: routeTag,
      parts: { a: chunks[0], b: chunks[1] }, order: ["a", "b"],
    };
  }
  return { v: 1, s: state.session, k: state.keyID, q: counter, x: expiresMS, n: nonceText, r: routeTag, c: chunks };
}

function randomBytes(size: number): Uint8Array<ArrayBuffer> {
  const value = new Uint8Array(new ArrayBuffer(size));
  crypto.getRandomValues(value);
  return value;
}

function encodeBase64URL(value: Uint8Array<ArrayBufferLike>): string {
  let binary = "";
  for (const item of value) binary += String.fromCharCode(item);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeBase64URL(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  const output = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index++) output[index] = binary.charCodeAt(index);
  return output;
}
