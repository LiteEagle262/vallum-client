export interface VallumClientOptions {
  endpoint: string;
  fetch?: typeof globalThis.fetch;
  sessionPath?: string;
  challengePath?: string;
  admissionPath?: string;
  renewalWindowMs?: number;
}

export interface VallumClient {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  wrapFetch(implementation: typeof globalThis.fetch): typeof globalThis.fetch;
  renew(): Promise<void>;
  /**
   * Paints a render-only value into `element` as pixels.
   *
   * Render-only values never exist as a string in the browser, so they cannot
   * be interpolated into markup. Mount them instead. After painting, the
   * pixel payload is released from the reference, so a later heap or state
   * dump does not recover it either.
   *
   * Accessibility: a canvas is invisible to assistive technology. Supply
   * `accessibleLabel` for users who need it — doing so intentionally puts the
   * value back into the accessibility tree for that user, so gate it on an
   * account-level preference rather than enabling it globally.
   */
  mount(element: Element, value: unknown, options?: MountOptions): Promise<boolean>;
  /** True when `value` is a render-only reference that must be mounted. */
  isRenderOnly(value: unknown): boolean;
}

export interface MountOptions {
  /** Re-exposes the value to assistive technology. Off by default. */
  accessibleLabel?: string;
  /** CSS pixel height. Defaults to the rendered height at device scale. */
  height?: number;
}

interface BootstrapResponse {
  version: number;
  session: string;
  expires_at: string;
  server_nonce: string;
  key_id: string;
  profile: number;
  metadata_key: string;
  view_key: string;
  wrapped_key: string;
  algorithm: string;
  session_header: string;
  proof_header: string;
}

interface ChallengeResponse {
  version: number;
  session: string;
  expires_at: string;
  admission_required: boolean;
  server_nonce: string;
}

interface AdmissionResponse {
  admission: string;
  expires_at?: string;
}

interface DecodingState extends BootstrapResponse {
  key: CryptoKey;
  proofKey: CryptoKey;
  expiresAtMs: number;
}

interface Envelope {
  version: number;
  session: string;
  keyID: string;
  counter: number;
  expiresMS: number;
  nonce: string;
  routeTag: string;
  ciphertext: string;
}

interface DeferredReference {
  handle: string;
  assign(value: unknown): void;
}

interface RenderPayload {
  png: string;
  width: number;
  height: number;
}

/**
 * A protected value delivered as pixels rather than text.
 *
 * The plaintext was rendered by the proxy and never sent as a string. Nothing
 * in this object, the DOM, or the accessibility tree contains it. Reading it
 * requires capturing the painted canvas and running OCR.
 *
 * `toString()` deliberately yields a mask rather than throwing, so accidental
 * interpolation renders a placeholder instead of crashing or leaking.
 */
export class VallumRenderRef {
  readonly kind = "vallum-render-ref";
  #payload: RenderPayload | undefined;

  constructor(payload: RenderPayload) {
    this.#payload = payload;
  }

  get width(): number { return this.#payload?.width ?? 0; }
  get height(): number { return this.#payload?.height ?? 0; }
  get consumed(): boolean { return this.#payload === undefined; }

  /** Returns the payload once and releases it. */
  take(): RenderPayload | undefined {
    const payload = this.#payload;
    this.#payload = undefined;
    return payload;
  }

  toString(): string { return "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"; }
  toJSON(): string { return this.toString(); }
}

function isRenderPayload(value: unknown): value is RenderPayload {
  return isRecord(value) && typeof value.png === "string" && value.png.length > 0 &&
    typeof value.width === "number" && typeof value.height === "number";
}

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const unsignedPayloadMarker = "UNSIGNED-PAYLOAD";
const requestProofDomain = "vallum-request-proof-v1.";
const deferredRefKey = "$vallum_ref";
const disclosurePath = "/__vallum/disclose";
const disclosureBatchSize = 64;
const maxDeferredReferences = 256;

/**
 * Returns the handle when the node is exactly `{"$vallum_ref": "<handle>"}`.
 * Requiring a sole member keeps an application object that happens to contain
 * the key alongside real data from being mistaken for a placeholder.
 */
function deferredHandleOf(value: unknown): string | undefined {
  if (!isRecord(value)) return undefined;
  const keys = Object.keys(value);
  if (keys.length !== 1 || keys[0] !== deferredRefKey) return undefined;
  const handle = value[deferredRefKey];
  return typeof handle === "string" && handle.length > 0 ? handle : undefined;
}

/**
 * Walks the reconstructed document for withheld-value placeholders, recording
 * how to write each one back in place. Bounded so a malformed document cannot
 * drive unbounded work in the browser.
 */
function collectDeferredReferences(node: unknown, out: DeferredReference[], depth = 0): void {
  if (depth > 64 || out.length > maxDeferredReferences) return;
  if (Array.isArray(node)) {
    for (let index = 0; index < node.length; index++) {
      const child = node[index];
      const handle = deferredHandleOf(child);
      if (handle !== undefined) {
        out.push({ handle, assign: (value) => { node[index] = value; } });
        continue;
      }
      collectDeferredReferences(child, out, depth + 1);
    }
    return;
  }
  if (!isRecord(node)) return;
  for (const key of Object.keys(node)) {
    const child = node[key];
    const handle = deferredHandleOf(child);
    if (handle !== undefined) {
      out.push({ handle, assign: (value) => { node[key] = value; } });
      continue;
    }
    collectDeferredReferences(child, out, depth + 1);
  }
}

export async function createVallumClient(options: VallumClientOptions): Promise<VallumClient> {
  const client = new BrowserVallumClient(options);
  await client.renew();
  return client;
}

class BrowserVallumClient implements VallumClient {
  private readonly endpoint: string;
  private readonly baseFetch: typeof globalThis.fetch;
  private readonly sessionPath: string;
  private readonly challengePath: string;
  private readonly admissionPath: string;
  private readonly renewalWindowMs: number;
  private state?: DecodingState;
  private renewal?: Promise<void>;
  private readonly replayByEpoch = new Map<string, { seen: Set<number>; pending: Set<number>; highest: number }>();

  constructor(options: VallumClientOptions) {
    if (!options.endpoint) throw new Error("Vallum endpoint is required");
    this.endpoint = options.endpoint.replace(/\/$/, "");
    this.baseFetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.sessionPath = options.sessionPath ?? "/__vallum/session";
    this.challengePath = options.challengePath ?? "/__vallum/challenge";
    this.admissionPath = options.admissionPath ?? "/.well-known/vallum/admission";
    this.renewalWindowMs = options.renewalWindowMs ?? 5_000;
  }

  async renew(): Promise<void> {
    if (this.renewal) return this.renewal;
    this.renewal = this.establishSession().finally(() => {
      this.renewal = undefined;
    });
    return this.renewal;
  }

  wrapFetch(implementation: typeof globalThis.fetch): typeof globalThis.fetch {
    return ((input: RequestInfo | URL, init?: RequestInit) => this.protectedFetch(implementation, input, init)) as typeof globalThis.fetch;
  }

  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    return this.protectedFetch(this.baseFetch, input, init);
  }

  private async establishSession(): Promise<void> {
    const keyPair = await crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      false,
      ["encrypt", "decrypt"],
    );
    const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const proofKeyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    );
    const proofPublicKey = await crypto.subtle.exportKey("jwk", proofKeyPair.publicKey);
    const challengeResponse = await this.baseFetch(new URL(this.challengePath, this.endpoint), {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!challengeResponse.ok) throw new Error(`Vallum session challenge failed (${challengeResponse.status})`);
    const challenge = (await challengeResponse.json()) as ChallengeResponse;
    validateChallenge(challenge);

    let admission = "";
    if (challenge.admission_required) {
      const admissionResponse = await this.baseFetch(new URL(this.admissionPath, this.endpoint), {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ public_key: publicKey, proof_key: proofPublicKey, session: challenge.session }),
      });
      if (!admissionResponse.ok) throw new Error(`Vallum decoding admission failed (${admissionResponse.status})`);
      const issued = (await admissionResponse.json()) as AdmissionResponse;
      if (!issued || typeof issued.admission !== "string" || issued.admission.length < 16) {
        throw new Error("Vallum decoding admission response is invalid");
      }
      admission = issued.admission;
    }
    const response = await this.baseFetch(new URL(this.sessionPath, this.endpoint), {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ public_key: publicKey, proof_key: proofPublicKey, admission }),
    });
    if (!response.ok) throw new Error(`Vallum session bootstrap failed (${response.status})`);
    const bootstrap = (await response.json()) as BootstrapResponse;
    validateBootstrap(bootstrap);
    const label = encoder.encode(`vallum-session-v1:${bootstrap.session}:${bootstrap.key_id}`);
    const rawKey = await crypto.subtle.decrypt(
      { name: "RSA-OAEP", label },
      keyPair.privateKey,
      decodeBase64URL(bootstrap.wrapped_key),
    );
    const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
    this.state = { ...bootstrap, key, proofKey: proofKeyPair.privateKey, expiresAtMs: Date.parse(bootstrap.expires_at) };
    this.replayByEpoch.set(bootstrap.key_id, { seen: new Set(), pending: new Set(), highest: 0 });
    while (this.replayByEpoch.size > 3) this.replayByEpoch.delete(this.replayByEpoch.keys().next().value!);
  }

  private async protectedFetch(implementation: typeof globalThis.fetch, input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    if (!this.state || Date.now() + this.renewalWindowMs >= this.state.expiresAtMs) await this.renew();
    let responseState = this.requireState();
    const request = await buildRequest(input, init, this.endpoint, responseState);
    let response = await implementation(request);
    if ((response.status === 409 || response.status === 428) && response.headers.get("X-Vallum-Proof-Required") === "1" && isSafeRetry(request.method)) {
      await this.renew();
      const renewed = this.requireState();
      responseState = renewed;
      response = await implementation(await buildRequest(input, init, this.endpoint, renewed));
    }
    return this.reconstructIfPresent(response, responseState);
  }

  private async reconstructIfPresent(response: Response, state: DecodingState): Promise<Response> {
    const contentType = response.headers.get("Content-Type")?.toLowerCase() ?? "";
    if (!contentType.includes("application/json") && !contentType.includes("+json")) return response;
    let transport: unknown;
    try {
      transport = JSON.parse(await response.clone().text());
    } catch {
      return response;
    }
    if (!isRecord(transport) || !Object.prototype.hasOwnProperty.call(transport, state.metadata_key)) return response;
    return this.reconstruct(response, state, transport);
  }

  private async reconstruct(response: Response, state: DecodingState, transport: Record<string, any>): Promise<Response> {
    const metadata = transport[state.metadata_key];
    const envelope = parseEnvelope(metadata, state.profile);
    if (envelope.version !== 1 || envelope.session !== state.session || envelope.keyID !== state.key_id) {
      throw new Error("Vallum protected response has the wrong session or key epoch");
    }
    if (envelope.expiresMS <= Date.now() || envelope.expiresMS > state.expiresAtMs + 1_000) {
      throw new Error("Vallum protected response has expired");
    }
    const replay = this.replayByEpoch.get(state.key_id) ?? { seen: new Set<number>(), pending: new Set<number>(), highest: 0 };
    this.replayByEpoch.set(state.key_id, replay);
    if (replay.seen.has(envelope.counter) || replay.pending.has(envelope.counter)) {
      throw new Error("Vallum protected response replay detected");
    }
    replay.pending.add(envelope.counter);
    let original: unknown;
    try {
      const plaintext = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: decodeBase64URL(envelope.nonce),
          additionalData: additionalData(envelope, state.profile),
          tagLength: 128,
        },
        state.key,
        decodeBase64URL(envelope.ciphertext),
      );
      original = JSON.parse(decoder.decode(plaintext));
      this.commitCounter(replay, envelope.counter);
    } catch (error) {
      if (error instanceof Error && error.message.includes("replay")) throw error;
      throw new Error("Vallum response integrity validation failed", { cause: error });
    } finally {
      replay.pending.delete(envelope.counter);
    }

    // Redemption happens after integrity validation and outside its error
    // handling. A disclosure failure is an authorization or budget outcome,
    // not a tampered response, and must not be reported as one.
    const restored = await this.restoreWithheldValues(original, state);
    const headers = new Headers(response.headers);
    for (const name of ["Content-Length", "Content-Encoding", "X-Vallum-Transform"]) headers.delete(name);
    headers.set("Content-Type", "application/json; charset=utf-8");
    return new Response(JSON.stringify(restored), {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }

  /**
   * Restores values the proxy withheld from the response.
   *
   * The protected document carries `{"$vallum_ref": handle}` in place of each
   * withheld value. Those values were never sent: they are absent from the
   * body and from the ciphertext, so this is the only way to obtain them. Each
   * redemption spends the session's server-side disclosure budget.
   *
   * Redemption is transparent to the application. It resolves before the
   * Response is constructed, so calling code receives the exact origin object
   * and never observes a handle.
   */
  private async restoreWithheldValues(document: unknown, state: DecodingState): Promise<unknown> {
    // A withheld value at the document root has no parent to assign into, so
    // it is handled before the walk.
    const rootHandle = deferredHandleOf(document);
    if (rootHandle !== undefined) {
      const rootValues = await this.redeemHandles([rootHandle], state);
      if (!Object.prototype.hasOwnProperty.call(rootValues, rootHandle)) {
        throw new Error("Vallum could not restore a withheld value; the disclosure budget may be exhausted");
      }
      return rootValues[rootHandle];
    }
    const references: DeferredReference[] = [];
    collectDeferredReferences(document, references);
    if (references.length === 0) return document;

    const handles = [...new Set(references.map((reference) => reference.handle))];
    const values = await this.redeemHandles(handles, state);
    for (const reference of references) {
      if (!Object.prototype.hasOwnProperty.call(values, reference.handle)) {
        throw new Error("Vallum could not restore a withheld value; the disclosure budget may be exhausted");
      }
      reference.assign(values[reference.handle]);
    }
    return document;
  }

  private async redeemHandles(handles: string[], state: DecodingState): Promise<Record<string, unknown>> {
    const values: Record<string, unknown> = {};
    for (let offset = 0; offset < handles.length; offset += disclosureBatchSize) {
      const batch = handles.slice(offset, offset + disclosureBatchSize);
      const request = await buildRequest(
        new URL(disclosurePath, this.endpoint),
        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ handles: batch }) },
        this.endpoint,
        state,
      );
      const response = await this.baseFetch(request);
      if (response.status === 429) {
        throw new Error("Vallum disclosure budget is exhausted for this session");
      }
      if (!response.ok) {
        throw new Error(`Vallum disclosure request failed with status ${response.status}`);
      }
      const payload = await response.json();
      if (!isRecord(payload) || !Array.isArray(payload.results)) {
        throw new Error("Vallum disclosure response is malformed");
      }
      for (const result of payload.results) {
        if (!isRecord(result) || typeof result.handle !== "string") continue;
        if (typeof result.error === "string" && result.error) continue;
        // A render-only field arrives as pixels. It is never turned into a
        // string here, so the plaintext does not enter the JS heap.
        values[result.handle] = isRenderPayload(result.render)
          ? new VallumRenderRef(result.render)
          : result.value;
      }
    }
    return values;
  }

  isRenderOnly(value: unknown): boolean {
    return value instanceof VallumRenderRef;
  }

  async mount(element: Element, value: unknown, options: MountOptions = {}): Promise<boolean> {
    if (!(value instanceof VallumRenderRef)) return false;
    const payload = value.take();
    if (!payload) return false;

    const bytes = Uint8Array.from(atob(payload.png.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const blob = new Blob([bytes], { type: "image/png" });
    let bitmap: ImageBitmap;
    try {
      bitmap = await createImageBitmap(blob);
    } catch (error) {
      throw new Error("Vallum could not paint a render-only value", { cause: error });
    }

    const ratio = globalThis.devicePixelRatio ?? 1;
    const cssHeight = options.height ?? payload.height / 2;
    const cssWidth = (payload.width / payload.height) * cssHeight;
    const canvas = element.ownerDocument.createElement("canvas");
    canvas.width = Math.round(cssWidth * ratio);
    canvas.height = Math.round(cssHeight * ratio);
    canvas.style.width = `${cssWidth}px`;
    canvas.style.height = `${cssHeight}px`;
    canvas.style.verticalAlign = "middle";
    canvas.setAttribute("role", "img");
    // Without an explicit opt-in the value stays out of the accessibility
    // tree. That is the protection and also its accessibility cost.
    canvas.setAttribute("aria-label", options.accessibleLabel ?? "protected value");
    const context = canvas.getContext("2d");
    if (!context) throw new Error("Vallum could not obtain a 2D canvas context");
    context.imageSmoothingEnabled = true;
    context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    bitmap.close();

    element.replaceChildren(canvas);
    return true;
  }

  private commitCounter(replay: { seen: Set<number>; pending: Set<number>; highest: number }, counter: number): void {
    replay.seen.add(counter);
    replay.highest = Math.max(replay.highest, counter);
    const floor = replay.highest - 1_024;
    for (const seen of replay.seen) if (seen < floor) replay.seen.delete(seen);
  }

  private requireState(): DecodingState {
    if (!this.state) throw new Error("Vallum session is not initialized");
    return this.state;
  }
}

function validateChallenge(challenge: ChallengeResponse): void {
  if (!challenge || challenge.version !== 1 || typeof challenge.session !== "string" || challenge.session.length < 8 ||
      typeof challenge.expires_at !== "string" || Number.isNaN(Date.parse(challenge.expires_at)) ||
    typeof challenge.admission_required !== "boolean" || typeof challenge.server_nonce !== "string" || challenge.server_nonce.length < 16) {
    throw new Error("Vallum session challenge is invalid");
  }
}

async function buildRequest(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  endpoint: string,
  state: DecodingState,
): Promise<Request> {
  const source = input instanceof Request ? input : undefined;
  const rawURL = source?.url ?? (input instanceof URL ? input.toString() : String(input));
  const absoluteURL = new URL(rawURL, endpoint);
  const base = source ? new Request(absoluteURL, source) : new Request(absoluteURL, init);
  const request = source && init ? new Request(base, init) : base;
  const headers = new Headers(request.headers);
  headers.set(state.session_header, state.session);
  headers.set("Accept", headers.get("Accept") ?? "application/json");
  const unsigned = new Request(request, { headers, credentials: init?.credentials ?? source?.credentials ?? "include", cache: "no-store" });
  const bodyHash = await requestBodyHash(unsigned);
  const tokenID = randomTokenID();
  const claims = {
    v: 1,
    s: state.session,
    k: state.key_id,
    m: unsigned.method.toUpperCase(),
    u: canonicalRequestURI(new URL(unsigned.url)),
    h: bodyHash,
    t: Date.now(),
    j: tokenID,
    n: state.server_nonce,
  };
  const payload = encodeBase64URL(encoder.encode(JSON.stringify(claims)));
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    state.proofKey,
    encoder.encode(requestProofDomain + payload),
  );
  const signatureBytes = new Uint8Array(signature);
  if (signatureBytes.byteLength !== 64) throw new Error("Vallum request proof signature is invalid");
  headers.set(state.proof_header, `${payload}.${encodeBase64URL(signatureBytes)}`);
  return new Request(unsigned, { headers, credentials: init?.credentials ?? source?.credentials ?? "include", cache: "no-store" });
}

async function requestBodyHash(request: Request): Promise<string> {
  if (request.body === null) return unsignedPayloadMarker;
  let body: ArrayBuffer;
  try {
    body = await request.clone().arrayBuffer();
  } catch (error) {
    throw new Error("Vallum cannot prove a non-cloneable request body", { cause: error });
  }
  if (body.byteLength === 0) return unsignedPayloadMarker;
  const digest = await crypto.subtle.digest("SHA-256", body);
  return encodeBase64URL(new Uint8Array(digest));
}

function canonicalRequestURI(url: URL): string {
  const path = canonicalPercentEscapes(url.pathname || "/");
  return path + (url.search ? `?${canonicalPercentEscapes(url.search.slice(1))}` : "");
}

function canonicalPercentEscapes(value: string): string {
  return value.replace(/%[0-9a-fA-F]{2}/g, (escape) => escape.toUpperCase());
}

function randomTokenID(): string {
  const value = new Uint8Array(18);
  crypto.getRandomValues(value);
  return encodeBase64URL(value);
}

function parseEnvelope(metadata: unknown, profile: number): Envelope {
  if (profile === 0) {
    if (!isRecord(metadata) || !Array.isArray(metadata.c)) throw new Error("Invalid Vallum profile 0 envelope");
    return envelopeValues(metadata.v, metadata.s, metadata.k, metadata.q, metadata.x, metadata.n, metadata.r, metadata.c.join(""));
  }
  if (profile === 1) {
    if (!Array.isArray(metadata) || metadata.length !== 8 || !Array.isArray(metadata[7])) throw new Error("Invalid Vallum profile 1 envelope");
    const chunks = [...metadata[7]].reverse().map((part) => {
      if (!Array.isArray(part) || typeof part[1] !== "string") throw new Error("Invalid Vallum profile 1 part");
      return part[1];
    });
    return envelopeValues(metadata[0], metadata[1], metadata[2], metadata[3], metadata[4], metadata[5], metadata[6], chunks.join(""));
  }
  if (!isRecord(metadata) || !isRecord(metadata.proof) || !isRecord(metadata.parts) || !Array.isArray(metadata.order)) {
    throw new Error("Invalid Vallum profile 2 envelope");
  }
  const chunks = metadata.order.map((name) => {
    if (typeof name !== "string" || typeof metadata.parts[name] !== "string") throw new Error("Invalid Vallum profile 2 part");
    return metadata.parts[name];
  });
  return envelopeValues(
    metadata.revision, metadata.subject, metadata.epoch, metadata.proof.counter,
    metadata.proof.until, metadata.proof.iv, metadata.route, chunks.join(""),
  );
}

function envelopeValues(
  version: unknown, session: unknown, keyID: unknown, counter: unknown, expiresMS: unknown,
  nonce: unknown, routeTag: unknown, ciphertext: unknown,
): Envelope {
  if (!Number.isSafeInteger(version) || !Number.isSafeInteger(counter) || (counter as number) < 1 ||
      !Number.isSafeInteger(expiresMS) || typeof session !== "string" || typeof keyID !== "string" ||
      typeof nonce !== "string" || typeof routeTag !== "string" || typeof ciphertext !== "string") {
    throw new Error("Invalid Vallum envelope values");
  }
  return { version: version as number, session, keyID, counter: counter as number, expiresMS: expiresMS as number, nonce, routeTag, ciphertext };
}

function additionalData(envelope: Envelope, profile: number): Uint8Array<ArrayBuffer> {
  const encoded = encoder.encode(`${envelope.version}\n${envelope.session}\n${envelope.keyID}\n${envelope.counter}\n${envelope.expiresMS}\n${profile}\n${envelope.routeTag}`);
  const output = new Uint8Array(new ArrayBuffer(encoded.byteLength));
  output.set(encoded);
  return output;
}

function validateBootstrap(value: BootstrapResponse): void {
  if (value.version !== 1 || value.algorithm !== "RSA-OAEP-256+A256GCM" ||
    !value.session || !value.key_id || !value.metadata_key || !value.wrapped_key || !value.server_nonce ||
    value.proof_header !== "X-Vallum-Proof" || value.session_header !== "X-Vallum-Session" ||
      ![0, 1, 2].includes(value.profile) || !Number.isFinite(Date.parse(value.expires_at))) {
    throw new Error("Vallum session bootstrap returned invalid material");
  }
}

function encodeBase64URL(value: Uint8Array<ArrayBufferLike>): string {
  let binary = "";
  for (const item of value) binary += String.fromCharCode(item);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeBase64URL(value: string): Uint8Array<ArrayBuffer> {
  const padding = (4 - (value.length % 4)) % 4;
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padding);
  const binary = atob(padded);
  const output = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index++) output[index] = binary.charCodeAt(index);
  return output;
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafeRetry(method: string): boolean {
  return method === "GET";
}
