/**
 * Client WebAuthn natif (zero-dep) pour le navigateur.
 * Convertit les options JSON du backend vers les types ArrayBuffer attendus par
 * navigator.credentials.create() et navigator.credentials.get(), et inversement.
 */

import i18n from "../i18n/config"

function base64UrlToBuffer(base64url: string): ArrayBuffer {
  const padding = "=".repeat((4 - (base64url.length % 4)) % 4)
  const base64 = (base64url + padding).replace(/-/g, "+").replace(/_/g, "/")
  const rawData = window.atob(base64)
  const outputArray = new Uint8Array(rawData.length)
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i)
  }
  return outputArray.buffer
}

function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ""
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]!)
  }
  const base64 = window.btoa(binary)
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export class WebauthnError extends Error {
  code: "not_supported" | "cancelled"
  constructor(code: "not_supported" | "cancelled") {
    const message =
      code === "not_supported"
        ? i18n.t("auth.webauthn.notSupported")
        : i18n.t("auth.webauthn.cancelled")
    super(message)
    this.name = "WebauthnError"
    this.code = code
  }
}

export async function createWebauthnCredential(options: any): Promise<any> {
  if (!navigator.credentials || !navigator.credentials.create) {
    throw new WebauthnError("not_supported")
  }

  const publicKey: CredentialCreationOptions["publicKey"] = {
    ...options,
    challenge: base64UrlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: typeof options.user.id === "string" ? base64UrlToBuffer(options.user.id) : options.user.id,
    },
    excludeCredentials: options.excludeCredentials?.map((cred: any) => ({
      ...cred,
      id: base64UrlToBuffer(cred.id),
    })),
  }

  let credential: any
  try {
    credential = (await navigator.credentials.create({ publicKey })) as any
  } catch (err: any) {
    if (err instanceof WebauthnError) throw err
    if (err?.name === "NotAllowedError" || err?.name === "AbortError") {
      throw new WebauthnError("cancelled")
    }
    throw err
  }
  if (!credential) throw new WebauthnError("cancelled")

  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
      attestationObject: bufferToBase64Url(credential.response.attestationObject),
      transports: credential.response.getTransports ? credential.response.getTransports() : undefined,
    },
  }
}

export async function getWebauthnAssertion(options: any): Promise<any> {
  if (!navigator.credentials || !navigator.credentials.get) {
    throw new WebauthnError("not_supported")
  }

  const publicKey: CredentialRequestOptions["publicKey"] = {
    ...options,
    challenge: base64UrlToBuffer(options.challenge),
    allowCredentials: options.allowCredentials?.map((cred: any) => ({
      ...cred,
      id: base64UrlToBuffer(cred.id),
    })),
  }

  let assertion: any
  try {
    assertion = (await navigator.credentials.get({ publicKey })) as any
  } catch (err: any) {
    if (err instanceof WebauthnError) throw err
    if (err?.name === "NotAllowedError" || err?.name === "AbortError") {
      throw new WebauthnError("cancelled")
    }
    throw err
  }
  if (!assertion) throw new WebauthnError("cancelled")

  return {
    id: assertion.id,
    rawId: bufferToBase64Url(assertion.rawId),
    type: assertion.type,
    response: {
      clientDataJSON: bufferToBase64Url(assertion.response.clientDataJSON),
      authenticatorData: bufferToBase64Url(assertion.response.authenticatorData),
      signature: bufferToBase64Url(assertion.response.signature),
      userHandle: assertion.response.userHandle ? bufferToBase64Url(assertion.response.userHandle) : undefined,
    },
  }
}
