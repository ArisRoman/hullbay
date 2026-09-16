import { useEffect, useState } from "react"
import { useNavigate, useSearchParams } from "react-router-dom"
import { api, auth, type ApiError, type AuthProviderPublic } from "../lib/api"
import {
  Button,
  Heading,
  Text,
  Input,
  Label,
  toast,
} from "@medusajs/ui"
import { useTranslation } from "react-i18next"

export function LoginPage({ onAuthed }: { onAuthed: () => void }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [pendingToken, setPendingToken] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [code, setCode] = useState("")

  // SSO : providers activés (rendu après mount pour ne pas bloquer le login local)
  const [ssoProviders, setSsoProviders] = useState<AuthProviderPublic[] | null>(null)
  // Bannière "identité en attente d'approbation" (callback → /login?pending=1)
  const wasPending = searchParams.get("pending") === "1"
  const pendingEmail = searchParams.get("email") ?? ""
  const ssoError = searchParams.get("error") ?? ""

  // Prefetch passe par le hook useEffect : le module reste SSR-compatible.
  useEffect(() => {
    let cancelled = false
    api
      .listAuthProviders()
      .then((providers) => {
        if (!cancelled) {
          setSsoProviders(providers.filter((p) => p.kind === "oidc" || p.kind === "oauth2" || p.kind === "saml"))
        }
      })
      .catch(() => {
        if (!cancelled) setSsoProviders([])
      })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    if (ssoError) {
      toast.error(t("auth.sso.failed"), { description: ssoError })
    }
  }, [ssoError, t])

  // Verrouillage temporaire après abus de tentatives (429 du back).
  const [lockedUntil, setLockedUntil] = useState<number | null>(null)
  const [nowTick, setNowTick] = useState(() => Date.now())

  const remainingSec =
    lockedUntil !== null ? Math.max(0, Math.ceil((lockedUntil - nowTick) / 1000)) : 0

  useEffect(() => {
    if (lockedUntil === null) return
    const id = setInterval(() => setNowTick(Date.now()), 1000)
    return () => clearInterval(id)
  }, [lockedUntil])

  useEffect(() => {
    if (lockedUntil !== null && Date.now() >= lockedUntil) {
      setLockedUntil(null)
      toast.info(t("auth.rateLimited.unlocked"))
    }
  }, [nowTick, lockedUntil, t])

  function lock(err: ApiError) {
    setLockedUntil(Date.now() + (err.retryAfterSec ?? 30) * 1000)
  }

  async function submitCredentials() {
    setLoading(true)

    try {
      const res = await api.login(email, password)

      if (res.mfaRequired && res.pendingToken) {
        setPendingToken(res.pendingToken)
        return
      }

      if (res.token) {
        auth.set(res.token)
        onAuthed()
        navigate("/", { replace: true })
      }
    } catch (e) {
      const err = e as ApiError

      if (err.status === 429) {
        lock(err)
        return
      }

      if (err.code === "invalid_credentials") {
        toast.error(t("auth.toast.loginFailed"), {
          description: t("auth.toast.invalidCredentialsDescription"),
        })
      } else {
        toast.error(t("auth.toast.loginFailed"), {
          description: err.message,
        })
      }
    } finally {
      setLoading(false)
    }
  }

  async function submitMfa() {
    if (!pendingToken) return

    setLoading(true)

    try {
      const res = await api.verifyMfa(pendingToken, code)

      auth.set(res.token)
      onAuthed()
      navigate("/", { replace: true })
    } catch (e) {
      const err = e as ApiError

      if (err.status === 429) {
        lock(err)
        return
      }

      if (
        err.code === "mfa_code_invalid" ||
        err.code === "mfa_token_invalid"
      ) {
        toast.error(t("auth.toast.invalidCode"), {
          description: t("auth.toast.invalidMfaDescription"),
        })
      } else {
        toast.error(t("auth.toast.invalidCode"), {
          description: err.message,
        })
      }
    } finally {
      setLoading(false)
    }
  }

  const lockVisible = remainingSec > 0;
  const disabled = loading || lockVisible;

  return (
  <div className="flex min-h-full w-full items-center justify-center bg-ui-bg-subtle px-4 py-8">
    <div className="w-full max-w-[390px]">



      {/* Header */}
      <div className="mb-6 text-center">
        <Heading
          level="h1"
          className="mb-2 text-xl font-semibold text-ui-fg-base"
        >
          {t("auth.title")}
        </Heading>

        <Text className="text-sm leading-5 text-ui-fg-subtle">
          {t("auth.subtitle")}
        </Text>
      </div>

      {lockVisible && (
        <div
          role="alert"
          aria-live="polite"
          className="mb-5 rounded-xl border border-ui-border-error bg-ui-bg-error px-4 py-3"
        >
          <Text className="text-sm font-medium leading-5 text-ui-fg-error">
            {t("auth.rateLimited.title")}
          </Text>
          <Text className="mt-0.5 text-sm leading-5 text-ui-fg-error">
            {t("auth.rateLimited.retryIn", { seconds: remainingSec })}
          </Text>
        </div>
      )}

      {/* Pending SSO : identité externe en attente d'approbation (workflow 5A) */}
      {wasPending && (
        <div
          role="status"
          aria-live="polite"
          className="mb-5 rounded-xl border border-ui-border-base bg-ui-bg-base px-4 py-3"
        >
          <Text className="text-sm font-medium leading-5 text-ui-fg-base">
            {t("auth.sso.pending.title")}
          </Text>
          <Text className="mt-0.5 text-sm leading-5 text-ui-fg-subtle">
            {t("auth.sso.pending.description", { email: pendingEmail || "—" })}
          </Text>
        </div>
      )}

      {!pendingToken ? (
        <div className="flex flex-col gap-4">

          {/* SSO : boutons vers les providers OIDC/OAuth2/SAML activés */}
          {ssoProviders && ssoProviders.length > 0 && (
            <>
              <div className="flex flex-col gap-2">
                {ssoProviders.map((p) => (
                  <Button
                    key={p.id}
                    variant="secondary"
                    onClick={() => {
                      const base = p.kind === "saml" ? "/api/auth/saml" : "/api/auth/sso"
                      window.location.href = `${base}/${encodeURIComponent(p.id)}/login`
                    }}
                    disabled={disabled}
                    className="h-10 w-full rounded-lg disabled:opacity-50"
                  >
                    {t("auth.sso.signInWith", { name: p.name })}
                  </Button>
                ))}
              </div>

              <div className="flex items-center gap-3">
                <div className="h-px flex-1 bg-ui-border-base" />
                <Text className="text-xs uppercase tracking-wide text-ui-fg-muted">
                  {t("auth.sso.orContinueWithLocal")}
                </Text>
                <div className="h-px flex-1 bg-ui-border-base" />
              </div>
            </>
          )}

          {/* Email */}
          <div>
            <Label
              size="small"
              className="mb-1.5 block text-ui-fg-subtle"
            >
              {t("auth.login.emailLabel")}
            </Label>

            <Input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder={t("auth.login.placeholder")}
              disabled={disabled}
              className="h-10 rounded-lg disabled:opacity-50"
            />
          </div>

          {/* Password */}
          <div>
            <Label
              size="small"
              className="mb-1.5 block text-ui-fg-subtle"
            >
              {t("auth.login.passwordLabel")}
            </Label>

            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={disabled}
              className="h-10 rounded-lg disabled:opacity-50"
            />
          </div>

          {/* Button */}
          <Button
            onClick={submitCredentials}
            isLoading={loading}
            disabled={disabled}
            className="mt-1 h-10 w-full rounded-lg disabled:opacity-50"
          >
            {t("auth.login.submitButton")}
          </Button>

          </div>
      ) : (
        <div className="flex flex-col gap-4">

          {/* MFA */}
          <div>
            <Label
              size="small"
              className="mb-1.5 block text-ui-fg-subtle"
            >
              {t("auth.mfa.codeLabel")}
            </Label>

            <Input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder={t("auth.mfa.codePlaceholder")}
              inputMode="numeric"
              disabled={disabled}
              className="h-10 rounded-lg text-center tracking-[0.25em] disabled:opacity-50"
            />
          </div>

          <Button
            onClick={submitMfa}
            isLoading={loading}
            disabled={disabled}
            className="h-10 w-full rounded-lg disabled:opacity-50"
          >
            {t("auth.mfa.submitButton")}
          </Button>
        </div>
      )}
    </div>
  </div>
)
}
