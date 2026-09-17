import { useEffect, useState } from "react"
import { useNavigate } from "react-router-dom"
import { useTranslation } from 'react-i18next'
import { useQueryClient } from "@tanstack/react-query"
import { api, auth } from "../lib/api"
import { useMe } from "../lib/useMe"
import { PasskeysCard } from "../components/PasskeysCard"
import { Button, Container, Heading, Input, Label, Text, toast } from "@medusajs/ui"
import { QRCodeSVG } from "qrcode.react"

// Un seul appel d'enrôlement, même en StrictMode (double mount dev) : on
// mémorise la promesse pour que le mount « survivant » récupère la réponse du
// 1er mount (démonté) — un simple booléen perdrait le résultat et laisserait
// l'écran bloqué sur « Préparation en cours… ».
let enrollPromise: Promise<{ otpauth: string; secret: string }> | null = null

export function ActivateMfaPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [secret, setSecret] = useState<string | null>(null)
  const [otpauth, setOtpauth] = useState<string | null>(null)
  const [code, setCode] = useState("")
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const { me } = useMe()

  // Une navigation directe n'a de sens que si la MFA locale est requise.
  useEffect(() => { if (me && !me.mfaRequired) navigate("/", { replace: true }) }, [me])

  useEffect(() => {
    let mounted = true
    async function start() {
      try {
        const data = await (enrollPromise ??= api.enrollMfa().catch((e) => {
          enrollPromise = null
          throw e
        }))
        if (!mounted) return
        setSecret(data.secret)
        setOtpauth(data.otpauth)
      } catch (e) {
        const err = e as Error & { code?: string }
        toast.error(t("auth.toast.mfaEnrollFailed"), {
          description: err.code === "mfa_not_enabled" ? t("auth.toast.mfaNotEnabledDescription") : err.message,
        })
      }
    }
    start()
    return () => {
      mounted = false
    }
  }, [])

  async function confirm() {
    setLoading(true)
    try {
      const res = await api.confirmMfa(code)
      if (res.token) {
        auth.set(res.token)
      }
      await queryClient.invalidateQueries({ queryKey: ["me"] })
      toast.success(t("auth.toast.mfaEnabled"))
      window.location.assign("/")
    } catch (e) {
      const err = e as Error & { code?: string }
      if (err.code === "mfa_code_invalid" || err.code === "mfa_enrollment_missing") {
        toast.error(t("auth.toast.invalidCode"), { description: t("auth.toast.invalidMfaDescription") })
      } else {
        toast.error(t("auth.toast.invalidCode"), { description: err.message })
      }
    } finally {
      setLoading(false)
    }
  }

  async function copySecret() {
    if (!secret) return
    await navigator.clipboard.writeText(secret)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
  <div className="flex min-h-full w-full items-center justify-center bg-ui-bg-subtle px-4 py-8">
    <div className="w-full max-w-[390px]">

      {/* Header */}
      <div className="mb-6 text-center">
        <Heading
          level="h1"
          className="mb-2 text-xl font-semibold text-ui-fg-base"
        >
          {t("auth.mfaModal.title")}
        </Heading>

        <Text className="text-sm leading-5 text-ui-fg-subtle">
          {t("auth.mfaModal.description")}
        </Text>
      </div>

      {/* QR Code */}
      <div className="mb-4 rounded-xl bg-ui-bg-base p-5 shadow-sm">
        <div className="mb-3 text-center">
          <Text className="text-sm font-medium text-ui-fg-base">
            {t("auth.mfaModal.scanQrTitle")}
          </Text>
        </div>

        <div className="flex justify-center">
          {otpauth ? (
            <div className="flex items-center justify-center rounded-xl bg-white p-4">
              <QRCodeSVG value={otpauth} size={180} marginSize={2} />
            </div>
          ) : (
            <div className="flex h-[212px] items-center justify-center">
              <Text className="text-sm text-ui-fg-muted">
                {t("auth.mfaModal.preparing")}
              </Text>
            </div>
          )}
        </div>

        <Text className="mt-3 text-center text-xs text-ui-fg-subtle">
          {t("auth.mfaModal.scanAppsHint")}
        </Text>
      </div>

      {/* Secret */}
      <div className="mb-4 rounded-xl bg-ui-bg-base p-4 shadow-sm">
        <Label
          size="small"
          className="mb-1.5 block text-ui-fg-subtle"
        >
          {t("auth.mfaModal.manualEntryLabel")}
        </Label>

        <Text className="mb-3 text-xs text-ui-fg-subtle">
          {t("auth.mfaModal.manualEntryHint")}
        </Text>

        <div className="flex items-center gap-2">
          <div className="min-w-0 flex-1 rounded-lg bg-ui-bg-base-pressed p-3 text-xs font-mono break-all text-ui-fg-base">
            {secret ?? "—"}
          </div>

          <Button
            variant="secondary"
            size="small"
            onClick={copySecret}
          >
            {copied ? t("auth.mfaModal.copied") : t("auth.mfaModal.copy")}
          </Button>
        </div>
      </div>

      {/* Verification code */}
      <div className="mb-5 rounded-xl bg-ui-bg-base p-4 shadow-sm">
        <Label
          size="small"
          className="mb-1.5 block text-ui-fg-subtle"
        >
          {t("auth.mfaModal.verificationCodeLabel")}
        </Label>

        <Text className="mb-3 text-xs text-ui-fg-subtle">
          {t("auth.mfaModal.codeHint")}
        </Text>

        <Input
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder={t("auth.mfa.codePlaceholder")}
          inputMode="numeric"
          maxLength={6}
          className="h-10 rounded-lg text-center text-base tracking-[0.3em]"
        />
      </div>

      {/* Confirm */}
      <Button
        onClick={confirm}
        isLoading={loading}
        disabled={code.length !== 6}
        className="h-10 w-full rounded-lg"
      >
        {t("auth.mfaModal.confirmButton")}
      </Button>

      {/* Clé de sécurité (optionnel) : permet d'utiliser une passkey au login
          dès le premier enrôlement, sans devoir passer par les Paramètres.
          L'API autorise register/options+verify pendant l'enrôlement forcé. */}
      <div className="mt-6">
        <Text className="mb-3 text-xs leading-5 text-ui-fg-subtle">
          {t("auth.mfaModal.passkeyOptional")}
        </Text>
        <PasskeysCard />
      </div>
    </div>
  </div>
)
}
