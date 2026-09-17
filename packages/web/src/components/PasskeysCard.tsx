import { useState } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { Button, Container, Heading, Input, Label, Text, toast } from "@medusajs/ui"
import { Key, Trash } from "@medusajs/icons"
import { api, type ApiError, type WebauthnCredentialPublic } from "../lib/api"
import { createWebauthnCredential, WebauthnError } from "../lib/webauthn-client"
import { useConfirmDelete } from "../lib/useConfirmDelete"

/**
 * Gestion des clés de sécurité / passkeys rattachées au compte.
 * Enrôlement : options serveur → cérémonie navigateur → vérification serveur.
 * La liste ne contient que les champs publics (jamais publicKey/counter).
 */
export function PasskeysCard() {
  const { t, i18n } = useTranslation()
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ["webauthn-credentials"],
    queryFn: api.listWebauthnCredentials,
  })

  const [name, setName] = useState("")
  const [registering, setRegistering] = useState(false)

  const supported =
    typeof window !== "undefined" && "PublicKeyCredential" in window

  const remove = useConfirmDelete<{ id: string; name: string }>({
    mutationFn: ({ id }) => api.deleteWebauthnCredential(id),
    success: t("settings.passkeys.removed"),
    invalidate: [["webauthn-credentials"], ["me"]],
    confirm: ({ name: credName }) => ({
      title: t("settings.passkeys.confirm.title"),
      description: t("settings.passkeys.confirm.description", {
        name: credName,
      }),
      confirmText: t("settings.passkeys.confirm.confirmText"),
    }),
  })

  async function addPasskey() {
    setRegistering(true)
    try {
      const options = await api.getWebauthnRegisterOptions()
      const attestation = await createWebauthnCredential(options)
      await api.verifyWebauthnRegister(attestation, name.trim() || undefined)
      setName("")
      await queryClient.invalidateQueries({ queryKey: ["webauthn-credentials"] })
      await queryClient.invalidateQueries({ queryKey: ["me"] })
      toast.success(t("settings.passkeys.added"))
    } catch (e) {
      const err = e as ApiError & { code?: string }
      if (err instanceof WebauthnError && err.code === "cancelled") {
        return
      }
      const description =
        err.code === "not_supported"
          ? t("settings.passkeys.unsupported")
          : err.message
      toast.error(t("settings.passkeys.errors.registerFailed"), { description })
    } finally {
      setRegistering(false)
    }
  }

  const credentials: WebauthnCredentialPublic[] = data ?? []
  const formatDate = (value: string) =>
    new Date(value).toLocaleDateString(i18n.language)

  return (
    <Container className="mb-4 p-6">
      <Heading level="h3" className="mb-3">
        {t("settings.passkeys.title")}
      </Heading>

      <Text size="small" className="mb-4 text-ui-fg-subtle">
        {t("settings.passkeys.hint")}
      </Text>

      {!supported ? (
        <Text size="small" className="text-ui-fg-muted">
          {t("settings.passkeys.unsupported")}
        </Text>
      ) : (
        <>
          {isLoading ? (
            <Text size="small" className="text-ui-fg-muted">
              …
            </Text>
          ) : credentials.length === 0 ? (
            <Text size="small" className="text-ui-fg-muted">
              {t("settings.passkeys.empty")}
            </Text>
          ) : (
            <ul className="mb-5 divide-y divide-ui-border-base rounded-lg border border-ui-border-base">
              {credentials.map((cred) => (
                <li
                  key={cred.id}
                  data-testid={`passkey-row-${cred.id}`}
                  className="flex items-center justify-between gap-3 p-3"
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-ui-bg-base-pressed text-ui-fg-muted">
                      <Key />
                    </div>
                    <div className="min-w-0">
                      <Text size="small" weight="plus" className="truncate">
                        {cred.name || t("settings.passkeys.defaultName")}
                      </Text>
                      <Text size="xsmall" className="text-ui-fg-muted">
                        {t("settings.passkeys.addedAt")}{" "}
                        {formatDate(cred.createdAt)}
                        {" · "}
                        {cred.lastUsedAt
                          ? `${t("settings.passkeys.lastUsed")} ${formatDate(cred.lastUsedAt)}`
                          : t("settings.passkeys.neverUsed")}
                      </Text>
                    </div>
                  </div>
                  <Button
                    variant="secondary"
                    size="small"
                    data-testid={`passkey-delete-${cred.id}`}
                    aria-label={t("settings.passkeys.remove")}
                    className="shrink-0"
                    onClick={() =>
                      remove({
                        id: cred.id,
                        name: cred.name || t("settings.passkeys.defaultName"),
                      })
                    }
                  >
                    <Trash />
                  </Button>
                </li>
              ))}
            </ul>
          )}

          <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <div className="flex-1">
              <Label size="small">{t("settings.passkeys.nameLabel")}</Label>
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t("settings.passkeys.namePlaceholder")}
                data-testid="passkey-name"
              />
            </div>
            <Button
              onClick={addPasskey}
              isLoading={registering}
              data-testid="passkey-add"
              className="sm:w-auto"
            >
              {t("settings.passkeys.addButton")}
            </Button>
          </div>
        </>
      )}
    </Container>
  )
}
