import { useState } from "react"
import { useMutation, useQuery } from "@tanstack/react-query"
import {
  Badge,
  Button,
  FocusModal,
  Heading,
  Input,
  Label,
  Select,
  Tabs,
  Text,
  Textarea,
  toast,
} from "@medusajs/ui"
import {
  Beaker,
  CheckCircle,
  PencilSquare,
  Plus,
  ShieldCheck,
  Trash,
  XCircle,
} from "@medusajs/icons"
import { useTranslation } from "react-i18next"
import { Navigate } from "react-router-dom"
import {
  api,
  type ApiError,
  type AuthProviderAdmin,
  type AuthProviderUpsert,
  type PendingIdentity,
} from "../lib/api"
import { useMe } from "../lib/useMe"
import { useMutationToast } from "../lib/useMutationToast"
import { useConfirmDelete } from "../lib/useConfirmDelete"
import { PageContainer, PageHeader } from "../components/PageHeader"
import { ModalForm } from "../components/ModalForm"
import { ToggleSwitch } from "../components/ToggleSwitch"

type Kind = "oidc" | "oauth2" | "saml" | "ldap"

const KINDS: Kind[] = ["oidc", "oauth2", "saml", "ldap"]

type BadgeColor = "green" | "red" | "blue" | "orange" | "purple" | "grey"

const KIND_BADGE: Record<string, { color: BadgeColor; icon: string }> = {
  oidc: { color: "blue", icon: "OIDC" },
  oauth2: { color: "purple", icon: "OAuth2" },
  saml: { color: "orange", icon: "SAML" },
  local: { color: "grey", icon: "Local" },
  ldap: { color: "green", icon: "LDAP" },
}

/** Protocoles dont la config est éditable/testable via l'API (cf. backend kindToSchema). */
const isManagedKind = (kind: string): kind is Kind => (KINDS as string[]).includes(kind)

/** Champs de config d'un kind ; vide si le protocole n'est pas géré par l'API. */
const fieldsFor = (kind: string): FieldDef[] => (isManagedKind(kind) ? CONFIG_FIELDS[kind] : [])

type FieldDef = {
  key: string
  labelKey: string
  required?: boolean
  type?: "text" | "url" | "password" | "number" | "textarea"
}

const CONFIG_FIELDS: Record<Kind, FieldDef[]> = {
  oidc: [
    { key: "issuer", labelKey: "field.issuer", required: true, type: "url" },
    { key: "clientId", labelKey: "field.clientId", required: true },
    { key: "clientSecret", labelKey: "field.clientSecret", type: "password" },
    { key: "redirectUri", labelKey: "field.redirectUri", required: true, type: "url" },
    { key: "scopes", labelKey: "field.scopes" },
    { key: "discoveryUrl", labelKey: "field.discoveryUrl", type: "url" },
    { key: "jwksUri", labelKey: "field.jwksUri", type: "url" },
  ],
  oauth2: [
    { key: "authorizationUri", labelKey: "field.authorizationUri", required: true, type: "url" },
    { key: "tokenUri", labelKey: "field.tokenUri", required: true, type: "url" },
    { key: "userinfoUri", labelKey: "field.userinfoUri", required: true, type: "url" },
    { key: "clientId", labelKey: "field.clientId", required: true },
    { key: "clientSecret", labelKey: "field.clientSecret", type: "password" },
    { key: "redirectUri", labelKey: "field.redirectUri", required: true, type: "url" },
    { key: "scopes", labelKey: "field.scopes" },
    { key: "groupAttr", labelKey: "field.groupAttr" },
  ],
  saml: [
    { key: "idpCert", labelKey: "field.idpCert", required: true, type: "textarea" },
    { key: "idpIssuer", labelKey: "field.idpIssuer", required: true },
    { key: "spIssuer", labelKey: "field.spIssuer", required: true },
    { key: "entryPoint", labelKey: "field.entryPoint", required: true, type: "url" },
    { key: "callbackUrl", labelKey: "field.callbackUrl", required: true, type: "url" },
    { key: "audience", labelKey: "field.audience" },
    { key: "acceptedClockSkewMs", labelKey: "field.acceptedClockSkewMs", type: "number" },
  ],
  ldap: [
    { key: "url", labelKey: "field.ldapUrl", required: true },
    { key: "bindDn", labelKey: "field.bindDn" },
    { key: "bindSecret", labelKey: "field.bindSecret", type: "password" },
    { key: "searchBase", labelKey: "field.searchBase", required: true },
    { key: "searchFilter", labelKey: "field.searchFilter", required: true },
    { key: "stableAttr", labelKey: "field.stableAttr", required: true },
    { key: "groupSearchBase", labelKey: "field.groupSearchBase" },
    { key: "groupFilter", labelKey: "field.groupFilter" },
    { key: "timeoutMs", labelKey: "field.timeoutMs", type: "number" },
  ],
}

type Draft = {
  kind: string
  name: string
  id: string
  enabled: boolean
  config: Record<string, string | number>
}

function emptyDraft(): Draft {
  return { kind: "oidc", name: "", id: "", enabled: false, config: {} }
}

function draftFrom(provider: AuthProviderAdmin): Draft {
  return {
    kind: provider.kind,
    name: provider.name,
    id: provider.id,
    enabled: provider.enabled,
    config: provider.config as Record<string, string | number>,
  }
}

/**
 * Page d'administration de l'authentification (owner uniquement) — Phase 5A1.
 * Onglet Providers : CRUD des providers SSO (OIDC/OAuth2/SAML) + test de
 * connexion ; onglet Pendings : approbation des identités externes par tenant.
 *
 * Design : tab pills custom (Updates page pattern) + cards en bordure arrondie.
 */
export function AdminProvidersPage() {
  const { t } = useTranslation()
  const { me, can } = useMe()

  const [activeTab, setActiveTab] = useState<"providers" | "pendings">("providers")

  const providers = useQuery({
    queryKey: ["admin", "providers"],
    queryFn: api.listAdminProviders,
    enabled: can("owner"),
  })
  const pendings = useQuery({
    queryKey: ["admin", "pendings"],
    queryFn: api.listAdminPendings,
    enabled: can("owner"),
  })
  const tenants = useQuery({
    queryKey: ["admin", "tenants"],
    queryFn: api.listTenants,
    enabled: can("owner"),
  })

  // ── Providers : modal create/edit ──────────────────────────────────────
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<AuthProviderAdmin | null>(null)
  const [draft, setDraft] = useState<Draft>(emptyDraft)

  const setField = (key: string, value: string | number) =>
    setDraft((d) => ({ ...d, config: { ...d.config, [key]: value } }))

  const openCreate = () => {
    setEditing(null)
    setDraft(emptyDraft())
    setModalOpen(true)
  }
  const openEdit = (provider: AuthProviderAdmin) => {
    setEditing(provider)
    setDraft(draftFrom(provider))
    setModalOpen(true)
  }
  const closeModal = () => {
    setModalOpen(false)
    setEditing(null)
  }

  const canSave = (): boolean => {
    if (draft.name.trim() === "") return false
    const missing = fieldsFor(draft.kind).some(
      (f) => f.required && String(draft.config[f.key] ?? "").trim() === "",
    )
    if (missing) return false
    if (!editing && !/^[a-z0-9-]{3,64}$/.test(draft.id.trim())) return false
    return true
  }

  const submit = () => {
    if (!canSave()) {
      toast.error(t("providers.form.requiredErrs"))
      return
    }
    save.mutate()
  }

  const save = useMutationToast({
    mutationFn: async (): Promise<AuthProviderAdmin> => {
      const fields = fieldsFor(draft.kind)
      const config = draft.config
      const numFields = fields.filter((f) => f.type === "number")
      const normalized: Record<string, unknown> = { ...config }
      for (const f of numFields) {
        const raw = config[f.key]
        // Champ vide/effacé ou non numérique : on retire la clé au lieu
        // d'envoyer "" / NaN (zod number refuserait → invalid_config).
        const n = raw === undefined || raw === "" ? NaN : Number(raw)
        if (Number.isFinite(n)) normalized[f.key] = n
        else delete normalized[f.key]
      }
      const managed = isManagedKind(draft.kind)
      const payload = {
        kind: draft.kind,
        name: draft.name.trim(),
        enabled: draft.enabled,
        ...(managed ? { config: normalized } : {}),
      } as AuthProviderUpsert
      return editing
        ? api.updateAdminProvider(editing.id, payload)
        : api.createAdminProvider({ ...payload, config: normalized, id: draft.id.trim() })
    },
    success: () =>
      t(editing ? "providers.toast.updateSuccess" : "providers.toast.createSuccess"),
    // Rend visible le champ refusé par zod (sinon le message générique
    // "Configuration du fournisseur invalide." ne dit pas ce qui cloche).
    errorDescription: (err) => {
      const details = (err as ApiError).details as Record<string, string[]> | undefined
      const entry = details && Object.entries(details)[0]
      if (!entry) return err.message
      return `${err.message} — ${entry[0]}: ${entry[1]?.[0] ?? ""}`
    },
    invalidate: [["admin", "providers"]],
    onSuccess: closeModal,
  })

  const activeCount = providers.data?.filter((p) => p.enabled).length ?? 0
  const enabledMut = useMutationToast({
    mutationFn: (p: AuthProviderAdmin) =>
      api.updateAdminProvider(p.id, { enabled: !p.enabled }),
    success: (r) =>
      t("providers.toast.enabledChanged", {
        enabled: r.enabled ? t("providers.badge.enabled") : t("providers.badge.disabled"),
      }),
    invalidate: [["admin", "providers"]],
    onError: (err) => {
      if (err instanceof Error && (err as ApiError).code === "last_active_provider") {
        toast.error(t("providers.toast.lastActiveProvider"))
      }
    },
  })

  const removeProvider = useConfirmDelete<AuthProviderAdmin>({
    mutationFn: (p) => api.deleteAdminProvider(p.id),
    success: t("providers.toast.deleteSuccess"),
    invalidate: [["admin", "providers"]],
    confirm: (p) => ({
      title: t("providers.deleteConfirm.title"),
      description: t("providers.deleteConfirm.description", { name: p.name }),
    }),
  })

  const [testingId, setTestingId] = useState<string | null>(null)
  const testMut = useMutation({
    mutationFn: async (id: string) => {
      setTestingId(id)
      try {
        return await api.testAdminProvider(id)
      } finally {
        setTestingId(null)
      }
    },
    onSuccess: (r) => {
      if (r.ok) {
        toast.success(t("providers.toast.testOk"))
      } else {
        toast.error(t("providers.toast.testKo", { message: r.message ?? "HTTP" }))
      }
    },
    onError: (err) => {
      toast.error(t("providers.toast.testKo", { message: err.message }))
    },
  })

  // ── Pendings : approbation / rejet ─────────────────────────────────────
  const [approving, setApproving] = useState<PendingIdentity | null>(null)
  const [rejecting, setRejecting] = useState<PendingIdentity | null>(null)
  const [approveTenant, setApproveTenant] = useState("")
  const [approveRole, setApproveRole] = useState<"owner" | "operator" | "viewer">("viewer")
  const [rejectReason, setRejectReason] = useState("")

  const openApprove = (p: PendingIdentity) => {
    setApproveTenant(tenants.data?.[0]?.id ?? "")
    setApproveRole("viewer")
    setApproving(p)
  }

  const approveMut = useMutationToast({
    mutationFn: () =>
      api.approveAdminPending(approving!.id, { tenantId: approveTenant, role: approveRole }),
    success: t("providers.toast.approveSuccess"),
    invalidate: [["admin", "pendings"], ["users"]],
    onSuccess: () => setApproving(null),
  })

  const rejectMut = useMutationToast({
    mutationFn: () =>
      api.rejectAdminPending(rejecting!.id, rejectReason.trim() || undefined),
    success: t("providers.toast.rejectSuccess"),
    invalidate: [["admin", "pendings"]],
    onSuccess: () => setRejecting(null),
  })

  if (!me || !can("owner")) {
    return <Navigate to="/" replace />
  }

  return (
    <PageContainer size="5xl">
      <PageHeader
        title={t("providers.pageTitle")}
        subtitle={t("providers.pageSubtitle")}
        actions={
          <Button size="small" onClick={openCreate}>
            <Plus /> {t("providers.actions.new")}
          </Button>
        }
      />

      {/* ── Onglets : providers / approbations en attente ──────────────────── */}
      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as "providers" | "pendings")}>
        <Tabs.List>
          <Tabs.Trigger value="providers">{t("providers.tab.providers")}</Tabs.Trigger>
          <Tabs.Trigger value="pendings">
            {t("providers.tab.pendings")}
            {pendings.data && pendings.data.length > 0 && (
              <span className="ml-1 rounded-full bg-ui-bg-base-pressed px-1.5 text-xs">
                {pendings.data.length}
              </span>
            )}
          </Tabs.Trigger>
        </Tabs.List>

        <Tabs.Content value="providers" className="mt-5">
          {/* ── Providers tab ──────────────────────────────────────────────── */}
          <div className="mb-4">
            <Heading level="h3">{t("providers.list.title")}</Heading>
            {providers.data && (
              <Text size="small" className="text-ui-fg-muted">
                {t("providers.list.subtitle", { count: providers.data.length })}
              </Text>
            )}
          </div>

          {providers.isLoading ? (
            <div className="rounded-lg border border-ui-border-base bg-ui-bg-base p-6">
              <Text className="text-ui-fg-muted">{t("users.loading")}</Text>
            </div>
          ) : providers.data?.length === 0 ? (
            <div className="rounded-lg border border-ui-border-base bg-ui-bg-base p-8 text-center">
              <ShieldCheck className="mx-auto mb-2 h-8 w-8 text-ui-fg-muted" />
              <Text weight="plus" className="text-ui-fg-base">{t("providers.empty.title")}</Text>
              <Text size="small" className="mt-1 text-ui-fg-muted">{t("providers.empty.description")}</Text>
            </div>
          ) : (
            <ul className="flex flex-col gap-3">
              {providers.data?.map((provider) => {
                const kindInfo = KIND_BADGE[provider.kind] ?? { color: "grey" as const, icon: provider.kind }
                const isLastActive = provider.enabled && activeCount <= 1
                return (
                  <li
                    key={provider.id}
                    className="group rounded-lg border border-ui-border-base bg-ui-bg-base p-4 transition-all hover:shadow-sm sm:p-5"
                  >
                    {/* Header row */}
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-start gap-3">
                        <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-ui-bg-subtle">
                          <ShieldCheck className="h-[18px] w-[18px] text-ui-fg-muted" />
                        </div>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <Text weight="plus" className="truncate text-ui-fg-base">
                              {provider.name}
                            </Text>
                            <Badge size="2xsmall" color={kindInfo.color}>
                              {kindInfo.icon}
                            </Badge>
                            <Badge size="2xsmall" color={provider.enabled ? "green" : "grey"}>
                              {provider.enabled
                                ? t("providers.badge.enabled")
                                : t("providers.badge.disabled")}
                            </Badge>
                          </div>
                          <Text size="xsmall" className="mt-0.5 text-ui-fg-muted">
                            {provider.id}
                          </Text>
                        </div>
                      </div>
                    </div>

                    {/* Actions bar */}
                    <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-ui-border-base pt-3">
                      <div className="flex items-center gap-2">
                        <ToggleSwitch
                          checked={provider.enabled}
                          disabled={isLastActive}
                          onCheckedChange={() => enabledMut.mutate(provider)}
                          aria-label={t("providers.form.enabledLabel")}
                        />
                        <Label size="xsmall" className="text-ui-fg-muted">
                          {t("providers.form.enabledLabel")}
                        </Label>
                      </div>

                      <div className="flex-1" />

                      <div className="flex items-center gap-2">
                        {isManagedKind(provider.kind) && (
                          <Button
                            variant="secondary"
                            size="small"
                            disabled={testingId === provider.id}
                            isLoading={testingId === provider.id}
                            onClick={() => testMut.mutate(provider.id)}
                          >
                            <Beaker />
                            {t("providers.actions.test")}
                          </Button>
                        )}
                        <Button
                          variant="secondary"
                          size="small"
                          onClick={() => openEdit(provider)}
                        >
                          <PencilSquare />
                          {t("providers.actions.edit")}
                        </Button>
                        {provider.id !== "local" && (
                          <Button
                            variant="danger"
                            size="small"
                            onClick={() => removeProvider(provider)}
                          >
                            <Trash />
                            {t("providers.actions.delete")}
                          </Button>
                        )}
                      </div>
                    </div>
                  </li>
                )
              })}
            </ul>
          )}
        </Tabs.Content>

        <Tabs.Content value="pendings" className="mt-5">
          {/* ── Pendings tab ───────────────────────────────────────────────── */}
          <div className="mb-4">
            <Heading level="h3">{t("providers.pendings.title")}</Heading>
            {pendings.data && (
              <Text size="small" className="text-ui-fg-muted">
                {t("providers.pendings.subtitle", { count: pendings.data.length })}
              </Text>
            )}
          </div>

          {pendings.isLoading ? (
            <div className="rounded-lg border border-ui-border-base bg-ui-bg-base p-6">
              <Text className="text-ui-fg-muted">{t("users.loading")}</Text>
            </div>
          ) : pendings.data?.length === 0 ? (
            <div className="rounded-lg border border-ui-border-base bg-ui-bg-base p-8 text-center">
              <CheckCircle className="mx-auto mb-2 h-8 w-8 text-ui-fg-muted" />
              <Text weight="plus" className="text-ui-fg-base">{t("providers.pendings.empty.title")}</Text>
              <Text size="small" className="mt-1 text-ui-fg-muted">{t("providers.pendings.empty.description")}</Text>
            </div>
          ) : (
            <ul className="flex flex-col gap-3">
              {pendings.data?.map((pending) => (
                <li
                  key={pending.id}
                  className="rounded-lg border border-ui-border-base bg-ui-bg-base p-4 transition-all hover:shadow-sm sm:p-5"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-ui-bg-subtle">
                        <ShieldCheck className="h-[18px] w-[18px] text-ui-fg-muted" />
                      </div>
                      <div className="min-w-0">
                        <Text weight="plus" className="truncate text-ui-fg-base">
                          {pending.email ?? pending.name ?? t("providers.pendings.emailUnknown")}
                        </Text>
                        <div className="mt-0.5 flex items-center gap-2">
                          <Text size="xsmall" className="text-ui-fg-muted">
                            {pending.providerId}
                          </Text>
                          <Text size="xsmall" className="text-ui-fg-muted">
                            {new Date(pending.createdAt).toLocaleString()}
                          </Text>
                        </div>
                      </div>
                    </div>

                    <div className="flex shrink-0 items-center gap-2">
                      <Button
                        size="small"
                        variant="secondary"
                        onClick={() => openApprove(pending)}
                        disabled={tenants.isLoading || tenants.data?.length === 0}
                      >
                        <CheckCircle /> {t("providers.pendings.approve")}
                      </Button>
                      <Button
                        size="small"
                        variant="danger"
                        onClick={() => {
                          setRejectReason("")
                          setRejecting(pending)
                        }}
                      >
                        <XCircle /> {t("providers.pendings.reject")}
                      </Button>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Tabs.Content>
      </Tabs>

      {/* ── Modal create/edit provider ─────────────────────────────────── */}
      <FocusModal open={modalOpen} onOpenChange={(o) => o || closeModal()}>
        <FocusModal.Content>
          <FocusModal.Header>
            <FocusModal.Title asChild>
              <Heading>
                {editing
                  ? t("providers.form.titleEdit", { name: editing.name })
                  : t("providers.form.titleCreate")}
              </Heading>
            </FocusModal.Title>
          </FocusModal.Header>
          <FocusModal.Body className="overflow-y-auto">
            <ModalForm size="lg" onSubmit={submit}>
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <Label size="small">{t("providers.form.kindLabel")}</Label>
                  <Select
                    value={draft.kind}
                    onValueChange={(v) =>
                      setDraft((d) => ({ ...d, kind: v, config: {} }))
                    }
                    disabled={!!editing}
                  >
                    <Select.Trigger>
                      <Select.Value />
                    </Select.Trigger>
                    <Select.Content>
                      {(isManagedKind(draft.kind) ? KINDS : [...KINDS, draft.kind]).map((k) => (
                        <Select.Item key={k} value={k}>
                          {t(`providers.form.kind${k[0].toUpperCase()}${k.slice(1)}`)}
                        </Select.Item>
                      ))}
                    </Select.Content>
                  </Select>
                </div>
                <div>
                  <Label size="small">{t("providers.form.nameLabel")}</Label>
                  <Input
                    value={draft.name}
                    onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
                    placeholder={t("providers.form.namePlaceholder")}
                  />
                </div>
                {!editing && (
                  <div>
                    <Label size="small">{t("providers.form.idLabel")}</Label>
                    <Input
                      value={draft.id}
                      onChange={(e) => setDraft((d) => ({ ...d, id: e.target.value }))}
                      placeholder={t("providers.form.idPlaceholder")}
                    />
                    <Text size="xsmall" className="mt-1 text-ui-fg-muted">
                      {t("providers.form.idHint")}
                    </Text>
                  </div>
                )}
                <div className="flex items-center gap-2 pt-4">
                  <ToggleSwitch
                    checked={draft.enabled}
                    onCheckedChange={(checked) =>
                      setDraft((d) => ({ ...d, enabled: checked }))
                    }
                    aria-label={t("providers.form.enabledLabel")}
                  />
                  <div>
                    <Text weight="plus" size="small">
                      {t("providers.form.enabledLabel")}
                    </Text>
                    <Text size="xsmall" className="text-ui-fg-muted">
                      {t("providers.form.enabledHint")}
                    </Text>
                  </div>
                </div>
              </div>

              <div>
                <Label size="small">{t("providers.form.configLabel")}</Label>
                {fieldsFor(draft.kind).length === 0 ? (
                  <Text size="xsmall" className="mt-2 block text-ui-fg-muted">
                    {t("providers.form.configUnsupported")}
                  </Text>
                ) : (
                  <>
                    {fieldsFor(draft.kind).map((field) => (
                      <div key={field.key} className="mt-3">
                        <Label size="small">{t(`providers.${field.labelKey}`)}</Label>
                        {field.type === "textarea" ? (
                          <Textarea
                            value={String(draft.config[field.key] ?? "")}
                            onChange={(e) => setField(field.key, e.target.value)}
                            rows={4}
                            className="mt-1 font-mono"
                          />
                        ) : (
                          <Input
                            type={field.type === "password" ? "password" : "text"}
                            inputMode={field.type === "number" ? "numeric" : undefined}
                            value={String(draft.config[field.key] ?? "")}
                            onChange={(e) =>
                              setField(
                                field.key,
                                field.type === "number" ? Number(e.target.value) : e.target.value,
                              )
                            }
                            className="mt-1"
                          />
                        )}
                      </div>
                    ))}
                    <Text size="xsmall" className="mt-2 text-ui-fg-muted">
                      {t("providers.form.secretHint")}
                    </Text>
                  </>
                )}
              </div>

              <div className="mt-2 flex justify-end gap-2">
                <Button variant="secondary" type="button" onClick={closeModal}>
                  {t("providers.actions.cancel")}
                </Button>
                <Button type="submit" isLoading={save.isPending}>
                  {t("providers.actions.save")}
                </Button>
              </div>
            </ModalForm>
          </FocusModal.Body>
        </FocusModal.Content>
      </FocusModal>

      {/* ── Modal approbation ──────────────────────────────────────────── */}
      <FocusModal open={!!approving} onOpenChange={(o) => o || setApproving(null)}>
        <FocusModal.Content>
          <FocusModal.Header>
            <FocusModal.Title asChild>
              <Heading>
                {t("providers.pendings.approveTitle", {
                  email: approving?.email ?? t("providers.pendings.emailUnknown"),
                })}
              </Heading>
            </FocusModal.Title>
          </FocusModal.Header>
          <FocusModal.Body>
            <ModalForm
              onSubmit={() =>
                approveTenant && approveRole && !approveMut.isPending && approveMut.mutate()
              }
            >
              <div>
                <Label size="small">{t("providers.pendings.approveDesc")}</Label>
              </div>
              {tenants.isLoading ? (
                <Text className="text-ui-fg-subtle">{t("users.loading")}</Text>
              ) : tenants.data && tenants.data.length > 0 ? (
                <>
                  <div>
                    <Label size="small">{t("providers.pendings.tenantLabel")}</Label>
                    <Select value={approveTenant} onValueChange={setApproveTenant}>
                      <Select.Trigger>
                        <Select.Value />
                      </Select.Trigger>
                      <Select.Content>
                        {tenants.data.map((tenant) => (
                          <Select.Item key={tenant.id} value={tenant.id}>
                            {tenant.name} ({tenant.slug})
                          </Select.Item>
                        ))}
                      </Select.Content>
                    </Select>
                  </div>
                  <div>
                    <Label size="small">{t("providers.pendings.roleLabel")}</Label>
                    <Select
                      value={approveRole}
                      onValueChange={(v) =>
                        setApproveRole(v as "owner" | "operator" | "viewer")
                      }
                    >
                      <Select.Trigger>
                        <Select.Value />
                      </Select.Trigger>
                      <Select.Content>
                        <Select.Item value="viewer">{t("users.createModal.roleViewer")}</Select.Item>
                        <Select.Item value="operator">{t("users.createModal.roleOperator")}</Select.Item>
                        <Select.Item value="owner">{t("nav.ownerBadge")}</Select.Item>
                      </Select.Content>
                    </Select>
                    <Text size="xsmall" className="mt-1 text-ui-fg-muted">
                      {t("providers.pendings.roleHint")}
                    </Text>
                  </div>
                  <div className="mt-2 flex justify-end gap-2">
                    <Button variant="secondary" type="button" onClick={() => setApproving(null)}>
                      {t("providers.actions.cancel")}
                    </Button>
                    <Button type="submit" isLoading={approveMut.isPending}>
                      {t("providers.toast.approveSuccess")}
                    </Button>
                  </div>
                </>
              ) : (
                <div>
                  <Text className="text-ui-fg-subtle">
                    {t("providers.pendings.empty.title")}
                  </Text>
                </div>
              )}
            </ModalForm>
          </FocusModal.Body>
        </FocusModal.Content>
      </FocusModal>

      {/* ── Modal rejet ────────────────────────────────────────────────── */}
      <FocusModal open={!!rejecting} onOpenChange={(o) => o || setRejecting(null)}>
        <FocusModal.Content>
          <FocusModal.Header>
            <FocusModal.Title asChild>
              <Heading>
                {t("providers.pendings.rejectTitle", {
                  email: rejecting?.email ?? t("providers.pendings.emailUnknown"),
                })}
              </Heading>
            </FocusModal.Title>
          </FocusModal.Header>
          <FocusModal.Body>
            <ModalForm onSubmit={() => !rejectMut.isPending && rejectMut.mutate()}>
              <Text>{t("providers.pendings.rejectDesc", {
                email: rejecting?.email ?? t("providers.pendings.emailUnknown"),
              })}</Text>
              <div>
                <Label size="small">{t("providers.pendings.reasonLabel")}</Label>
                <Textarea
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                  rows={2}
                />
              </div>
              <div className="mt-2 flex justify-end gap-2">
                <Button variant="secondary" type="button" onClick={() => setRejecting(null)}>
                  {t("providers.actions.cancel")}
                </Button>
                <Button variant="danger" type="submit" isLoading={rejectMut.isPending}>
                  {t("providers.toast.rejectSuccess")}
                </Button>
              </div>
            </ModalForm>
          </FocusModal.Body>
        </FocusModal.Content>
      </FocusModal>
    </PageContainer>
  )
}
