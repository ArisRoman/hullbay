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
  SECRET_MASK,
  type AuthProviderAdmin,
  type AuthProviderUpsert,
  type PendingIdentity,
} from "../lib/api"
import { useMe } from "../lib/useMe"
import { useMutationToast } from "../lib/useMutationToast"
import { useConfirmDelete } from "../lib/useConfirmDelete"
import { PageContainer, PageHeader } from "../components/PageHeader"
import { ActionMenu } from "../components/ActionMenu"
import { EmptyState } from "../components/EmptyState"
import { ListContainer, ListRow } from "../components/ListContainer"
import { ModalForm } from "../components/ModalForm"
import { ToggleSwitch } from "../components/ToggleSwitch"

type Kind = "oidc" | "oauth2" | "saml"

const KINDS: Kind[] = ["oidc", "oauth2", "saml"]

const KIND_COLOR: Record<Kind, "blue" | "purple" | "orange"> = {
  oidc: "blue",
  oauth2: "purple",
  saml: "orange",
}

/** Champs de config exposés par le formulaire, par protocole (whitelist côté
 *  API — ici on reflète les schémas zod du backend sans rien ajouter). */
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
}

/** Draft d'un formulaire create/edit (config : string|number brut du form). */
type Draft = {
  kind: Kind
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
 * Le backend masque les secrets (jamais renvoyés) ; le marqueur "••••••••"
 * envoyé en PUT conserve la valeur actuelle.
 */
export function AdminProvidersPage() {
  const { t } = useTranslation()
  const { me, can } = useMe()

  const [tab, setTab] = useState<"providers" | "pendings">("providers")

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

  /** Validation côté client avant toute mutation : les champs requis du
   *  protocole courant + nom (et l'id au create). Un seul toast d'erreur. */
  const canSave = (): boolean => {
    if (draft.name.trim() === "") return false
    const missing = CONFIG_FIELDS[draft.kind].some(
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
      const fields = CONFIG_FIELDS[draft.kind]
      const config = draft.config
      const numFields = fields.filter((f) => f.type === "number")
      const normalized: Record<string, unknown> = { ...config }
      for (const f of numFields) {
        const raw = config[f.key]
        if (raw !== undefined && raw !== "") normalized[f.key] = Number(raw)
      }
      const payload = {
        kind: draft.kind,
        name: draft.name.trim(),
        enabled: draft.enabled,
        config: normalized,
      } as AuthProviderUpsert
      return editing
        ? api.updateAdminProvider(editing.id, payload)
        : api.createAdminProvider({ ...payload, id: draft.id.trim() })
    },
    success: (p) =>
      t(editing ? "providers.toast.updateSuccess" : "providers.toast.createSuccess"),
    invalidate: [["admin", "providers"]],
    onSuccess: closeModal,
  })

  // ── Providers : toggle enabled / suppression / test ────────────────────
  const enabledMut = useMutationToast({
    mutationFn: (p: AuthProviderAdmin) =>
      api.updateAdminProvider(p.id, { enabled: !p.enabled }),
    success: (r) =>
      t("providers.toast.enabledChanged", {
        enabled: r.enabled ? t("providers.badge.enabled") : t("providers.badge.disabled"),
      }),
    invalidate: [["admin", "providers"]],
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
        toast.error(
          t("providers.toast.testKo", { message: r.message ?? "HTTP" }),
        )
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
    mutationFn: () => api.approveAdminPending(approving!.id, { tenantId: approveTenant, role: approveRole }),
    success: t("providers.toast.approveSuccess"),
    invalidate: [["admin", "pendings"], ["users"]],
    onSuccess: () => setApproving(null),
  })

  const rejectMut = useMutationToast({
    mutationFn: () => api.rejectAdminPending(rejecting!.id, rejectReason.trim() || undefined),
    success: t("providers.toast.rejectSuccess"),
    invalidate: [["admin", "pendings"]],
    onSuccess: () => setRejecting(null),
  })

  if (!me || !can("owner")) {
    return <Navigate to="/" replace />
  }

  return (
    <PageContainer size="5xl">
      <PageHeader title={t("providers.pageTitle")} subtitle={t("providers.pageSubtitle")} />

      <Tabs value={tab} onValueChange={(v) => setTab(v as "providers" | "pendings")}>
        <Tabs.List>
          <Tabs.Trigger value="providers">
            {t("providers.tab.providers")}
          </Tabs.Trigger>
          <Tabs.Trigger value="pendings">
            {t("providers.tab.pendings")}
            {pendings.data && pendings.data.length > 0 && (
              <span className="ml-1 rounded-full bg-ui-bg-base-pressed px-1.5 text-xs">
                {pendings.data.length}
              </span>
            )}
          </Tabs.Trigger>
        </Tabs.List>

        <Tabs.Content value="providers" className="pt-4">
          {/* ── Liste des providers ─────────────────────────────────────── */}
          <ListContainer
            title={t("providers.list.title")}
            subtitle={providers.data ? t("providers.list.subtitle", { count: providers.data.length }) : undefined}
            actions={
              <Button size="small" onClick={openCreate}>
                <Plus /> {t("providers.actions.new")}
              </Button>
            }
            isEmpty={!providers.isLoading && providers.data?.length === 0}
            empty={
              <EmptyState
                icon={ShieldCheck}
                title={t("providers.empty.title")}
                description={t("providers.empty.description")}
              />
            }
          >
            {providers.isLoading ? (
              <div className="px-6 py-8">
                <Text className="text-ui-fg-subtle">{t("users.loading")}</Text>
              </div>
            ) : (
              providers.data?.map((provider) => (
                <ListRow key={provider.id}>
                  <div className="flex min-w-0 items-center gap-3">
                    <ShieldCheck className="shrink-0 text-ui-fg-muted" />
                    <div className="min-w-0">
                      <Text weight="plus" className="truncate">
                        {provider.name}
                      </Text>
                      <Badge size="2xsmall" color={KIND_COLOR[provider.kind] ?? "grey"}>
                        {provider.kind}
                      </Badge>
                      <Text size="xsmall" className="mt-0.5 text-ui-fg-muted">
                        {provider.id}
                      </Text>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <Badge size="2xsmall" color={provider.enabled ? "green" : "grey"}>
                      {provider.enabled
                        ? t("providers.badge.enabled")
                        : t("providers.badge.disabled")}
                    </Badge>
                    <div className="flex items-center gap-2">
                      <Label size="xsmall" className="text-ui-fg-muted">
                        {t("providers.form.enabledLabel")}
                      </Label>
                      <ToggleSwitch
                        checked={provider.enabled}
                        onCheckedChange={() => enabledMut.mutate(provider)}
                        aria-label={t("providers.form.enabledLabel")}
                      />
                    </div>
                    <ActionMenu
                      groups={[
                        {
                          actions: [
                            {
                              label: t("providers.actions.test"),
                              icon: <Beaker />,
                              disabled: testingId === provider.id,
                              onClick: () => testMut.mutate(provider.id),
                            },
                          ],
                        },
                        {
                          actions: [{
                            label: t("providers.actions.edit"),
                            icon: <PencilSquare />,
                            onClick: () => openEdit(provider),
                          }],
                        },
                        {
                          actions: [{
                            label: t("providers.actions.delete"),
                            icon: <Trash />,
                            variant: "danger",
                            onClick: () => removeProvider(provider),
                          }],
                        },
                      ]}
                    />
                  </div>
                </ListRow>
              ))
            )}
          </ListContainer>
        </Tabs.Content>

        <Tabs.Content value="pendings" className="pt-4">
          {/* ── Identités en attente ────────────────────────────────────── */}
          <ListContainer
            title={t("providers.pendings.title")}
            subtitle={pendings.data ? t("providers.pendings.subtitle", { count: pendings.data.length }) : undefined}
            isEmpty={!pendings.isLoading && pendings.data?.length === 0}
            empty={
              <EmptyState
                icon={ShieldCheck}
                title={t("providers.pendings.empty.title")}
                description={t("providers.pendings.empty.description")}
              />
            }
          >
            {pendings.isLoading ? (
              <div className="px-6 py-8">
                <Text className="text-ui-fg-subtle">{t("users.loading")}</Text>
              </div>
            ) : (
              pendings.data?.map((pending) => (
                <ListRow key={pending.id}>
                  <div className="flex min-w-0 items-center gap-3">
                    <ShieldCheck className="shrink-0 text-ui-fg-muted" />
                    <div className="min-w-0">
                      <Text weight="plus" className="truncate">
                        {pending.email ?? pending.name ?? t("providers.pendings.emailUnknown")}
                      </Text>
                      <Text size="xsmall" className="text-ui-fg-muted">
                        {pending.providerId}
                      </Text>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <Text size="xsmall" className="text-ui-fg-subtle">
                      {new Date(pending.createdAt).toLocaleString()}
                    </Text>
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
                </ListRow>
              ))
            )}
          </ListContainer>
        </Tabs.Content>
      </Tabs>

      {/* ── Modal create/edit provider ─────────────────────────────────── */}
      <FocusModal open={modalOpen} onOpenChange={(o) => o || closeModal()}>
        <FocusModal.Content>
          <FocusModal.Header>
            <Heading>
              {editing
                ? t("providers.form.titleEdit", { name: editing.name })
                : t("providers.form.titleCreate")}
            </Heading>
          </FocusModal.Header>
          <FocusModal.Body className="overflow-y-auto">
            <ModalForm size="lg" onSubmit={submit}>
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <Label size="small">{t("providers.form.kindLabel")}</Label>
                  <Select
                    value={draft.kind}
                    onValueChange={(v) =>
                      setDraft((d) => ({ ...d, kind: v as Kind, config: {} }))
                    }
                    disabled={!!editing}
                  >
                    <Select.Trigger>
                      <Select.Value />
                    </Select.Trigger>
                    <Select.Content>
                      {KINDS.map((k) => (
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
                    onCheckedChange={(checked) => setDraft((d) => ({ ...d, enabled: checked }))}
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
                {CONFIG_FIELDS[draft.kind].map((field) => (
                  <div key={field.key} className="mt-3">
                    <Label size="small">{t(field.labelKey)}</Label>
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
                        onChange={(e) => setField(field.key, field.type === "number" ? Number(e.target.value) : e.target.value)}
                        className="mt-1"
                      />
                    )}
                  </div>
                ))}
                <Text size="xsmall" className="mt-2 text-ui-fg-muted">
                  {t("providers.form.secretHint")}
                </Text>
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
            <Heading>
              {t("providers.pendings.approveTitle", {
                email: approving?.email ?? t("providers.pendings.emailUnknown"),
              })}
            </Heading>
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
                        <Select.Item value="viewer">viewer</Select.Item>
                        <Select.Item value="operator">operator</Select.Item>
                        <Select.Item value="owner">owner</Select.Item>
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
            <Heading>
              {t("providers.pendings.rejectTitle", {
                email: rejecting?.email ?? t("providers.pendings.emailUnknown"),
              })}
            </Heading>
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