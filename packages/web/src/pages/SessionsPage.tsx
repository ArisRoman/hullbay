import { useQuery } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { Badge, Button, Container, Table, Text } from "@medusajs/ui"
import { ComputerDesktop, Spinner } from "@medusajs/icons"
import { api } from "../lib/api"
import { useConfirmDelete } from "../lib/useConfirmDelete"
import { PageHeader, PageContainer } from "../components/PageHeader"
import { EmptyState } from "../components/EmptyState"

type Session = {
  id: string
  jti: string
  providerId: string
  createdAt: string
  expiresAt: string
  lastSeenAt: string
  ip: string | null
  userAgent: string | null
  current: boolean
}

/** Traduit un User-Agent brut en libellé lisible « OS · Navigateur ». */
function describeDevice(userAgent: string | null): string | null {
  if (!userAgent) return null
  const os = /windows/i.test(userAgent)
    ? "Windows"
    : /mac os|macintosh/i.test(userAgent)
      ? "macOS"
      : /android/i.test(userAgent)
        ? "Android"
        : /iphone|ipad|ios/i.test(userAgent)
          ? "iOS"
          : /linux/i.test(userAgent)
            ? "Linux"
            : ""
  const browser = /edg\//i.test(userAgent)
    ? "Edge"
    : /chrome\//i.test(userAgent)
      ? "Chrome"
      : /firefox\//i.test(userAgent)
        ? "Firefox"
        : /safari\//i.test(userAgent)
          ? "Safari"
          : ""
  return [os, browser].filter(Boolean).join(" · ") || null
}

export function SessionsPage() {
  const { t, i18n } = useTranslation()
  const { data, isLoading } = useQuery({
    queryKey: ["sessions"],
    queryFn: api.listSessions,
  })

  const revoke = useConfirmDelete<{ jti: string; current: boolean }>({
    mutationFn: ({ jti }) => api.revokeSession(jti),
    success: t("sessions.revoked"),
    invalidate: [["sessions"]],
    confirm: ({ current }) => ({
      title: t("sessions.confirm.title"),
      description: current
        ? t("sessions.confirm.currentDescription")
        : t("sessions.confirm.description"),
      confirmText: t("sessions.revoke"),
    }),
  })

  const sessions: Session[] = data?.sessions ?? []
  const formatDate = (value: string) =>
    new Date(value).toLocaleString(i18n.language)

  const deviceLabel = (session: Session) =>
    describeDevice(session.userAgent) ?? t("sessions.unknownDevice")

  return (
    <PageContainer>
      <PageHeader
        title={t("sessions.pageTitle")}
        subtitle={t("sessions.pageSubtitle")}
      />

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Spinner className="animate-spin text-ui-fg-muted" />
        </div>
      ) : sessions.length === 0 ? (
        <Container className="p-0">
          <EmptyState
            icon={ComputerDesktop}
            title={t("sessions.empty.title")}
            description={t("sessions.empty.description")}
          />
        </Container>
      ) : (
        <Container className="p-0">
          {/* Desktop : tableau dense (masqué < md) */}
          <Table className="hidden md:table">
            <Table.Header>
              <Table.Row>
                <Table.HeaderCell>{t("sessions.table.device")}</Table.HeaderCell>
                <Table.HeaderCell>{t("sessions.table.ip")}</Table.HeaderCell>
                <Table.HeaderCell>
                  {t("sessions.table.lastSeen")}
                </Table.HeaderCell>
                <Table.HeaderCell>
                  {t("sessions.table.expiresAt")}
                </Table.HeaderCell>
                <Table.HeaderCell className="w-0" />
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {sessions.map((session) => (
                <Table.Row key={session.jti}>
                  <Table.Cell>
                    <div className="flex items-center gap-2">
                      <Text size="small" weight="plus">
                        {deviceLabel(session)}
                      </Text>
                      {session.current && (
                        <Badge size="2xsmall" color="green">
                          {t("sessions.current")}
                        </Badge>
                      )}
                    </div>
                    <Text size="xsmall" className="text-ui-fg-muted">
                      {session.providerId}
                    </Text>
                  </Table.Cell>
                  <Table.Cell>{session.ip ?? "—"}</Table.Cell>
                  <Table.Cell>{formatDate(session.lastSeenAt)}</Table.Cell>
                  <Table.Cell>{formatDate(session.expiresAt)}</Table.Cell>
                  <Table.Cell>
                    <Button
                      variant="secondary"
                      size="small"
                      onClick={() =>
                        revoke({ jti: session.jti, current: session.current })
                      }
                    >
                      {t("sessions.revoke")}
                    </Button>
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>

          {/* Mobile : card list (masquée >= md) */}
          <ul className="divide-y divide-ui-border-base md:hidden">
            {sessions.map((session) => (
              <li key={session.jti} className="flex flex-col gap-3 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <Text size="small" weight="plus" className="truncate">
                        {deviceLabel(session)}
                      </Text>
                      {session.current && (
                        <Badge size="2xsmall" color="green">
                          {t("sessions.current")}
                        </Badge>
                      )}
                    </div>
                    <Text size="xsmall" className="text-ui-fg-muted">
                      {session.providerId}
                    </Text>
                  </div>
                  <Button
                    variant="secondary"
                    size="small"
                    className="shrink-0"
                    onClick={() =>
                      revoke({ jti: session.jti, current: session.current })
                    }
                  >
                    {t("sessions.revoke")}
                  </Button>
                </div>
                <dl className="grid grid-cols-2 gap-x-3 gap-y-2">
                  <div>
                    <dt>
                      <Text size="xsmall" className="text-ui-fg-muted">
                        {t("sessions.table.ip")}
                      </Text>
                    </dt>
                    <dd>
                      <Text size="small">{session.ip ?? "—"}</Text>
                    </dd>
                  </div>
                  <div>
                    <dt>
                      <Text size="xsmall" className="text-ui-fg-muted">
                        {t("sessions.table.lastSeen")}
                      </Text>
                    </dt>
                    <dd>
                      <Text size="small">
                        {formatDate(session.lastSeenAt)}
                      </Text>
                    </dd>
                  </div>
                  <div className="col-span-2">
                    <dt>
                      <Text size="xsmall" className="text-ui-fg-muted">
                        {t("sessions.table.expiresAt")}
                      </Text>
                    </dt>
                    <dd>
                      <Text size="small">
                        {formatDate(session.expiresAt)}
                      </Text>
                    </dd>
                  </div>
                </dl>
              </li>
            ))}
          </ul>
        </Container>
      )}
    </PageContainer>
  )
}
