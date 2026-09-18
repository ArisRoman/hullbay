import { Buildings, ChevronDownMini, CheckCircleMiniSolid } from "@medusajs/icons"
import { Badge, DropdownMenu, clx } from "@medusajs/ui"
import { useTranslation } from "react-i18next"
import { useMe } from "../lib/useMe"

const BADGE_COLOR: Record<string, "purple" | "blue" | "green"> = {
  owner: "purple",
  operator: "blue",
  viewer: "green",
}

/**
 * Switcher de tenant actif (Phase 5B §14). Session-scoped (§87) : la bascule
 * re-signe le JWT avec un nouveau claim tenantId ; aucune route URL :tenantSlug.
 * N'apparaît que lorsque le compte est membre de plusieurs tenants.
 */
export function TenantSwitcher() {
  const { t } = useTranslation()
  const { me, tenants, activeTenantId, switchTenant, isSwitchingTenant } = useMe()

  if (!tenants.length) return null

  const active = tenants.find((x) => x.tenantId === activeTenantId)

  return (
    <DropdownMenu>
      <DropdownMenu.Trigger asChild>
        <button
          disabled={isSwitchingTenant}
          aria-label={t("tenantSwitcher.switchTenant")}
          className={clx(
            "flex w-full items-center justify-between gap-2 rounded-md px-3 py-2 text-left",
            "text-ui-fg-subtle transition-colors",
            "hover:bg-ui-bg-base-hover hover:text-ui-fg-base",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ui-border-interactive",
            "disabled:cursor-not-allowed disabled:opacity-60",
          )}
        >
          <span className="flex min-w-0 items-center gap-2">
            <Buildings className="shrink-0 text-ui-fg-muted" />
            <span className="truncate text-ui-fg-base" title={active?.slug ?? ""}>
              {active?.slug ?? t("tenantSwitcher.unknownTenant")}
            </span>
          </span>
          <ChevronDownMini className="shrink-0 text-ui-fg-muted" />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Content align="start" side="right" className="w-56">
        {tenants.map((tenant) => {
          const isActive = tenant.tenantId === activeTenantId
          return (
            <DropdownMenu.Item
              key={tenant.tenantId}
              disabled={isSwitchingTenant}
              onClick={() => void switchTenant(tenant.tenantId)}
              className="flex items-center justify-between gap-2"
            >
              <span className="truncate" title={tenant.slug}>
                {tenant.slug}
              </span>
              <span className="flex shrink-0 items-center gap-1.5">
                <Badge color={BADGE_COLOR[tenant.role]} size="2xsmall" className="capitalize">
                  {tenant.role}
                </Badge>
                {isActive && <CheckCircleMiniSolid className="text-ui-fg-interactive" />}
              </span>
            </DropdownMenu.Item>
          )
        })}
      </DropdownMenu.Content>
    </DropdownMenu>
  )
}