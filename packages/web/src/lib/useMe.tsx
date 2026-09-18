import { createContext, useContext, useState, type ReactNode } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { api, auth, type Me, type MemberTenant } from "./api"

export type Role = "owner" | "operator" | "viewer"

const RANK: Record<Role, number> = { viewer: 0, operator: 1, owner: 2 }

type MeContextValue = {
  me: Me | undefined
  isLoading: boolean
  isError: boolean
  error?: unknown
  can: (min: Role) => boolean
  /** Membreships du compte (tenantId + rôle + slug) — alimente le TenantSwitcher. */
  tenants: MemberTenant[]
  /** Tenant actif de la session courante (claim JWT re-signé à chaque bascule). */
  activeTenantId?: string
  /** Bascule le tenant actif : re-sign de la session puis rechargement des données. */
  switchTenant: (tenantId: string) => Promise<void>
  isSwitchingTenant: boolean
}

const MeContext = createContext<MeContextValue | null>(null)

export function MeProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["me"],
    queryFn: api.me,
    staleTime: 15_000,
    retry: false,
    // Re-fetch à chaque montage : mfaEnabled peut changer en cours de session
    // (enrôlement via /activate-mfa ou le challenge de login) sans que le
    // cache ne le voie — un "me" périmé fait boucler l'app sur /activate-mfa.
    refetchOnMount: "always",
    refetchOnWindowFocus: false,
  })

  const me = data as Me | undefined
  const can = (min: Role) => {
    if (!me) return false
    return (RANK[me.role] ?? -1) >= RANK[min]
  }

  const tenants = me?.tenants ?? []
  const activeTenantId = me?.activeTenantId

  const [isSwitchingTenant, setSwitchingTenant] = useState(false)

  const switchTenant = async (tenantId: string) => {
    if (!tenantId || tenantId === activeTenantId) return
    setSwitchingTenant(true)
    try {
      // Re-sign côté API : le nouveau token porte le claim tenantId ciblé.
      const res = await api.switchTenant(tenantId)
      auth.set(res.token)
      // Toutes les requêtes dépendent du tenant de session (guard backend) :
      // on invalide tout pour que nav/can() et les listes reflètent le tenant actif.
      await queryClient.invalidateQueries()
    } finally {
      setSwitchingTenant(false)
    }
  }

  return (
    <MeContext.Provider value={{ me, isLoading, isError, error, can, tenants, activeTenantId, switchTenant, isSwitchingTenant }}>
      {children}
    </MeContext.Provider>
  )
}

export function useMe(): MeContextValue {
  const ctx = useContext(MeContext)
  if (!ctx) throw new Error("useMe doit être utilisé dans <MeProvider>")
  return ctx
}