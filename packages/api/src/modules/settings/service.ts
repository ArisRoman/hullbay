import { prisma } from "../../lib/prisma"
import { applyDomainToCaddy } from "./caddy-domain"
import { DEFAULT_TENANT_ID } from "../auth/identity/auth-identity.service"

export class SettingsService {
    /**Lit les parametres du tenant. Renvoie domain: null si rien n'a ete configure */
    async get(tenantId = DEFAULT_TENANT_ID) {
        const Settings = await prisma.settings.upsert({
            where: { tenantId },
            create: { tenantId },
            update: {},
        })
        return { domain: Settings.domain }
    }

    /**
     * Definition ou bien remplacement du nom de domaine (par tenant)
     * 
     * on applique d'abord la config a caddy, et on ne persiste en DB que si caddy a accepte.
     */
    async setDomain(domain: string, tenantId = DEFAULT_TENANT_ID) {
        await applyDomainToCaddy(domain, tenantId)

        const Settings = await prisma.settings.upsert({
            where: { tenantId },
            create: { tenantId, domain },
            update: { domain },
        })

        return { 
            domain: Settings.domain,
            url: `https://${Settings.domain}`
        }
    }
}

export const settingsService = new SettingsService()