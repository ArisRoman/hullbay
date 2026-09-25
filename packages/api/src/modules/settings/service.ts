import { prisma } from "../../lib/prisma"
import { applyDomainToCaddy } from "./caddy-domain"
import { DEFAULT_TENANT_ID } from "../auth/identity/auth-identity.service"
import { AuthError } from "../auth/providers/types"

/** Environnement de production au sens strict (hors développement/test). */
function isProdLike(): boolean {
    const env = process.env.NODE_ENV
    return env !== "development" && env !== "test"
}

export interface WebauthnSettingsInput {
    enabled: boolean
    origin?: string
    rpId?: string
    rpName?: string
}

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

    /** Source de vérité WebAuthn du tenant : résolue ici, jamais depuis l'environnement. */
    async getWebauthn(tenantId = DEFAULT_TENANT_ID) {
        const Settings = await prisma.settings.upsert({
            where: { tenantId },
            create: { tenantId },
            update: {},
        })
        return {
            enabled: Settings.webauthnEnabled,
            origin: Settings.webauthnOrigin,
            rpId: Settings.webauthnRpId,
            rpName: Settings.webauthnRpName,
        }
    }

    /**
     * Enregistre la configuration WebAuthn du tenant (configuration publique :
     * aucun secret impliqué, aucun chiffrement nécessaire).
     *
     * Règles :
     * - origin explicite : HTTPS exigé en production, aucun path/query/fragment,
     *   normalisée (protocole + host) avant stockage ;
     * - origin absente : dérivée automatiquement de https://<domain> si le
     *   domaine existe ; sinon, en production, une activation est rejetée
     *   (domain_not_configured) ;
     * - rpId absent : dérivé de hostname(origin) ; explicite : validation de
     *   compatibilité suffixe domaniale avec l'origin ;
     * - rpName défaut : "Hullbay".
     */
    async setWebauthn(tenantId: string, input: WebauthnSettingsInput) {
        const existing = await prisma.settings.upsert({
            where: { tenantId },
            create: { tenantId },
            update: {},
        })

        let nextOrigin = existing.webauthnOrigin
        if (input.origin !== undefined && input.origin.trim().length > 0) {
            // normalizeOrigin exige déjà HTTPS en production (http autorisé dev/test).
            nextOrigin = this.normalizeOrigin(input.origin)
        } else if (!nextOrigin && existing.domain) {
            // Origin absente : dérivée depuis le domaine public (priorité à l'existant).
            nextOrigin = `https://${existing.domain}`
        }

        // Origin persistée (ex. configurée http:// en dev puis déployée en prod) :
        // la valeur conservée doit respecter les règles de production, même quand
        // l'origin n'est pas fournie dans la requête.
        if (isProdLike() && nextOrigin && !nextOrigin.startsWith("https://")) {
            throw new AuthError("webauthn_origin_invalid", "origin WebAuthn : HTTPS requis en production", 400)
        }

        // Activation en production sans domaine public → refus explicite.
        // La désactivation reste autorisée sans domaine.
        if (input.enabled && !nextOrigin && isProdLike()) {
            throw new AuthError("domain_not_configured", "activation WebAuthn nécessite un domaine public configuré", 400)
        }

        let nextRpId = existing.webauthnRpId
        if (input.rpId !== undefined && input.rpId.trim().length > 0) {
            nextRpId = this.validateRpId(input.rpId, nextOrigin)
        } else if (nextOrigin && !nextRpId) {
            nextRpId = new URL(nextOrigin).hostname
        } else if (nextOrigin && existing.webauthnOrigin !== nextOrigin && nextRpId) {
            // Origin modifiée, rpId non fourni : revalider le rpId existant contre la
            // nouvelle origin — jamais persister une paire incompatible. Un rpId encore
            // compatible (racine domaniale commune) est conservé ; sinon re-dérivé.
            if (!this.isRpIdCompatible(nextRpId, nextOrigin)) {
                nextRpId = new URL(nextOrigin).hostname
            }
        }

        const nextRpName = input.rpName?.trim() || existing.webauthnRpName || "Hullbay"

        const Settings = await prisma.settings.upsert({
            where: { tenantId },
            create: {
                tenantId,
                webauthnEnabled: input.enabled,
                webauthnOrigin: nextOrigin,
                webauthnRpId: nextRpId,
                webauthnRpName: nextRpName,
            },
            update: {
                webauthnEnabled: input.enabled,
                webauthnOrigin: nextOrigin,
                webauthnRpId: nextRpId,
                webauthnRpName: nextRpName,
            },
        })

        return {
            enabled: Settings.webauthnEnabled,
            origin: Settings.webauthnOrigin,
            rpId: Settings.webauthnRpId,
            rpName: Settings.webauthnRpName,
        }
    }

    private normalizeOrigin(origin: string): string {
        let parsed: URL
        try {
            parsed = new URL(origin)
        } catch {
            throw new AuthError("webauthn_origin_invalid", "origin WebAuthn invalide", 400)
        }
        if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
            throw new AuthError("webauthn_origin_invalid", "origin WebAuthn : protocole http/https requis", 400)
        }
        if (isProdLike() && parsed.protocol !== "https:") {
            throw new AuthError("webauthn_origin_invalid", "origin WebAuthn : HTTPS requis en production", 400)
        }
        if (parsed.hash || parsed.search || (parsed.pathname && parsed.pathname !== "/")) {
            throw new AuthError("webauthn_origin_invalid", "origin WebAuthn : ni path, ni query, ni fragment", 400)
        }
        if (parsed.username || parsed.password) {
            throw new AuthError("webauthn_origin_invalid", "origin WebAuthn : credentials interdites", 400)
        }
        return `${parsed.protocol}//${parsed.host}`
    }

    private isRpIdCompatible(rpId: string, origin: string): boolean {
        const host = new URL(origin).hostname
        return host === rpId || host.endsWith(`.${rpId}`)
    }

    private validateRpId(rpId: string, origin: string | null): string {
        if (!origin) {
            throw new AuthError("webauthn_rpid_invalid", "rpId WebAuthn : origin manquante", 400)
        }
        if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*$/i.test(rpId)) {
            throw new AuthError("webauthn_rpid_invalid", "rpId WebAuthn : hostname invalide", 400)
        }
        if (!this.isRpIdCompatible(rpId, origin)) {
            throw new AuthError("webauthn_rpid_invalid", "rpId WebAuthn incompatible avec l'origin", 400)
        }
        return rpId
    }
}

export const settingsService = new SettingsService()