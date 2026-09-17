/**
 * Provider LDAP / LDAPS (Phase 5A3, N°2 du plan).
 *
 * Modèle d'exécution propre (§17.4) :
 * 1. Bind service account (si configuré)
 * 2. Search utilisateur (searchFilter sur base DN)
 * 3. Récupération des attributs + vérification compte désactivé (UAC)
 * 4. Bind utilisateur (vérification des credentials)
 * 5. Résolution des groupes (memberOf ou recherche groupFilter)
 * 6. Mapping ExternalIdentity avec attribut stable (search attr ≠ identity attr)
 * 7. Résolution via identity-mapping (User existant OU PendingIdentity)
 */

import { Client, Filter } from "ldapts"
import { prisma } from "../../../../lib/prisma"
import {
  AuthError,
  type AuthInput,
  type AuthProviderContract,
  type AuthResult,
  type ExternalIdentity,
  type ProviderPublicConfig,
} from "../types"
import { resolveIdentity } from "../../core/identity-mapping"
import { shouldRequireLocalMfa } from "../../mfa/policy"

export interface LdapTlsOptions {
  rejectUnauthorized?: boolean
  ca?: string
}

export interface LdapAttrMap {
  username?: string
  email?: string
  name?: string
  groups?: string
}

export interface LdapProviderOptions {
  id: string
  name?: string
  enabled?: boolean
  url: string
  tlsOptions?: LdapTlsOptions
  bindDn?: string
  bindSecret?: string
  searchBase: string
  searchFilter: string
  groupSearchBase?: string
  groupFilter?: string
  stableAttr: string // "objectGUID" | "entryUUID" | etc. (search attribute ≠ identity attribute)
  attrMap?: LdapAttrMap
  timeoutMs?: number
  handleReferrals?: boolean
}

/**
 * Formate un objectGUID Active Directory (Buffer 16 octets) au format UUID canonique
 * (avec l'endianness little-endian propre à Microsoft pour les 3 premiers segments).
 */
export function formatObjectGuid(buffer: Buffer): string {
  if (buffer.length !== 16) {
    return buffer.toString("hex")
  }
  const p1 = Buffer.from(buffer.subarray(0, 4)).reverse().toString("hex")
  const p2 = Buffer.from(buffer.subarray(4, 6)).reverse().toString("hex")
  const p3 = Buffer.from(buffer.subarray(6, 8)).reverse().toString("hex")
  const p4 = buffer.subarray(8, 10).toString("hex")
  const p5 = buffer.subarray(10, 16).toString("hex")
  return `${p1}-${p2}-${p3}-${p4}-${p5}`
}

export class LdapProvider implements AuthProviderContract {
  readonly id: string
  readonly kind = "ldap" as const
  readonly enabled: boolean
  private readonly name: string
  private readonly options: LdapProviderOptions

  constructor(options: LdapProviderOptions) {
    this.id = options.id
    this.name = options.name || "LDAP"
    this.enabled = options.enabled ?? false
    // Les champs sensibles (bindSecret) sont déchiffrés en amont par
    // loadProviderRows : l'adapter reçoit toujours une config en clair et ne
    // doit donc PAS déchiffrer une seconde fois (double-déchiffrement).
    this.options = options
  }

  getConfig(): ProviderPublicConfig {
    return {
      id: this.id,
      kind: this.kind,
      name: this.name,
      enabled: this.enabled,
    }
  }

  private createClient(timeoutMs?: number, urlOverride?: string): Client {
    const timeout = timeoutMs ?? this.options.timeoutMs ?? 5000
    return new Client({
      url: urlOverride ?? this.options.url,
      timeout,
      connectTimeout: timeout,
      tlsOptions: {
        rejectUnauthorized: this.options.tlsOptions?.rejectUnauthorized ?? true,
        ca: this.options.tlsOptions?.ca ? [this.options.tlsOptions.ca] : undefined,
      },
      strictDN: false,
    })
  }

  /**
   * Suit (profondeur bornée) les références LDAP renvoyées par le serveur quand
   * `handleReferrals` est actif. ldapts n'effectue pas ce chaînage lui-même : il
   * expose les URIs dans `searchReferences`. Best-effort : une référence
   * injoignable/invalide est ignorée, elle ne bloque jamais l'authentification.
   */
  private async followReferrals(
    // ldapts expose des `SearchReference` ({ uris }) à l'exécution ; le typage
    // public de Client.search annonce `string[]`. On accepte les deux.
    references: Array<string | { uris?: string[] }>,
    filter: string,
    attributes: string[],
  ): Promise<Array<Record<string, unknown>>> {
    const entries: Array<Record<string, unknown>> = []
    const visited = new Set<string>()
    const queue = references.flatMap((r) => (typeof r === "string" ? [r] : (r.uris ?? [])))
    const MAX_FOLLOW = 3

    // Durcissement : on ne suit une référence que vers le domaine (suffixe) du
    // serveur configuré, et jamais en clair vers un host étranger. Les
    // credentials du compte de service ne sont JAMAIS envoyés à un host
    // différent (sinon un annuaire compromis/mal configuré exfiltre le secret
    // et SSRF l'app vers un host interne arbitraire).
    const configured = new URL(this.options.url)
    const configuredHost = configured.hostname.toLowerCase()
    const labels = configuredHost.split(".")
    const parentDomain = labels.length > 2 ? labels.slice(1).join(".") : configuredHost

    const isSameDomain = (host: string): boolean =>
      host === configuredHost || host === parentDomain || host.endsWith(`.${parentDomain}`)

    let followed = 0
    while (queue.length > 0 && followed < MAX_FOLLOW) {
      const uri = queue.shift()
      if (!uri || visited.has(uri)) continue
      visited.add(uri)
      followed++
      try {
        const parsed = new URL(uri)
        if (parsed.protocol !== "ldap:" && parsed.protocol !== "ldaps:") continue
        const refHost = parsed.hostname.toLowerCase()
        const sameHost = refHost === configuredHost
        // Host étranger : uniquement toléré en LDAPS et dans le même domaine.
        if (!sameHost && !(parsed.protocol === "ldaps:" && isSameDomain(refHost))) continue
        const baseDn = decodeURIComponent(parsed.pathname.replace(/^\//, ""))
        if (!baseDn) continue
        const client = this.createClient(5000, `${parsed.protocol}//${parsed.host}`)
        try {
          // Le bind service-account n'est réutilisé que sur le host configuré ;
          // vers un autre host on reste anonyme (jamais de fuite du secret).
          if (sameHost && this.options.bindDn && this.options.bindSecret) {
            await client.bind(this.options.bindDn, this.options.bindSecret)
          }
          const res = await client.search(baseDn, {
            filter,
            scope: "sub",
            attributes,
            sizeLimit: 2,
          })
          entries.push(...((res.searchEntries ?? []) as Array<Record<string, unknown>>))
        } finally {
          await client.unbind().catch(() => {})
        }
      } catch {
        // Référence injoignable / invalide : ignorée (best-effort).
      }
    }
    return entries
  }

  /**
   * Effectue un bind factice (DN inexistant) pour égaliser le coût d'un
   * aller-retour bind entre un utilisateur introuvable/bloqué et un échec de
   * mot de passe — évite un oracle temporel d'énumération de comptes.
   */
  private async equalizeBindWork(): Promise<void> {
    const client = this.createClient()
    try {
      await client.bind("cn=__hullbay_timing_guard__,dc=invalid", "invalid-password")
    } catch {
      // attendu : le bind factice échoue
    } finally {
      await client.unbind().catch(() => {})
    }
  }

  /**
   * Teste la connectivité et le bind service account (utilisé par l'endpoint admin de test).
   */
  async testConnection(): Promise<{ ok: boolean; message: string }> {
    const client = this.createClient(5000)
    try {
      if (this.options.bindDn && this.options.bindSecret) {
        await client.bind(this.options.bindDn, this.options.bindSecret)
      }
      await client.unbind()
      return { ok: true, message: "connexion et bind LDAP réussis" }
    } catch (err) {
      await client.unbind().catch(() => {})
      return {
        ok: false,
        message: err instanceof Error ? err.message : "échec de connexion LDAP",
      }
    }
  }

  async authenticate(input: AuthInput): Promise<AuthResult> {
    const username = input.ldapUsername || input.email
    const password = input.ldapPassword || input.password

    if (!username || !password) {
      throw new AuthError("invalid_credentials", "identifiants invalides", 401)
    }

    const client = this.createClient()

    try {
      // 1. Bind service account si configuré
      if (this.options.bindDn && this.options.bindSecret) {
        try {
          await client.bind(this.options.bindDn, this.options.bindSecret)
        } catch {
          throw new AuthError("invalid_credentials", "échec d’authentification du compte de service LDAP", 401)
        }
      }

      // 2. Recherche de l'utilisateur avec filtre sécurisé (Filter.escape)
      const safeUsername = Filter.escape(username.trim())
      let filterString = this.options.searchFilter
      if (filterString.includes("{{username}}")) {
        filterString = filterString.replace(/\{\{username\}\}/g, safeUsername)
      } else if (filterString.includes("{username}")) {
        filterString = filterString.replace(/\{username\}/g, safeUsername)
      } else if (filterString.includes("%u")) {
        filterString = filterString.replace(/%u/g, safeUsername)
      } else {
        // Fail-closed : un filtre admin sans placeholder est une erreur de
        // configuration, pas un prétexte à substitution silencieuse.
        throw new AuthError(
          "invalid_credentials",
          "searchFilter LDAP mal configuré : placeholder {{username}}, {username} ou %u requis",
          500,
        )
      }

      const attrMap = this.options.attrMap ?? {}
      const usernameAttr = attrMap.username ?? "sAMAccountName"
      const emailAttr = attrMap.email ?? "mail"
      const nameAttr = attrMap.name ?? "displayName"
      const groupsAttr = attrMap.groups ?? "memberOf"

      const attributesToFetch = [
        this.options.stableAttr,
        usernameAttr,
        emailAttr,
        nameAttr,
        groupsAttr,
        "cn",
        "userAccountControl",
      ]

      let searchResult
      try {
        searchResult = await client.search(this.options.searchBase, {
          filter: filterString,
          scope: "sub",
          attributes: attributesToFetch,
          sizeLimit: 2,
          // Force le décodage binaire des attributs stables (objectGUID AD) :
          // sans cela ldapts renvoie une string mojibake, jamais un Buffer.
          explicitBufferAttributes: [this.options.stableAttr],
        })
      } catch {
        throw new AuthError("invalid_credentials", "erreur de recherche LDAP", 401)
      }

      let searchEntries = searchResult.searchEntries ?? []

      // Aucun résultat dans la base : suivre les références si activé (forêts
      // AD multi-domaines). Les références sont renvoyées par le serveur dans
      // searchReferences ; on les suit de façon bornée et best-effort.
      if (searchEntries.length === 0 && this.options.handleReferrals && searchResult.searchReferences?.length) {
        searchEntries = (await this.followReferrals(
          searchResult.searchReferences,
          filterString,
          attributesToFetch,
        )) as unknown as typeof searchEntries
      }

      if (searchEntries.length === 0) {
        await this.equalizeBindWork()
        throw new AuthError("invalid_credentials", "identifiants invalides", 401)
      }

      if (searchEntries.length > 1) {
        throw new AuthError("invalid_credentials", "résultat de recherche LDAP ambigu", 401)
      }

      const userEntry = searchEntries[0]
      if (!userEntry || !userEntry.dn) {
        throw new AuthError("invalid_credentials", "entrée LDAP invalide", 401)
      }

      // 3. Vérification des indicateurs Active Directory (userAccountControl)
      const rawUac = Array.isArray(userEntry.userAccountControl)
        ? userEntry.userAccountControl[0]
        : userEntry.userAccountControl
      if (typeof rawUac === "number" || typeof rawUac === "string") {
        const uacNum = Number(rawUac)
        // 0x0002 = ACCOUNTDISABLE, 0x0010 = LOCKOUT
        if ((uacNum & 0x0002) !== 0 || (uacNum & 0x0010) !== 0) {
          await this.equalizeBindWork()
          throw new AuthError("invalid_credentials", "compte désactivé ou verrouillé", 401)
        }
      }

      // Libère le client de service avant le bind utilisateur
      await client.unbind().catch(() => {})

      // 4. Bind utilisateur pour valider son mot de passe
      const userClient = this.createClient()
      try {
        await userClient.bind(userEntry.dn, password)
      } catch {
        throw new AuthError("invalid_credentials", "identifiants invalides", 401)
      } finally {
        await userClient.unbind().catch(() => {})
      }

      // 5. Extraction de l'identifiant stable (search attribute ≠ identity attribute)
      const rawStable = userEntry[this.options.stableAttr]
      if (!rawStable) {
        throw new AuthError("invalid_credentials", "attribut d’identité stable absent de l’annuaire", 401)
      }

      let stableSubject: string
      if (Buffer.isBuffer(rawStable)) {
        if (this.options.stableAttr.toLowerCase() === "objectguid") {
          stableSubject = formatObjectGuid(rawStable)
        } else {
          stableSubject = rawStable.toString("hex")
        }
      } else if (Array.isArray(rawStable)) {
        const first = rawStable[0]
        if (Buffer.isBuffer(first)) {
          stableSubject =
            this.options.stableAttr.toLowerCase() === "objectguid"
              ? formatObjectGuid(first)
              : first.toString("hex")
        } else {
          stableSubject = String(first)
        }
      } else {
        stableSubject = String(rawStable)
      }

      // 6. Extraction des attributs utilisateur (email, name, groups)
      const rawEmail = userEntry[emailAttr]
      const email = typeof rawEmail === "string" ? rawEmail : (Array.isArray(rawEmail) ? String(rawEmail[0]) : null)

      const rawName = userEntry[nameAttr] || userEntry.cn
      const name = typeof rawName === "string" ? rawName : (Array.isArray(rawName) ? String(rawName[0]) : undefined)

      let groups: string[] = []
      const rawGroups = userEntry[groupsAttr]
      if (Array.isArray(rawGroups)) {
        groups = rawGroups.map(String)
      } else if (typeof rawGroups === "string") {
        groups = [rawGroups]
      }

      // Recherche de groupes explicite (OpenLDAP / Posix / RFC2307) si configurée
      if (groups.length === 0 && this.options.groupSearchBase && this.options.groupFilter) {
        try {
          const groupFilterStr = this.options.groupFilter
            .replace(/\{\{username\}\}/g, safeUsername)
            .replace(/\{username\}/g, safeUsername)
            .replace(/%u/g, safeUsername)
            .replace(/\{\{dn\}\}/g, Filter.escape(userEntry.dn))
          const groupClient = this.createClient()
          try {
            if (this.options.bindDn && this.options.bindSecret) {
              await groupClient.bind(this.options.bindDn, this.options.bindSecret)
            }
            const groupRes = await groupClient.search(this.options.groupSearchBase, {
              filter: groupFilterStr,
              scope: "sub",
              attributes: ["cn", "name"],
            })
            for (const entry of groupRes.searchEntries ?? []) {
              const gName = entry.cn || entry.name
              if (gName) groups.push(String(gName))
            }
          } finally {
            await groupClient.unbind().catch(() => {})
          }
        } catch {
          // Ne bloque pas l'authentification si la recherche de groupes échoue
        }
      }

      // 7. Construction de l'ExternalIdentity
      const externalIdentity: ExternalIdentity = {
        providerId: this.id,
        kind: "ldap",
        issuer: null, // NULL pour ldap (§5.1)
        subject: stableSubject,
        email,
        name,
        groups,
      }

      // 8. Résolution d'identité (AuthIdentity existante OU PendingIdentity créée)
      const resolved = await resolveIdentity(externalIdentity)

      const user = await prisma.user.findUnique({
        where: { id: resolved.userId },
        select: { id: true, role: true },
      })

      if (!user) {
        throw new AuthError("invalid_credentials", "utilisateur introuvable", 401)
      }

      // Évaluation de la politique MFA locale (par défaut : pas de 2e MFA sauf rôle imposé)
      const mfaDecision = shouldRequireLocalMfa({
        providerKind: "ldap",
        role: user.role,
      })

      // Mise à jour lastLoginAt en fire-and-forget
      void prisma.authIdentity
        .updateMany({
          where: {
            providerId: this.id,
            issuer: null,
            subject: stableSubject,
          },
          data: { lastLoginAt: new Date() },
        })
        .catch(() => {})

      return {
        identity: externalIdentity,
        mfaRequired: mfaDecision.requireLocalMfa,
        userId: user.id,
        role: user.role,
      }
    } catch (err) {
      await client.unbind().catch(() => {})
      throw err
    }
  }
}

export function createLdapProvider(options: LdapProviderOptions): LdapProvider {
  return new LdapProvider(options)
}
