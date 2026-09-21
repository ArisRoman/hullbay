import { describe, it, expect, vi, beforeEach } from "vitest"
import { createLdapProvider, formatObjectGuid } from "../providers/ldap/ldap-provider"
import { AuthError } from "../providers/types"
import { IdentityPendingError } from "../core/identity-mapping"

// Mock de ldapts
const mockClient = {
  bind: vi.fn(),
  search: vi.fn(),
  unbind: vi.fn(),
}

vi.mock("ldapts", () => {
  return {
    Client: vi.fn().mockImplementation(function() {
      return mockClient
    }),
    Filter: {
      escape: (val: string) => val.replace(/([\\*()\0])/g, "\\$1"),
    },
  }
})

// Mock de prisma
vi.mock("../../../lib/prisma", () => ({
  prisma: {
    user: {
      findUnique: vi.fn(),
    },
    authIdentity: {
      updateMany: vi.fn().mockResolvedValue({ count: 1 }),
    },
  },
}))

// Mock de identity-mapping
vi.mock("../core/identity-mapping", () => ({
  resolveIdentity: vi.fn(),
  IdentityPendingError: class IdentityPendingError extends Error {
    readonly identity: unknown
    constructor(identity: unknown) {
      super("identité en attente d'approbation")
      this.name = "IdentityPendingError"
      this.identity = identity
    }
  },
}))

// Mock de policy
vi.mock("../mfa/policy", () => ({
  shouldRequireLocalMfa: vi.fn().mockReturnValue({ requireLocalMfa: false, reason: "mfa-idp-fournie" }),
}))

// Mock de secret-encryption-service
vi.mock("../secrets/secret-encryption-service", () => ({
  decryptObject: (obj: unknown) => obj,
}))

import { prisma } from "../../../lib/prisma"
import { resolveIdentity } from "../core/identity-mapping"

describe("LdapProvider (LDAP / LDAPS)", () => {
  const baseConfig = {
    id: "ldap-corp",
    name: "Enterprise LDAP",
    enabled: true,
    url: "ldaps://ldap.example.com:636",
    bindDn: "cn=admin,dc=example,dc=com",
    bindSecret: "secret-service-password",
    searchBase: "ou=users,dc=example,dc=com",
    searchFilter: "(&(objectClass=user)(sAMAccountName={{username}}))",
    stableAttr: "objectGUID",
    attrMap: {
      username: "sAMAccountName",
      email: "mail",
      name: "displayName",
      groups: "memberOf",
    },
  }

  beforeEach(() => {
    vi.clearAllMocks()
    mockClient.bind.mockResolvedValue(undefined)
    mockClient.unbind.mockResolvedValue(undefined)
  })

  it("formatObjectGuid convertit fidèlement un GUID Active Directory 16 octets", () => {
    // 16 octets d'un GUID AD simulé
    const buf = Buffer.from([
      0x01, 0x02, 0x03, 0x04,
      0x05, 0x06,
      0x07, 0x08,
      0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    ])
    const guid = formatObjectGuid(buf)
    expect(guid).toBe("04030201-0605-0807-090a-0b0c0d0e0f10")
  })

  it("authentifie avec succès un utilisateur existant via bind service + user bind", async () => {
    const provider = createLdapProvider(baseConfig)

    // GUID simulé
    const guidBuf = Buffer.alloc(16, 0xaa)

    mockClient.search.mockResolvedValueOnce({
      searchEntries: [
        {
          dn: "cn=alice,ou=users,dc=example,dc=com",
          sAMAccountName: "alice",
          mail: "alice@example.com",
          displayName: "Alice Smith",
          memberOf: ["cn=engineers,ou=groups,dc=example,dc=com"],
          objectGUID: guidBuf,
        },
      ],
    })

    vi.mocked(resolveIdentity).mockResolvedValueOnce({
      userId: "u-alice",
      providerId: "ldap-corp",
      subject: formatObjectGuid(guidBuf),
      email: "alice@example.com",
    })

    vi.mocked(prisma.user.findUnique).mockResolvedValueOnce({
      id: "u-alice",
      role: "operator",
    } as any)

    const result = await provider.authenticate({
      kind: "ldap",
      ldapUsername: "alice",
      ldapPassword: "password123",
    })

    expect(result.userId).toBe("u-alice")
    expect(result.role).toBe("operator")
    expect(result.mfaRequired).toBe(false)
    expect(result.identity.kind).toBe("ldap")
    expect(result.identity.issuer).toBeNull()
    expect(result.identity.subject).toBe(formatObjectGuid(guidBuf))
    expect(result.identity.groups).toEqual(["cn=engineers,ou=groups,dc=example,dc=com"])

    // Vérifie que le service account s'est lié d'abord, puis le user bind
    expect(mockClient.bind).toHaveBeenCalledWith("cn=admin,dc=example,dc=com", "secret-service-password")
    expect(mockClient.bind).toHaveBeenCalledWith("cn=alice,ou=users,dc=example,dc=com", "password123")
  })

  it("rejette fail-closed si le service account ne peut pas se lier (401)", async () => {
    const provider = createLdapProvider(baseConfig)
    mockClient.bind.mockRejectedValueOnce(new Error("Invalid service credentials"))

    await expect(
      provider.authenticate({
        kind: "ldap",
        ldapUsername: "alice",
        ldapPassword: "password123",
      }),
    ).rejects.toThrow(AuthError)
  })

  it("rejette fail-closed si la recherche ne trouve aucun utilisateur (401)", async () => {
    const provider = createLdapProvider(baseConfig)
    mockClient.search.mockResolvedValueOnce({ searchEntries: [] })

    await expect(
      provider.authenticate({
        kind: "ldap",
        ldapUsername: "inconnu",
        ldapPassword: "password123",
      }),
    ).rejects.toThrow(AuthError)
  })

  it("rejette fail-closed si le mot de passe utilisateur est erroné au 2e bind (401)", async () => {
    const provider = createLdapProvider(baseConfig)

    mockClient.search.mockResolvedValueOnce({
      searchEntries: [
        {
          dn: "cn=alice,ou=users,dc=example,dc=com",
          sAMAccountName: "alice",
          objectGUID: Buffer.alloc(16, 0x11),
        },
      ],
    })

    // 1er bind (service account) OK, 2e bind (user) en échec
    mockClient.bind
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("Invalid Credentials"))

    await expect(
      provider.authenticate({
        kind: "ldap",
        ldapUsername: "alice",
        ldapPassword: "badpassword",
      }),
    ).rejects.toThrow(AuthError)
  })

  it("rejette un compte Active Directory désactivé ou verrouillé via userAccountControl", async () => {
    const provider = createLdapProvider(baseConfig)

    // UAC avec bit ACCOUNTDISABLE (0x0002) activé
    mockClient.search.mockResolvedValueOnce({
      searchEntries: [
        {
          dn: "cn=disabled,ou=users,dc=example,dc=com",
          sAMAccountName: "disabled",
          objectGUID: Buffer.alloc(16, 0x22),
          userAccountControl: 0x0202, // 514 = NORMAL_ACCOUNT | ACCOUNTDISABLE
        },
      ],
    })

    await expect(
      provider.authenticate({
        kind: "ldap",
        ldapUsername: "disabled",
        ldapPassword: "password123",
      }),
    ).rejects.toThrow(AuthError)
  })

  it("propage IdentityPendingError si l'identité n'est pas encore approuvée", async () => {
    const provider = createLdapProvider(baseConfig)
    const guidBuf = Buffer.alloc(16, 0x33)

    mockClient.search.mockResolvedValueOnce({
      searchEntries: [
        {
          dn: "cn=newuser,ou=users,dc=example,dc=com",
          sAMAccountName: "newuser",
          mail: "newuser@example.com",
          objectGUID: guidBuf,
        },
      ],
    })

    vi.mocked(resolveIdentity).mockRejectedValueOnce(
      new IdentityPendingError({
        providerId: "ldap-corp",
        kind: "ldap",
        issuer: null,
        subject: formatObjectGuid(guidBuf),
      }),
    )

    await expect(
      provider.authenticate({
        kind: "ldap",
        ldapUsername: "newuser",
        ldapPassword: "password123",
      }),
    ).rejects.toThrow(IdentityPendingError)
  })

  it("supporte un identifiant stable OpenLDAP entryUUID (string)", async () => {
    const openLdapConfig = {
      ...baseConfig,
      stableAttr: "entryUUID",
      searchFilter: "(&(objectClass=inetOrgPerson)(uid={{username}}))",
    }
    const provider = createLdapProvider(openLdapConfig)

    mockClient.search.mockResolvedValueOnce({
      searchEntries: [
        {
          dn: "uid=bob,ou=people,dc=example,dc=com",
          uid: "bob",
          mail: "bob@example.com",
          entryUUID: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        },
      ],
    })

    vi.mocked(resolveIdentity).mockResolvedValueOnce({
      userId: "u-bob",
      providerId: "ldap-corp",
      subject: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      email: "bob@example.com",
    })

    vi.mocked(prisma.user.findUnique).mockResolvedValueOnce({
      id: "u-bob",
      role: "viewer",
    } as any)

    const result = await provider.authenticate({
      kind: "ldap",
      ldapUsername: "bob",
      ldapPassword: "password123",
    })

    expect(result.userId).toBe("u-bob")
    expect(result.identity.subject).toBe("f47ac10b-58cc-4372-a567-0e02b2c3d479")
  })

  it("force le décodage binaire de l'attribut stable (explicitBufferAttributes)", async () => {
    const provider = createLdapProvider(baseConfig)
    const guidBuf = Buffer.alloc(16, 0x55)

    mockClient.search.mockResolvedValueOnce({
      searchEntries: [
        {
          dn: "cn=alice,ou=users,dc=example,dc=com",
          sAMAccountName: "alice",
          mail: "alice@example.com",
          objectGUID: guidBuf,
        },
      ],
    })
    vi.mocked(resolveIdentity).mockResolvedValueOnce({
      userId: "u-alice",
      providerId: "ldap-corp",
      subject: formatObjectGuid(guidBuf),
      email: "alice@example.com",
    })
    vi.mocked(prisma.user.findUnique).mockResolvedValueOnce({ id: "u-alice", role: "operator" } as any)

    await provider.authenticate({ kind: "ldap", ldapUsername: "alice", ldapPassword: "password123" })

    expect(mockClient.search).toHaveBeenCalledWith(
      baseConfig.searchBase,
      expect.objectContaining({ explicitBufferAttributes: ["objectGUID"] }),
    )
  })

  it("décode un identifiant stable binaire non-objectGUID en hexadécimal", async () => {
    const provider = createLdapProvider({ ...baseConfig, stableAttr: "entryUUID" })
    const uuidBuf = Buffer.from("f47ac10b58cc4372a5670e02b2c3d479", "hex")

    mockClient.search.mockResolvedValueOnce({
      searchEntries: [
        {
          dn: "uid=bob,ou=people,dc=example,dc=com",
          uid: "bob",
          mail: "bob@example.com",
          entryUUID: [uuidBuf],
        },
      ],
    })
    vi.mocked(resolveIdentity).mockResolvedValueOnce({
      userId: "u-bob",
      providerId: "ldap-corp",
      subject: uuidBuf.toString("hex"),
      email: "bob@example.com",
    })
    vi.mocked(prisma.user.findUnique).mockResolvedValueOnce({ id: "u-bob", role: "viewer" } as any)

    const result = await provider.authenticate({ kind: "ldap", ldapUsername: "bob", ldapPassword: "password123" })

    expect(result.identity.subject).toBe(uuidBuf.toString("hex"))
  })

  it("suit les références LDAP quand handleReferrals est activé", async () => {
    const provider = createLdapProvider({ ...baseConfig, handleReferrals: true })
    const guidBuf = Buffer.alloc(16, 0x77)

    mockClient.search
      .mockResolvedValueOnce({
        searchEntries: [],
        searchReferences: [{ uris: ["ldaps://ldap2.example.com/dc=example,dc=com"] }],
      })
      .mockResolvedValueOnce({
        searchEntries: [
          {
            dn: "cn=carol,dc=example,dc=com",
            sAMAccountName: "carol",
            mail: "carol@example.com",
            objectGUID: guidBuf,
          },
        ],
      })

    vi.mocked(resolveIdentity).mockResolvedValueOnce({
      userId: "u-carol",
      providerId: "ldap-corp",
      subject: formatObjectGuid(guidBuf),
      email: "carol@example.com",
    })
    vi.mocked(prisma.user.findUnique).mockResolvedValueOnce({ id: "u-carol", role: "operator" } as any)

    const result = await provider.authenticate({ kind: "ldap", ldapUsername: "carol", ldapPassword: "password123" })

    expect(result.userId).toBe("u-carol")
    expect(mockClient.search).toHaveBeenCalledTimes(2)
    // Le secret du compte de service n'est JAMAIS envoyé au host référencé.
    const serviceBinds = mockClient.bind.mock.calls.filter(
      (c) => c[0] === baseConfig.bindDn,
    )
    expect(serviceBinds).toHaveLength(1)
  })

  it("ne suit pas une référence hors domaine (anti-SSRF)", async () => {
    const provider = createLdapProvider({ ...baseConfig, handleReferrals: true })

    mockClient.search.mockResolvedValueOnce({
      searchEntries: [],
      searchReferences: [{ uris: ["ldaps://evil.attacker.net/dc=example,dc=com"] }],
    })

    await expect(
      provider.authenticate({ kind: "ldap", ldapUsername: "carol", ldapPassword: "password123" }),
    ).rejects.toThrow(AuthError)
    // Seule la recherche initiale : la référence étrangère est ignorée.
    expect(mockClient.search).toHaveBeenCalledTimes(1)
  })

  it("ne suit pas une référence cross-host en clair (ldap://)", async () => {
    const provider = createLdapProvider({ ...baseConfig, handleReferrals: true })

    mockClient.search.mockResolvedValueOnce({
      searchEntries: [],
      searchReferences: [{ uris: ["ldap://ldap2.example.com/dc=example,dc=com"] }],
    })

    await expect(
      provider.authenticate({ kind: "ldap", ldapUsername: "carol", ldapPassword: "password123" }),
    ).rejects.toThrow(AuthError)
    expect(mockClient.search).toHaveBeenCalledTimes(1)
  })

  it("échoue fail-closed si searchFilter ne contient aucun placeholder", async () => {
    const provider = createLdapProvider({
      ...baseConfig,
      searchFilter: "(&(objectClass=user)(sAMAccountName=admin))",
    })

    await expect(
      provider.authenticate({ kind: "ldap", ldapUsername: "alice", ldapPassword: "password123" }),
    ).rejects.toThrow(AuthError)
  })

  it("égalise le coût d'un bind sur utilisateur introuvable (anti-oracle temporel)", async () => {
    const provider = createLdapProvider(baseConfig)
    mockClient.search.mockResolvedValueOnce({ searchEntries: [] })

    await expect(
      provider.authenticate({ kind: "ldap", ldapUsername: "inconnu", ldapPassword: "password123" }),
    ).rejects.toThrow(AuthError)

    const timingBinds = mockClient.bind.mock.calls.filter((c) =>
      typeof c[0] === "string" && c[0].includes("timing_guard"),
    )
    expect(timingBinds).toHaveLength(1)
  })

  it("ignore les références si handleReferrals est désactivé (échec fail-closed)", async () => {
    const provider = createLdapProvider(baseConfig)

    mockClient.search.mockResolvedValueOnce({
      searchEntries: [],
      searchReferences: [{ uris: ["ldap://ldap2.example.com/dc=example,dc=com"] }],
    })

    await expect(
      provider.authenticate({ kind: "ldap", ldapUsername: "carol", ldapPassword: "password123" }),
    ).rejects.toThrow(AuthError)
    expect(mockClient.search).toHaveBeenCalledTimes(1)
  })

  it("testConnection retourne ok: true si le bind service fonctionne", async () => {
    const provider = createLdapProvider(baseConfig)
    mockClient.bind.mockResolvedValueOnce(undefined)

    const res = await provider.testConnection()
    expect(res.ok).toBe(true)
    expect(mockClient.unbind).toHaveBeenCalled()
  })

  it("testConnection retourne ok: false avec message d'erreur si échec", async () => {
    const provider = createLdapProvider(baseConfig)
    mockClient.bind.mockRejectedValueOnce(new Error("Connection refused"))

    const res = await provider.testConnection()
    expect(res.ok).toBe(false)
    expect(res.message).toContain("Connection refused")
  })
})
