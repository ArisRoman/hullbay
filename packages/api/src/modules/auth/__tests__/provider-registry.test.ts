import { describe, it, expect, beforeEach } from "vitest";
import { ProviderRegistry, SUPPORTED_KINDS } from "../registry/provider-registry";
import { PROVIDER_SEEDS } from "../registry/seeds";

describe("ProviderRegistry", () => {
  let registry: ProviderRegistry;

  beforeEach(() => {
    registry = new ProviderRegistry();
  });

  it("déclare ldap comme kind supporté (hydratation au boot)", () => {
    expect(SUPPORTED_KINDS).toContain("ldap");
  });

  it("register + get par id", () => {
    registry.register({ id: "local", kind: "local", getConfig: () => ({}) } as never);
    expect(registry.get("local")).toBeTruthy();
  });

  it("register dupliqué écrase l'ancien", () => {
    registry.register({ id: "local", kind: "local", getConfig: () => ({ a: 1 }) } as never);
    registry.register({ id: "local", kind: "local", getConfig: () => ({ b: 2 }) } as never);
    expect(registry.list()).toHaveLength(1);
  });

  it("get retourne undefined si absent", () => {
    expect(registry.get("absent")).toBeUndefined();
  });

  it("require lève sur un provider absent", () => {
    expect(() => registry.require("absent")).toThrow(/introuvable/);
  });

  it("require retourne le provider enregistré", () => {
    registry.register({ id: "local", kind: "local", getConfig: () => ({}) } as never);
    expect(registry.require("local")).toBeTruthy();
  });

  it("list retourne tous les providers enregistrés", () => {
    registry.register({ id: "a", kind: "local", getConfig: () => ({}) } as never);
    registry.register({ id: "b", kind: "local", getConfig: () => ({}) } as never);
    expect(registry.list().map((p) => p.id).sort()).toEqual(["a", "b"]);
  });

  it("clear vide le registre", () => {
    registry.register({ id: "a", kind: "local", getConfig: () => ({}) } as never);
    registry.clear();
    expect(registry.list()).toHaveLength(0);
  });

  it("registerSeeds n'enregistre que les presets activés (Phase 2 : local)", () => {
    registry.registerSeeds();
    const ids = registry.list().map((p) => p.id);
    const enabledSeeds = PROVIDER_SEEDS.filter((s) => s.enabled).map((s) => s.id);
    expect(ids.sort()).toEqual(enabledSeeds.sort());
    expect(ids).toContain("local");
    expect(ids).not.toContain("oidc-generic");
    expect(ids).not.toContain("saml-generic");
  });
});