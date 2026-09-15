/**
 * Fixture provider OAuth2 style GitHub — endpoints mockés en mémoire.
 * Servent discovery-less : authorizationUri, tokenUri, userinfoUri explicites.
 */

export class MockOauth2 {
  readonly authorizationUri: string
  readonly tokenUri: string
  readonly userinfoUri: string
  readonly clientId: string

  private _userinfo: Record<string, unknown>
  tokenRequests: string[] = []

  constructor(opts: { authorizationUri: string; tokenUri: string; userinfoUri: string; clientId: string }) {
    this.authorizationUri = opts.authorizationUri
    this.tokenUri = opts.tokenUri
    this.userinfoUri = opts.userinfoUri
    this.clientId = opts.clientId
    this._userinfo = { id: 42, login: "alice", name: "Alice Test", email: "alice@example.test", groups: ["admins"] }
  }

  setUserinfo(userinfo: Record<string, unknown>): void {
    this._userinfo = userinfo
  }

  /** fetchFn mocké : token_endpoint (POST) + userinfo (GET). */
  makeFetch(opts: { tokenStatus?: number; userinfoStatus?: number; accessToken?: string } = {}) {
    const self = this
    return async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = String(input)
      const body = String(init?.body ?? "")

      if (url === self.tokenUri) {
        self.tokenRequests.push(body)
        if (opts.tokenStatus && opts.tokenStatus !== 200) {
          return new Response(JSON.stringify({ error: "bad_grant" }), {
            status: opts.tokenStatus,
            headers: { "content-type": "application/json", "access-control-allow-origin": "*" },
          })
        }
        return new Response(JSON.stringify({ access_token: opts.accessToken ?? "at-gh", token_type: "bearer" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        })
      }

      if (url === self.userinfoUri) {
        if (opts.userinfoStatus && opts.userinfoStatus !== 200) {
          return new Response("unauthorized", { status: opts.userinfoStatus, headers: { "content-type": "text/plain" } })
        }
        return new Response(JSON.stringify(self._userinfo), {
          status: 200,
          headers: { "content-type": "application/json" },
        })
      }

      return new Response("not found", { status: 404 })
    }
  }
}