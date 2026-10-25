import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { afterAll, beforeAll, describe, expect, it } from "vitest"
import { RcloneStorageProvider, StorageProviderError } from "../rclone-provider"

/**
 * Faux binaire rclone : vérifie l'interface réelle (argv, stdin, parsing)
 * sans dépendre du réseau ni d'un backend distant.
 */
const SCRIPT = `#!/bin/sh
cmd="$1"
case "$cmd" in
  rcat) cat > "$FAKE_DIR/object" ;;
  cat) cat "$FAKE_DIR/object" ;;
  lsjson)
    if [ "$2" = "--stat" ]; then
      echo '{"Size":5,"ModTime":"2026-10-25T10:00:00Z","IsDir":false}'
    else
      echo '[{"Path":"dir/a.sql.gz","Size":5,"IsDir":false},{"Path":"dir","Size":0,"IsDir":true}]'
    fi ;;
  hashsum) echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  x" ;;
  deletefile)
    if [ -f "$FAKE_DIR/fail" ]; then
      echo ":s3,access_key_id=AKIAEXAMPLE,secret_access_key=xyz:bucket" >&2
      exit 1
    fi
    rm -f "$FAKE_DIR/object" ;;
  moveto) echo "not supported by this backend" >&2; exit 1 ;;
  *) echo "commande inconnue: $cmd" >&2; exit 2 ;;
esac
`

let dir: string
let binary: string

beforeAll(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), "hullbay-rclone-"))
  binary = path.join(dir, "rclone")
  await writeFile(binary, SCRIPT, "utf8")
  await chmod(binary, 0o755)
  process.env.FAKE_DIR = dir
})

afterAll(async () => {
  delete process.env.FAKE_DIR
  await rm(dir, { recursive: true, force: true })
})

function provider() {
  return new RcloneStorageProvider(":s3,access_key_id=K,secret_access_key=S:bucket", {
    binary,
    timeoutMs: 5000,
  })
}

describe("RcloneStorageProvider", () => {
  it("écrit via rcat puis relit", async () => {
    const result = await provider().put("dir/a.sql.gz", Buffer.from("hello"))
    expect(result.size).toBe(5)
    expect(await readFile(path.join(dir, "object"), "utf8")).toBe("hello")
  })

  it("liste en ignorant les répertoires", async () => {
    const entries = await provider().list("dir")
    expect(entries).toEqual([
      { key: "dir/a.sql.gz", size: 5, modifiedAt: undefined },
    ])
  })

  it("lit le hash sha256 natif", async () => {
    expect(await provider().hash("dir/a.sql.gz")).toBe("a".repeat(64))
  })

  it("retourne false quand le backend ne supporte pas le rename", async () => {
    expect(await provider().move("a", "b")).toBe(false)
  })

  it("ne laisse jamais fuiter la remote-string dans une erreur", async () => {
    await writeFile(path.join(dir, "fail"), "1")
    try {
      await provider().delete("dir/a.sql.gz")
      throw new Error("aurait dû échouer")
    } catch (err) {
      expect(err).toBeInstanceOf(StorageProviderError)
      expect((err as Error).message).not.toContain("AKIAEXAMPLE")
      expect((err as Error).message).not.toContain("secret_access_key=xyz")
    } finally {
      await rm(path.join(dir, "fail"), { force: true })
    }
  })
})
