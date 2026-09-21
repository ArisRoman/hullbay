import type { Server as HttpServer } from "node:http"
import jwt from "jsonwebtoken"
import { Server as SocketIOServer } from "socket.io"
import { eventBus } from "../lib/event-bus"
import { DockerEngineService } from "../modules/docker-engine/service"
import { authService } from "../modules/auth/service"
import { prisma } from "../lib/prisma"
import { clusterService } from "../modules/clusters/service"
import { DEFAULT_TENANT_ID } from "../modules/auth/identity/auth-identity.service"

/**
 * Loader WebSocket (socket.io) — calque le pattern backend/src/loaders/chat-websocket.ts.
 *
 * - Auth JWT obligatoire au handshake (le canvas n'est jamais accessible anonyme).
 * - Rooms par projet : `project:<id>` → les events live (node.state, deploy...) y sont diffusés.
 * - Rooms par tenant : `tenant:<id>` → les events système/opérations y sont diffusés.
 * - Stream de logs d'un conteneur à la demande (subscribe:logs).
 *
 * Isolation WS stricte — join/subscribe vérifient l'appartenance au
 * tenant, le relai emit scope par tenant et projet (plus de io.emit global pour
 * les events métier).
 */
export function attachWebSocket(httpServer: HttpServer): SocketIOServer {
  const io = new SocketIOServer(httpServer, {
    path: "/ws",
    cors: {
      origin: (process.env.WEB_ORIGIN || "http://localhost:5273").split(","),
      credentials: true,
    },
    transports: ["polling", "websocket"],
  })

  // Auth au handshake : via authService.verifyToken qui exige l'audience SESSION
  // (rejette tout token mfa-pending — pas de bypass MFA par le WebSocket).
  io.use((socket, next) => {
    const token = socket.handshake.auth?.token as string | undefined
    if (!token) return next(new Error("AUTH_FAILED"))
    try {
      const decoded = authService.verifyToken(token)
      const header = jwt.decode(token, { complete: true })
      const sessionId = (header as { header?: { kid?: string } })?.header?.kid ?? undefined
      socket.data.userId = decoded.sub
      socket.data.role = decoded.role
      socket.data.sessionId = sessionId
      socket.data.tenantId = decoded.tenantId ?? DEFAULT_TENANT_ID
      next()
    } catch {
      next(new Error("AUTH_FAILED"))
    }
  })

  io.on("connection", (socket) => {
    // Chaque socket rejoint la room de son tenant.
    void socket.join(`tenant:${socket.data.tenantId as string}`)

    // Rejoindre la room d'un projet (pour recevoir ses events live).
    // Validation que le projet appartient bien au tenant du socket.
    socket.on("join:project", async (projectId: string) => {
      if (typeof projectId !== "string") return
      const tenantId = socket.data.tenantId as string
      const exists = await prisma.project.findUnique({
        where: { id: projectId, tenantId },
        select: { id: true },
      })
      if (!exists) {
        socket.emit("error", { message: "projet introuvable ou accès refusé", projectId })
        return
      }
      socket.join(`project:${projectId}`)
    })

    socket.on("leave:project", (projectId: string) => {
      if (typeof projectId === "string") socket.leave(`project:${projectId}`)
    })

    // Stream de logs d'un conteneur à la demande.
    // Le cluster doit appartenir au tenant du socket.
    let logStream: NodeJS.ReadableStream | null = null
    socket.on("subscribe:logs", async (payload: { clusterId: string; containerId: string }) => {
      if (typeof payload?.containerId !== "string" || typeof payload?.clusterId !== "string") return
      const tenantId = socket.data.tenantId as string
      const cluster = await clusterService.get(payload.clusterId, tenantId)
      if (!cluster) {
        socket.emit("error", { message: "cluster introuvable ou accès refusé", containerId: payload.containerId })
        return
      }
      try {
        const docker = await DockerEngineService.forCluster(payload.clusterId, undefined, tenantId)
        logStream = await docker.streamLogs(payload.containerId)
        logStream.on("data", (chunk: Buffer) => {
          socket.emit("log", { containerId: payload.containerId, line: chunk.toString("utf8") })
        })
      } catch (err) {
        socket.emit("error", {
          message: err instanceof Error ? err.message : "log stream failed",
        })
      }
    })
    socket.on("unsubscribe:logs", () => {
      ;(logStream as unknown as { destroy?: () => void })?.destroy?.()
      logStream = null
    })
    socket.on("disconnect", () => {
      ;(logStream as unknown as { destroy?: () => void })?.destroy?.()
      logStream = null
    })
  })

  // Relai des events ops → rooms scopées (tenant / projet uniquement).
  // Plus de io.emit() pour les events métier : chaque socket reçoit uniquement les
  // events de son tenant. Les events système globaux (updates, auth, user) restent
  // émis globalement car ils ne sont pas liés à un tenant spécifique.
  eventBus.on("*", async (event) => {
    const data = event.data ?? {}

    // 1) Event lié à un projet → room projet (uniquement les sockets qui ont join:project)
    if (typeof data.projectId === "string") {
      io.to(`project:${data.projectId}`).emit(event.name, data)
      return
    }

    // 2) Event portant tenantId explicitement → room tenant
    // 3) Sinon, résolution du tenant via clusterId/serverId (events infra : cluster,
    //    server, secret, provision.step). Empêche toute fuite cross-tenant.
    const tenantId =
      typeof data.tenantId === "string"
        ? data.tenantId
        : await resolveTenantForEvent(data)
    if (tenantId) {
      io.to(`tenant:${tenantId}`).emit(event.name, data)
      return
    }

    // 4) Events système globaux (updates.*, auth.*, user.*) → broadcast global
    io.emit(event.name, data)
  })

  return io
}

/**
 * Résout le tenant d'un event infra qui ne porte pas tenantId, à
 * partir de son clusterId ou serverId. Renvoie null pour les events réellement
 * système (aucun rattachement tenant).
 */
async function resolveTenantForEvent(data: Record<string, unknown>): Promise<string | null> {
  if (typeof data.clusterId === "string") {
    const cluster = await prisma.cluster.findUnique({
      where: { id: data.clusterId },
      select: { tenantId: true },
    })
    if (cluster?.tenantId) return cluster.tenantId
  }
  if (typeof data.serverId === "string") {
    const server = await prisma.server.findUnique({
      where: { id: data.serverId },
      select: { cluster: { select: { tenantId: true } } },
    })
    if (server?.cluster?.tenantId) return server.cluster.tenantId
  }
  return null
}