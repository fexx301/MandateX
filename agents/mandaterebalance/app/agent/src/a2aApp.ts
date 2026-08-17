import type { AgentCard } from "@a2a-js/sdk";
import {
  type A2ARequestHandler,
  type AgentExecutor,
  DefaultRequestHandler,
  InMemoryTaskStore,
} from "@a2a-js/sdk/server";
import {
  agentCardHandler,
  jsonRpcHandler,
  UserBuilder,
} from "@a2a-js/sdk/server/express";
import type { IRouter } from "express";

/** Build the in-memory A2A request handler used by the seller transport. */
export function createA2ARequestHandler(
  agentCard: AgentCard,
  executor: AgentExecutor,
): DefaultRequestHandler {
  return new DefaultRequestHandler(
    agentCard,
    new InMemoryTaskStore(),
    executor,
  );
}

/** Mount the public agent card and root JSON-RPC endpoints. */
export function mountA2ARoutes(
  app: IRouter,
  handler: A2ARequestHandler,
): void {
  app.use(
    "/.well-known/agent-card.json",
    agentCardHandler({ agentCardProvider: handler }),
  );
  app.use(
    jsonRpcHandler({
      requestHandler: handler,
      userBuilder: UserBuilder.noAuthentication,
    }),
  );
}
