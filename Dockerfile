# syntax=docker/dockerfile:1

# ── build stage: compile TypeScript ─────────────────────────
FROM node:22-slim AS build
WORKDIR /app
RUN corepack enable
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.base.json ./
COPY packages/core/package.json packages/core/
COPY packages/mcp-stdio/package.json packages/mcp-stdio/
RUN pnpm install --frozen-lockfile
COPY packages/core packages/core
COPY packages/mcp-stdio packages/mcp-stdio
RUN pnpm build
# Standalone prod install of just the MCP server (converts workspace:* deps).
RUN pnpm --filter flotilla-mcp deploy --legacy --prod /prod

# ── runtime stage: minimal, non-root ────────────────────────
FROM node:22-slim
ENV NODE_ENV=production
# Bind-mounted config dirs are created by the container runtime (0755);
# the config FILE mode is still enforced.
ENV FLOTILLA_IN_DOCKER=1
WORKDIR /app
COPY --from=build /prod ./
USER node
# Mount your config read-only and pass credentials via env:
#   docker run -i --rm \
#     -v ~/.config/flotilla/config.toml:/home/node/.config/flotilla/config.toml:ro \
#     -v ~/.ssh:/home/node/.ssh:ro \
#     -e SSH_AUTH_SOCK -v $SSH_AUTH_SOCK:/ssh-agent -e SSH_AUTH_SOCK=/ssh-agent \
#     flotilla-mcp
ENTRYPOINT ["node", "/app/dist/index.js"]
