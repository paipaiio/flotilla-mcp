import { z } from "zod";
import type { Strategy } from "flotilla-core";

export const strategySchema = z
  .union([
    z.enum(["parallel", "serial", "rolling"]),
    z.object({
      kind: z.literal("rolling"),
      batchSize: z.number().int().positive().optional(),
      maxBatchFailures: z.number().int().min(0).optional(),
    }),
    z.object({ kind: z.literal("serial"), stopOnError: z.boolean().optional() }),
    z.object({ kind: z.literal("parallel"), concurrency: z.number().int().positive().optional() }),
  ])
  .optional();

export function parseStrategy(raw: z.infer<typeof strategySchema>, fallback: Strategy): Strategy {
  if (!raw) return fallback;
  if (typeof raw === "string") return { kind: raw } as Strategy;
  return raw as Strategy;
}
