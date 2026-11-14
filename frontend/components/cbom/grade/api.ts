// The two model routes the grade and agility components read (the run, asset and posture data come from the queries
// the mounting page already makes). Keys sit under ["cbom-sources", teamId] so invalidating the team prefix refreshes
// them with every other CBOM Sources query.
import { useQuery } from "@tanstack/react-query";

import api from "@/utils/interceptors";

import type { AgilityModel, GradeModel } from "./model";

export const gradeKeys = {
  gradeModel: (teamId: number) => ["cbom-sources", teamId, "grade-model"] as const,
  agilityModel: (teamId: number) => ["cbom-sources", teamId, "agility-model"] as const,
};

/** GET /{team}/cbom/sources/grade-model: the signed qg-1 text, its sha256, the grades and the reason codes. */
export async function getCbomGradeModel(teamId: number): Promise<GradeModel> {
  const response = await api.get(`/${teamId}/cbom/sources/grade-model`);
  return response.data as GradeModel;
}

/** GET /{team}/cbom/sources/agility-model: the fix classes, their order and text, and the rules. */
export async function getCbomAgilityModel(teamId: number): Promise<AgilityModel> {
  const response = await api.get(`/${teamId}/cbom/sources/agility-model`);
  return response.data as AgilityModel;
}

// The models change only with a deploy: one fetch per page view is enough.
const MODEL_STALE_MS = 10 * 60_000;

export function useGradeModel(teamId: number | undefined, enabled = true) {
  return useQuery({
    queryKey: gradeKeys.gradeModel(teamId ?? NaN),
    queryFn: () => getCbomGradeModel(teamId as number),
    enabled: enabled && Number.isFinite(teamId),
    staleTime: MODEL_STALE_MS,
    retry: 1,
  });
}

export function useAgilityModel(teamId: number | undefined, enabled = true) {
  return useQuery({
    queryKey: gradeKeys.agilityModel(teamId ?? NaN),
    queryFn: () => getCbomAgilityModel(teamId as number),
    enabled: enabled && Number.isFinite(teamId),
    staleTime: MODEL_STALE_MS,
    retry: 1,
  });
}
