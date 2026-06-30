import techniques from './techniques.json';

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  detection_guidance: string;
  mitigation: string;
  external_url: string;
}

const techniqueMap = new Map<string, MitreTechnique>(
  (techniques as MitreTechnique[]).map(t => [t.id, t])
);

export function getTechnique(id: string): MitreTechnique | undefined {
  return techniqueMap.get(id);
}

export function getAllTechniques(): MitreTechnique[] {
  return techniques as MitreTechnique[];
}
