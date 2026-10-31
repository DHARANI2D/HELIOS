// Cloud regions by jurisdiction, so a rule written as "india" or "eu" holds
// for a provider that names its region the way its cloud does (AWS
// ap-south-1, Azure centralindia, Google asia-south1). Pure.

const FAMILIES: Record<string, RegExp> = {
  india: /^(ap-south-[12]|asia-south[12]|(central|south|west)india|jioindia(west|central)|in|india|in-[a-z0-9-]+)$/i,
  eu: /^(eu|europe|eu-[a-z0-9-]+|europe-[a-z0-9-]+|(north|west)europe|francecentral|francesouth|germany(west|north)central|swedencentral|swedensouth|italynorth|polandcentral|spaincentral|austriaeast|belgiumcentral|denmarkeast|finlandcentral|greececentral|irelandcentral|norwaywest|norwayeast|switzerland(north|west))$/i,
  us: /^(us|usa|us-[a-z0-9-]+|(east|west|central|north ?central|south ?central|west ?central)us[0-9]?)$/i,
};

export const inIndia = (region: string | null | undefined) => !!region && FAMILIES.india.test(region.trim());

// Does a provider's region satisfy a region a client's rule names? The same
// name, or a cloud region inside the jurisdiction the rule names.
export function regionSatisfies(providerRegion: string | null | undefined, ruleRegion: string) {
  if (!providerRegion) return false;
  const p = providerRegion.trim().toLowerCase();
  const r = ruleRegion.trim().toLowerCase();
  if (p === r) return true;
  const family = r === "in" ? "india" : r === "europe" ? "eu" : r === "usa" ? "us" : r;
  return !!FAMILIES[family]?.test(p);
}
