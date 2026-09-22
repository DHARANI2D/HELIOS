import type { Detector } from "../types";
import { geoVelocityDetector } from "./geoVelocity";
import { fsmChainDetector } from "./fsmChain";
import { anomalousActionDetector } from "./anomalousAction";
import { threatIntelDetector } from "./threatIntel";
import { reconnaissanceDetector } from "./reconnaissance";
import { credentialHarvestingDetector } from "./credentialHarvesting";
import { lateralMovementDetector } from "./lateralMovement";
import { dataExfiltrationDetector } from "./dataExfiltration";
import { persistenceDetector } from "./persistence";
import { defenseEvasionDetector } from "./defenseEvasion";
import { impactDetector } from "./impact";

export const DETECTORS: Detector[] = [
  geoVelocityDetector,
  fsmChainDetector,
  anomalousActionDetector,
  threatIntelDetector,
  reconnaissanceDetector,
  credentialHarvestingDetector,
  lateralMovementDetector,
  dataExfiltrationDetector,
  persistenceDetector,
  defenseEvasionDetector,
  impactDetector,
];
