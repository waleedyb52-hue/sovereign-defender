/**
 * Sovereign Defender - Threat Mathematics & Algorithmic Triage Engine
 * Includes:
 * 1. Haversine Formula & 3D Great-Circle Trajectory Calculation
 * 2. Shannon Entropy of Payloads (H(X))
 * 3. Bayesian Threat Scoring & Weighted Risk Matrix (IP Rep + Entropy + Frequency)
 * 4. K-Means Spatial Threat Clustering for Autonomous Camera Targeting
 */

export interface GeoCoordinate {
  lat: number;
  lon: number;
  alt?: number;
}

export interface Vector3D {
  x: number;
  y: number;
  z: number;
}

export interface ThreatTriageInput {
  ip: string;
  asn?: string;
  country?: string;
  sourceGeo: GeoCoordinate;
  payload?: string | Uint8Array;
  entropy?: number;
  ipReputationScore: number; // 0 - 100 (100 = known malicious C2/bulletproof host)
  requestFrequencyHz: number; // requests per second or burst ratio
  historicBlockCount?: number;
  isTorOrProxy?: boolean;
}

export type ThreatClassification = 'CRITICAL' | 'HIGH' | 'SAFE';

export interface ThreatTriageResult {
  threatScore: number; // 0 - 100%
  classification: ThreatClassification;
  ebpfAutoDropped: boolean;
  shannonEntropy: number; // 0.0 - 8.0 bits/byte
  entropyNormalized: number; // 0.0 - 1.0
  reputationWeightScore: number;
  frequencyScore: number;
  bayesianPosterior: number;
  passesNoiseFilter: boolean;
  trajectoryPoints: Vector3D[];
  greatCircleDistanceKm: number;
  triageReason: string;
}

export interface ThreatCluster {
  id: string;
  centroid: GeoCoordinate;
  centroidVector: Vector3D;
  radiusKm: number;
  threatCount: number;
  criticalCount: number;
  density: number; // criticalCount / (radiusKm + 1)
  assignedThreats: string[]; // threat IDs
}

// Fixed Sovereign Datacenter Node (Primary Riyadh Defense Core)
export const SOVEREIGN_NODE_COORDINATES: GeoCoordinate = {
  lat: 24.7136,
  lon: 46.6753,
  alt: 0.0
};

// Earth Radius in Kilometers
export const EARTH_RADIUS_KM = 6371.0;

// Globe 3D Unit Radius
export const GLOBE_RADIUS_3D = 100.0;

// ============================================================================
// 1. HAVERSINE FORMULA & 3D GREAT-CIRCLE TRAJECTORY
// ============================================================================

/**
 * Calculates Great-Circle Distance between two coordinates using the Haversine formula
 */
export function calculateHaversineDistanceKm(coord1: GeoCoordinate, coord2: GeoCoordinate): number {
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(coord2.lat - coord1.lat);
  const dLon = toRad(coord2.lon - coord1.lon);

  const lat1Rad = toRad(coord1.lat);
  const lat2Rad = toRad(coord2.lat);

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1Rad) * Math.cos(lat2Rad) * Math.sin(dLon / 2) * Math.sin(dLon / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return EARTH_RADIUS_KM * c;
}

/**
 * Converts spherical Lat/Lon/Altitude to 3D Cartesian coordinates (Three.js coordinate space)
 */
export function latLonToCartesian(
  lat: number,
  lon: number,
  radius: number = GLOBE_RADIUS_3D,
  altitudeOffset: number = 0
): Vector3D {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  const r = radius + altitudeOffset;

  return {
    x: -(r * Math.sin(phi) * Math.cos(theta)),
    y: r * Math.cos(phi),
    z: r * Math.sin(phi) * Math.sin(theta)
  };
}

/**
 * Generates Great-Circle Arc with parabolic 3D altitude bezier curve
 * Used to render attack vector laser beams originating from global IPs to the Sovereign Node
 */
export function computeGreatCircleTrajectory(
  origin: GeoCoordinate,
  destination: GeoCoordinate = SOVEREIGN_NODE_COORDINATES,
  steps: number = 48,
  maxAltitudeFraction: number = 0.32
): Vector3D[] {
  const points: Vector3D[] = [];
  const distKm = calculateHaversineDistanceKm(origin, destination);

  // Normalized distance ratio determines maximum parabolic arc height
  const normalizedDist = Math.min(distKm / (Math.PI * EARTH_RADIUS_KM), 1.0);
  const peakAltitude = GLOBE_RADIUS_3D * maxAltitudeFraction * Math.max(normalizedDist, 0.18);

  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const toDeg = (rad: number) => (rad * 180) / Math.PI;

  const lat1 = toRad(origin.lat);
  const lon1 = toRad(origin.lon);
  const lat2 = toRad(destination.lat);
  const lon2 = toRad(destination.lon);

  // Angular distance between points
  const d =
    2 *
    Math.asin(
      Math.sqrt(
        Math.pow(Math.sin((lat1 - lat2) / 2), 2) +
          Math.cos(lat1) * Math.cos(lat2) * Math.pow(Math.sin((lon1 - lon2) / 2), 2)
      )
    );

  // If points are identical, return single coordinate
  if (d < 1e-6) {
    return [latLonToCartesian(origin.lat, origin.lon, GLOBE_RADIUS_3D)];
  }

  for (let i = 0; i <= steps; i++) {
    const f = i / steps; // Interpolation factor [0, 1]

    // Spherical linear interpolation (slerp formula for great-circle path)
    const A = Math.sin((1 - f) * d) / Math.sin(d);
    const B = Math.sin(f * d) / Math.sin(d);

    const x = A * Math.cos(lat1) * Math.cos(lon1) + B * Math.cos(lat2) * Math.cos(lon2);
    const y = A * Math.cos(lat1) * Math.sin(lon1) + B * Math.cos(lat2) * Math.sin(lon2);
    const z = A * Math.sin(lat1) + B * Math.sin(lat2);

    const currentLat = toDeg(Math.atan2(z, Math.sqrt(x * x + y * y)));
    const currentLon = toDeg(Math.atan2(y, x));

    // Parabolic altitude arc: peaks at f = 0.5 (sin(f * PI))
    const currentAlt = Math.sin(f * Math.PI) * peakAltitude;

    points.push(latLonToCartesian(currentLat, currentLon, GLOBE_RADIUS_3D, currentAlt));
  }

  return points;
}

// ============================================================================
// 2. SHANNON ENTROPY CALCULATION (H(X))
// ============================================================================

/**
 * Calculates Shannon Entropy H(X) = -sum(P(x) * log2(P(x))) in bits per byte
 * Theoretical range: 0.0 (uniform string) to 8.0 (completely encrypted / random binary payload)
 */
export function calculateShannonEntropy(payload: string | Uint8Array | undefined): number {
  if (!payload || payload.length === 0) {
    return 0.0;
  }

  let bytes: Uint8Array;
  if (typeof payload === 'string') {
    const encoder = new TextEncoder();
    bytes = encoder.encode(payload);
  } else {
    bytes = payload;
  }

  if (bytes.length === 0) return 0.0;

  // Byte frequency distribution table (256 possible byte values)
  const frequencies = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) {
    frequencies[bytes[i]]++;
  }

  const len = bytes.length;
  let entropy = 0.0;

  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / len;
      entropy -= p * Math.log2(p);
    }
  }

  return Math.min(Math.max(entropy, 0.0), 8.0);
}

// ============================================================================
// 3. BAYESIAN THREAT SCORING & WEIGHTED RISK MATRIX
// ============================================================================

/**
 * Computes Dynamic Bayesian ThreatScore combining:
 * 1. Source IP Reputation (Historical IoC, Malicious ASN, Tor Node)
 * 2. Payload Shannon Entropy (High entropy indicates encrypted webshells/packed shellcode)
 * 3. Request Frequency / Burst Rate (DDoS & volumetric indicator)
 *
 * Logic Enforcement:
 * IF ThreatScore > 85% THEN trigger eBPF Auto-Drop AND classify as CRITICAL
 */
export function computeBayesianThreatScore(input: ThreatTriageInput): ThreatTriageResult {
  // 1. Calculate or use provided Shannon Entropy
  const entropy =
    input.entropy !== undefined ? input.entropy : calculateShannonEntropy(input.payload);

  // Normalized entropy: 0 to 1 (entropy > 6.8 bits is heavily weighted towards malicious)
  const normalizedEntropy = Math.min(Math.max((entropy - 3.2) / 4.8, 0.0), 1.0);

  // 2. Normalize IP Reputation Score (0 to 100) -> [0.0, 1.0]
  let repScore = input.ipReputationScore / 100;
  if (input.isTorOrProxy) repScore = Math.min(repScore + 0.25, 1.0);
  if ((input.historicBlockCount || 0) > 3) repScore = Math.min(repScore + 0.2, 1.0);

  // 3. Request Frequency (DDoS Indicator)
  // Baseline acceptable web request is 1-15 Hz. Above 60 Hz indicates volumetric attack
  const freqScore = Math.min(Math.max((input.requestFrequencyHz - 5) / 75, 0.0), 1.0);

  // 4. Weighted Risk Matrix
  // Weights: IP Reputation (35%), Shannon Entropy (35%), Request Frequency (30%)
  const wRep = 0.35;
  const wEntropy = 0.35;
  const wFreq = 0.3;
  const rawWeightedScore = repScore * wRep + normalizedEntropy * wEntropy + freqScore * wFreq;

  // 5. Bayesian Posterior Probability Formulation
  // Prior Probability P(Malicious) = 0.12 (standard SOC operational baseline)
  const prior = 0.12;

  // Likelihood of observing evidence given Malicious vs Benign
  // Sigmoid transfer function applied to raw weighted score
  const likelihoodMalicious = 1 / (1 + Math.exp(-6 * (rawWeightedScore - 0.45)));
  const likelihoodBenign = 1 - likelihoodMalicious;

  // Bayes Theorem: P(M|E) = (P(E|M) * P(M)) / (P(E|M) * P(M) + P(E|B) * P(B))
  const numerator = likelihoodMalicious * prior;
  const denominator = numerator + likelihoodBenign * (1 - prior);
  const bayesianPosterior = Math.min(Math.max(numerator / (denominator || 0.0001), 0.0), 1.0);

  // Final ThreatScore expressed as percentage [0, 100]
  const threatScore = Math.round(bayesianPosterior * 1000) / 10;

  // Operational Hard Rule:
  // IF ThreatScore > 85% THEN trigger eBPF Auto-Drop AND classify as CRITICAL
  const ebpfAutoDropped = threatScore > 85.0;
  let classification: ThreatClassification = 'SAFE';

  if (threatScore > 85.0) {
    classification = 'CRITICAL';
  } else if (threatScore >= 50.0) {
    classification = 'HIGH';
  } else {
    classification = 'SAFE';
  }

  // Algorithmic Noise Filter: filter out low-level noise (< 35%) to eliminate alert fatigue
  const passesNoiseFilter = threatScore >= 35.0;

  // Compute 3D Great-Circle Trajectory to Sovereign Datacenter
  const trajectoryPoints = computeGreatCircleTrajectory(
    input.sourceGeo,
    SOVEREIGN_NODE_COORDINATES
  );
  const greatCircleDistanceKm = Math.round(
    calculateHaversineDistanceKm(input.sourceGeo, SOVEREIGN_NODE_COORDINATES)
  );

  let triageReason = '';
  if (ebpfAutoDropped) {
    triageReason = `[AUTONOMOUS eBPF DROP] ThreatScore ${threatScore}% > 85.0% threshold. Entropy: ${entropy.toFixed(2)}b, Rep: ${input.ipReputationScore}/100, Rate: ${input.requestFrequencyHz}Hz. Immediate kernel XDP drop rule applied.`;
  } else if (classification === 'HIGH') {
    triageReason = `[DEEP INSPECT] ThreatScore ${threatScore}%. Elevated entropy (${entropy.toFixed(2)}b) and suspicious origin. Stateful TLS inspection active.`;
  } else {
    triageReason = `[AUTHORIZED] ThreatScore ${threatScore}%. Normal telemetry profile within baseline bounds.`;
  }

  return {
    threatScore,
    classification,
    ebpfAutoDropped,
    shannonEntropy: Math.round(entropy * 100) / 100,
    entropyNormalized: Math.round(normalizedEntropy * 100) / 100,
    reputationWeightScore: Math.round(repScore * 100),
    frequencyScore: Math.round(freqScore * 100),
    bayesianPosterior: Math.round(bayesianPosterior * 1000) / 1000,
    passesNoiseFilter,
    trajectoryPoints,
    greatCircleDistanceKm,
    triageReason
  };
}

// ============================================================================
// 4. K-MEANS SPATIAL THREAT CLUSTERING (Spherical Coordinate Space)
// ============================================================================

export interface ClusterableThreat {
  id: string;
  lat: number;
  lon: number;
  ip: string;
  country?: string;
  threatScore: number;
  classification: ThreatClassification;
}

/**
 * Converts Lat/Lon to 3D Cartesian Unit Vector on sphere for spherical K-Means
 */
function coordToUnitVector(lat: number, lon: number): Vector3D {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  return {
    x: -(Math.sin(phi) * Math.cos(theta)),
    y: Math.cos(phi),
    z: Math.sin(phi) * Math.sin(theta)
  };
}

function unitVectorToCoord(v: Vector3D): GeoCoordinate {
  const norm = Math.sqrt(v.x * v.x + v.y * v.y + v.z * v.z) || 1.0;
  const nx = v.x / norm;
  const ny = v.y / norm;
  const nz = v.z / norm;

  const lat = 90 - (Math.acos(Math.max(Math.min(ny, 1.0), -1.0)) * 180) / Math.PI;
  const lon = (Math.atan2(nz, -nx) * 180) / Math.PI - 180;

  return {
    lat: Math.round(lat * 10000) / 10000,
    lon: Math.round(lon * 10000) / 10000
  };
}

/**
 * Spherical K-Means Clustering for active threat vectors
 * Identifies high-density threat hot spots and computes camera lookAt vector
 */
export function runKMeansThreatClustering(
  threats: ClusterableThreat[],
  k: number = 3,
  maxIterations: number = 10
): {
  clusters: ThreatCluster[];
  highestDensityCluster: ThreatCluster | null;
} {
  if (!threats || threats.length === 0) {
    return { clusters: [], highestDensityCluster: null };
  }

  const effectiveK = Math.min(k, threats.length);

  // Initialize centroids using K-Means++ style selection
  const centroids: Vector3D[] = [];
  centroids.push(coordToUnitVector(threats[0].lat, threats[0].lon));

  while (centroids.length < effectiveK) {
    let maxDist = -1;
    let bestCandidate = threats[0];

    for (const t of threats) {
      const tv = coordToUnitVector(t.lat, t.lon);
      let minDistToAnyCentroid = Infinity;

      for (const c of centroids) {
        // Euclidean distance in 3D unit space equates monotonically to spherical angular distance
        const dx = tv.x - c.x;
        const dy = tv.y - c.y;
        const dz = tv.z - c.z;
        const dist = dx * dx + dy * dy + dz * dz;
        if (dist < minDistToAnyCentroid) minDistToAnyCentroid = dist;
      }

      if (minDistToAnyCentroid > maxDist) {
        maxDist = minDistToAnyCentroid;
        bestCandidate = t;
      }
    }

    centroids.push(coordToUnitVector(bestCandidate.lat, bestCandidate.lon));
  }

  // Iterative assignment & update
  let assignments = new Int32Array(threats.length);

  for (let iter = 0; iter < maxIterations; iter++) {
    let changed = false;

    // Assignment Step
    for (let i = 0; i < threats.length; i++) {
      const tv = coordToUnitVector(threats[i].lat, threats[i].lon);
      let closestIdx = 0;
      let minD = Infinity;

      for (let j = 0; j < centroids.length; j++) {
        const c = centroids[j];
        const dx = tv.x - c.x;
        const dy = tv.y - c.y;
        const dz = tv.z - c.z;
        const dist = dx * dx + dy * dy + dz * dz;
        if (dist < minD) {
          minD = dist;
          closestIdx = j;
        }
      }

      if (assignments[i] !== closestIdx) {
        assignments[i] = closestIdx;
        changed = true;
      }
    }

    if (!changed && iter > 0) break;

    // Update Step (calculate new centroid as average unit vector)
    for (let j = 0; j < centroids.length; j++) {
      let sumX = 0,
        sumY = 0,
        sumZ = 0,
        count = 0;

      for (let i = 0; i < threats.length; i++) {
        if (assignments[i] === j) {
          const tv = coordToUnitVector(threats[i].lat, threats[i].lon);
          sumX += tv.x;
          sumY += tv.y;
          sumZ += tv.z;
          count++;
        }
      }

      if (count > 0) {
        const norm = Math.sqrt(sumX * sumX + sumY * sumY + sumZ * sumZ) || 1.0;
        centroids[j] = { x: sumX / norm, y: sumY / norm, z: sumZ / norm };
      }
    }
  }

  // Build cluster results
  const clusters: ThreatCluster[] = centroids.map((cVector, idx) => {
    const geo = unitVectorToCoord(cVector);
    const assignedThreats: string[] = [];
    let criticalCount = 0;
    let maxDistFromCentroid = 0;

    for (let i = 0; i < threats.length; i++) {
      if (assignments[i] === idx) {
        assignedThreats.push(threats[i].id);
        if (threats[i].classification === 'CRITICAL') {
          criticalCount++;
        }
        const dist = calculateHaversineDistanceKm(geo, {
          lat: threats[i].lat,
          lon: threats[i].lon
        });
        if (dist > maxDistFromCentroid) maxDistFromCentroid = dist;
      }
    }

    const threatCount = assignedThreats.length;
    // Density calculation: higher critical count in smaller radius = highest density
    const density =
      (criticalCount * 2.5 + threatCount) / (Math.max(maxDistFromCentroid, 150) / 100);

    return {
      id: `cluster-${idx + 1}`,
      centroid: geo,
      centroidVector: latLonToCartesian(geo.lat, geo.lon, GLOBE_RADIUS_3D),
      radiusKm: Math.round(maxDistFromCentroid || 300),
      threatCount,
      criticalCount,
      density: Math.round(density * 10) / 10,
      assignedThreats
    };
  });

  // Filter out empty clusters and sort by density descending
  const activeClusters = clusters.filter(c => c.threatCount > 0);
  activeClusters.sort((a, b) => b.density - a.density);

  const highestDensityCluster = activeClusters.length > 0 ? activeClusters[0] : null;

  return {
    clusters: activeClusters,
    highestDensityCluster
  };
}
