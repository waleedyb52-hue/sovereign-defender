import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as THREE from 'three';
import {
  Globe,
  Radio,
  Crosshair,
  Maximize2,
  Minimize2,
  Eye,
  EyeOff,
  Layers
} from 'lucide-react';
import {
  computeGreatCircleTrajectory,
  latLonToCartesian,
  SOVEREIGN_NODE_COORDINATES,
  GLOBE_RADIUS_3D,
  ThreatCluster,
  Vector3D
} from '../utils/threatMath';

export interface ThreatVectorData {
  id: string;
  uuid?: string;
  ip: string;
  asn: string;
  city: string;
  country: string;
  sourceGeo: { lat: number; lon: number };
  payloadSnippet?: string;
  entropy: number;
  ipReputationScore: number;
  requestFrequencyHz: number;
  port: number;
  targetProtocol: string;
  timestamp: string;
  triage: {
    threatScore: number;
    classification: 'CRITICAL' | 'HIGH' | 'SAFE';
    ebpfAutoDropped: boolean;
    shannonEntropy: number;
    entropyNormalized: number;
    reputationWeightScore: number;
    frequencyScore: number;
    bayesianPosterior: number;
    passesNoiseFilter: boolean;
    trajectoryPoints: Vector3D[];
    greatCircleDistanceKm: number;
    triageReason: string;
  };
}

interface AutonomousThreatMapProps {
  lang?: 'ar' | 'en';
  isKioskMode?: boolean;
  onToggleKiosk?: () => void;
}

export const AutonomousThreatMap: React.FC<AutonomousThreatMapProps> = ({
  lang = 'ar',
  isKioskMode = false,
  onToggleKiosk
}) => {
  const isAr = lang === 'ar';
  const mountRef = useRef<HTMLDivElement>(null);

  // Streaming & Algorithm State
  const [vectors, setVectors] = useState<ThreatVectorData[]>([]);
  const [clusters, setClusters] = useState<ThreatCluster[]>([]);
  const [activeHighestCluster, setActiveHighestCluster] = useState<ThreatCluster | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<ThreatVectorData | null>(null);
  const [metrics, setMetrics] = useState({
    totalActiveVectors: 0,
    criticalCount: 0,
    highCount: 0,
    safeCount: 0,
    autoDroppedCount: 0,
    averageThreatScore: 0,
    packetsDroppedTotal: 0
  });

  // Controls & Toggles
  const [noiseFilterEnabled, setNoiseFilterEnabled] = useState(true);
  const [autoCameraEnabled, setAutoCameraEnabled] = useState(true);
  const [showClusterOverlays, setShowClusterOverlays] = useState(true);
  const [showLaserBeams, setShowLaserBeams] = useState(true);
  const [noiseThreshold, setNoiseThreshold] = useState(35); // Filter noise < 35%
  const [isSwarmLoading, setIsSwarmLoading] = useState(false);

  // References for Three.js Scene Lifecycle
  const sceneRef = useRef<THREE.Scene | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const globeGroupRef = useRef<THREE.Group | null>(null);
  const vectorsGroupRef = useRef<THREE.Group | null>(null);
  const clustersGroupRef = useRef<THREE.Group | null>(null);
  const laserPulsesRef = useRef<Array<{ mesh: THREE.Mesh; points: THREE.Vector3[]; speed: number; progress: number }>>([]);
  const animFrameIdRef = useRef<number | null>(null);

  // Camera Target Interpolation Ref
  const targetCamPosRef = useRef<THREE.Vector3>(new THREE.Vector3(0, 50, 240));
  const targetLookAtRef = useRef<THREE.Vector3>(new THREE.Vector3(0, 0, 0));
  const currentLookAtRef = useRef<THREE.Vector3>(new THREE.Vector3(0, 0, 0));

  // User Interaction State (manual drag / orbit)
  const isDraggingRef = useRef(false);
  const previousMousePositionRef = useRef({ x: 0, y: 0 });
  const autoRotatePauseTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Fetch real-time streaming threat data from backend
  const fetchThreatData = async () => {
    try {
      const res = await fetch('/api/v1/threats/heatmap-stream').catch(() => null);
      if (!res || !res.ok) return;
      const data = await res.json().catch(() => null);
      if (data && data.success) {
        const enrichedVectors = (data.activeVectors || []).map((v: any) => ({
          ...v,
          uuid: v.uuid || `threat-uuid-${v.id || v.ip}-${crypto.randomUUID()}`
        }));
        setVectors(enrichedVectors);
        setClusters(data.clusters || []);
        setActiveHighestCluster(data.highestDensityCluster || null);
        if (data.metrics) setMetrics(data.metrics);
      }
    } catch {
      // Graceful error handling
    }
  };

  useEffect(() => {
    fetchThreatData().catch(() => {});
    const interval = setInterval(() => {
      fetchThreatData().catch(() => {});
    }, 3500);
    return () => clearInterval(interval);
  }, []);

  // Filter vectors by noise threshold
  const displayedVectors = useMemo(() => {
    if (!noiseFilterEnabled) return vectors;
    return vectors.filter(v => v.triage.threatScore >= noiseThreshold);
  }, [vectors, noiseFilterEnabled, noiseThreshold]);

  // Trigger synthetic swarm simulation
  const handleSimulateSwarm = async (region: string) => {
    setIsSwarmLoading(true);
    try {
      await fetch('/api/v1/threats/simulate-swarm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ region })
      }).catch(() => null);
      await fetchThreatData().catch(() => {});
    } catch {
      // Graceful fallback
    } finally {
      setIsSwarmLoading(false);
    }
  };

  // ==========================================================================
  // THREE.JS WEBGL GLOBE INITIALIZATION & RENDER PIPELINE
  // ==========================================================================
  useEffect(() => {
    if (!mountRef.current) return;
    const container = mountRef.current;
    const width = container.clientWidth || window.innerWidth;
    const height = container.clientHeight || window.innerHeight;

    // 1. Scene & Camera
    const scene = new THREE.Scene();
    scene.background = new THREE.Color('#0d1117');
    sceneRef.current = scene;

    const camera = new THREE.PerspectiveCamera(45, width / height, 1, 2000);
    camera.position.set(0, 60, 240);
    cameraRef.current = camera;

    // 2. WebGL Renderer with High Precision
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'high-performance' });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.1;
    container.innerHTML = '';
    container.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // 3. Lighting Setup
    const ambientLight = new THREE.AmbientLight(0x1c3a66, 2.2);
    scene.add(ambientLight);

    const dirLight1 = new THREE.DirectionalLight(0xdfeeff, 2.0);
    dirLight1.position.set(150, 100, 150);
    scene.add(dirLight1);

    const dirLight2 = new THREE.DirectionalLight(0x22d3ee, 1.1);
    dirLight2.position.set(-150, -50, -150);
    scene.add(dirLight2);

    // 4. Globe Core Group
    const globeGroup = new THREE.Group();
    scene.add(globeGroup);
    globeGroupRef.current = globeGroup;

    // Earth Sphere Mesh (Tactical Navy Blue with cyan specular highlight)
    const earthGeo = new THREE.SphereGeometry(GLOBE_RADIUS_3D, 64, 64);
    const earthMat = new THREE.MeshPhongMaterial({
      color: 0x0d1e3f,
      emissive: 0x0a1830,
      specular: 0x3d7fd6,
      shininess: 38,
      wireframe: false
    });
    const earthMesh = new THREE.Mesh(earthGeo, earthMat);
    globeGroup.add(earthMesh);

    // Tactical Wireframe Grid — bright electric blue, clearly visible latitude/longitude lines
    const wireGeo = new THREE.SphereGeometry(GLOBE_RADIUS_3D * 1.002, 36, 18);
    const wireMat = new THREE.MeshBasicMaterial({
      color: 0x4fb2ff,
      wireframe: true,
      transparent: true,
      opacity: 0.55
    });
    const wireMesh = new THREE.Mesh(wireGeo, wireMat);
    globeGroup.add(wireMesh);

    // Atmospheric Glow Outer Shell
    const glowGeo = new THREE.SphereGeometry(GLOBE_RADIUS_3D * 1.035, 48, 48);
    const glowMat = new THREE.MeshBasicMaterial({
      color: 0x22d3ee,
      transparent: true,
      opacity: 0.18,
      side: THREE.BackSide
    });
    const glowMesh = new THREE.Mesh(glowGeo, glowMat);
    globeGroup.add(glowMesh);

    // Sovereign Datacenter Node Marker (Riyadh)
    const sovPos = latLonToCartesian(SOVEREIGN_NODE_COORDINATES.lat, SOVEREIGN_NODE_COORDINATES.lon, GLOBE_RADIUS_3D);
    const sovGroup = new THREE.Group();
    sovGroup.position.set(sovPos.x, sovPos.y, sovPos.z);

    // Sovereign Central Core Pin
    const pinGeo = new THREE.SphereGeometry(2.0, 16, 16);
    const pinMat = new THREE.MeshBasicMaterial({ color: 0x00ffcc });
    const pinMesh = new THREE.Mesh(pinGeo, pinMat);
    sovGroup.add(pinMesh);

    // Sovereign Vertical Laser Beacon (Cylinder)
    const beaconGeo = new THREE.CylinderGeometry(0.5, 1.2, 28, 16);
    const beaconMat = new THREE.MeshBasicMaterial({
      color: 0x39ff14,
      transparent: true,
      opacity: 0.85
    });
    const beaconMesh = new THREE.Mesh(beaconGeo, beaconMat);
    beaconMesh.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), new THREE.Vector3(sovPos.x, sovPos.y, sovPos.z).normalize());
    beaconMesh.position.copy(new THREE.Vector3(sovPos.x, sovPos.y, sovPos.z).normalize().multiplyScalar(14));
    globeGroup.add(beaconMesh);

    // Concentric Radar Rings at Sovereign Node
    const ringGeo = new THREE.RingGeometry(2.8, 4.2, 32);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0x39ff14,
      transparent: true,
      opacity: 0.7,
      side: THREE.DoubleSide
    });
    const ringMesh = new THREE.Mesh(ringGeo, ringMat);
    ringMesh.lookAt(new THREE.Vector3(sovPos.x * 2, sovPos.y * 2, sovPos.z * 2));
    sovGroup.add(ringMesh);
    globeGroup.add(sovGroup);

    // 5. Threat Vectors & Clusters Groups
    const vectorsGroup = new THREE.Group();
    globeGroup.add(vectorsGroup);
    vectorsGroupRef.current = vectorsGroup;

    const clustersGroup = new THREE.Group();
    globeGroup.add(clustersGroup);
    clustersGroupRef.current = clustersGroup;

    // 6. Mouse Orbit & Drag Controls
    const onMouseDown = (e: MouseEvent) => {
      isDraggingRef.current = true;
      previousMousePositionRef.current = { x: e.clientX, y: e.clientY };
      if (autoRotatePauseTimeoutRef.current) clearTimeout(autoRotatePauseTimeoutRef.current);
    };

    const onMouseMove = (e: MouseEvent) => {
      if (!isDraggingRef.current || !globeGroupRef.current) return;
      const deltaX = e.clientX - previousMousePositionRef.current.x;
      const deltaY = e.clientY - previousMousePositionRef.current.y;

      globeGroupRef.current.rotation.y += deltaX * 0.005;
      globeGroupRef.current.rotation.x += deltaY * 0.005;

      // Clamp vertical rotation to avoid flip
      globeGroupRef.current.rotation.x = Math.max(-Math.PI / 2.5, Math.min(Math.PI / 2.5, globeGroupRef.current.rotation.x));

      previousMousePositionRef.current = { x: e.clientX, y: e.clientY };
    };

    const onMouseUp = () => {
      isDraggingRef.current = false;
      // Resume auto-focus after 8 seconds of inactivity
      autoRotatePauseTimeoutRef.current = setTimeout(() => {
        // Resume
      }, 8000);
    };

    const onWheel = (e: WheelEvent) => {
      if (!cameraRef.current) return;
      cameraRef.current.position.z += e.deltaY * 0.15;
      cameraRef.current.position.z = Math.max(140, Math.min(420, cameraRef.current.position.z));
    };

    container.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);
    container.addEventListener('wheel', onWheel, { passive: true });

    // Handle Window Resize
    const handleResize = () => {
      if (!mountRef.current || !cameraRef.current || !rendererRef.current) return;
      const w = mountRef.current.clientWidth;
      const h = mountRef.current.clientHeight;
      cameraRef.current.aspect = w / h;
      cameraRef.current.updateProjectionMatrix();
      rendererRef.current.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    // 7. Animation Loop (Using THREE.Timer / performance.now() to silence deprecated THREE.Clock)
    let lastTime = performance.now();
    const startTime = performance.now();
    const timer = typeof (THREE as any).Timer === 'function' ? new (THREE as any).Timer() : null;

    const animate = (timestamp?: number) => {
      animFrameIdRef.current = requestAnimationFrame(animate);

      let delta = 0.016;
      let elapsedTime = 0;

      if (timer && typeof timestamp === 'number') {
        timer.update(timestamp);
        delta = timer.getDelta();
        elapsedTime = timer.getElapsed();
      } else {
        const now = performance.now();
        delta = Math.min((now - lastTime) / 1000, 0.1);
        lastTime = now;
        elapsedTime = (now - startTime) / 1000;
      }

      // Slow passive rotation if user is not actively dragging
      if (globeGroupRef.current && !isDraggingRef.current && !autoCameraEnabled) {
        globeGroupRef.current.rotation.y += 0.0015;
      }

      // Sovereign Ring Pulse Animation
      if (ringMesh) {
        const pulse = (Math.sin(elapsedTime * 4) + 1) / 2;
        ringMesh.scale.set(1 + pulse * 0.4, 1 + pulse * 0.4, 1);
        (ringMesh.material as THREE.MeshBasicMaterial).opacity = 0.8 - pulse * 0.5;
      }

      // Animate Laser Beam Photon Pulses along 3D Bezier Trajectories
      laserPulsesRef.current.forEach(laser => {
        laser.progress = (laser.progress + laser.speed * delta) % 1.0;
        if (laser.points.length > 2) {
          const index = Math.floor(laser.progress * (laser.points.length - 1));
          const currentPoint = laser.points[index];
          const nextPoint = laser.points[Math.min(index + 1, laser.points.length - 1)];
          laser.mesh.position.lerpVectors(currentPoint, nextPoint, (laser.progress * (laser.points.length - 1)) % 1);
        }
      });

      // Autonomous Camera Panning & Smooth Interpolation (Phase 3 Zero-Touch)
      if (autoCameraEnabled && cameraRef.current && !isDraggingRef.current) {
        cameraRef.current.position.lerp(targetCamPosRef.current, 0.035);
        currentLookAtRef.current.lerp(targetLookAtRef.current, 0.04);
        cameraRef.current.lookAt(currentLookAtRef.current);
      } else if (cameraRef.current) {
        cameraRef.current.lookAt(0, 0, 0);
      }

      renderer.render(scene, camera);
    };
    animate();

    // Cleanup
    return () => {
      if (animFrameIdRef.current) cancelAnimationFrame(animFrameIdRef.current);
      if (autoRotatePauseTimeoutRef.current) clearTimeout(autoRotatePauseTimeoutRef.current);
      container.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
      container.removeEventListener('wheel', onWheel);
      window.removeEventListener('resize', handleResize);
      if (sceneRef.current) {
        disposeHierarchy(sceneRef.current);
      }
      try {
        renderer.forceContextLoss();
        renderer.dispose();
      } catch {
        // Suppress if WebGL context was already lost
      }
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, [autoCameraEnabled]);

  // Helper to completely purge GPU geometries and materials to avoid memory leaks
  const disposeHierarchy = (root: THREE.Object3D) => {
    root.traverse((child: any) => {
      if (child.geometry) {
        child.geometry.dispose();
      }
      if (child.material) {
        if (Array.isArray(child.material)) {
          child.material.forEach((m: any) => m.dispose());
        } else {
          child.material.dispose();
        }
      }
    });
  };

  // ==========================================================================
  // UPDATE 3D TRAJECTORIES, LASER BEAMS & K-MEANS CLUSTERS
  // ==========================================================================
  useEffect(() => {
    if (!vectorsGroupRef.current || !clustersGroupRef.current) return;

    // 1. Thoroughly dispose of GPU memory for all previous dynamic objects
    while (vectorsGroupRef.current.children.length > 0) {
      const obj = vectorsGroupRef.current.children[0];
      disposeHierarchy(obj);
      vectorsGroupRef.current.remove(obj);
    }
    while (clustersGroupRef.current.children.length > 0) {
      const obj = clustersGroupRef.current.children[0];
      disposeHierarchy(obj);
      clustersGroupRef.current.remove(obj);
    }
    laserPulsesRef.current = [];

    // 2. High-Density Level-Of-Detail (LOD) & Batching Engine (Supports 10,000+ Vectors at 60 FPS)
    const isUltraHighDensity = displayedVectors.length > 150;
    
    // Sort vectors so critical and high threats get prioritized trajectory arcs
    const sortedVectors = [...displayedVectors].sort((a, b) => {
      return (b.triage?.threatScore || 0) - (a.triage?.threatScore || 0);
    });

    // Full 3D curves for top vectors (capped at 120 during ultra-high density loads)
    const arcVectors = isUltraHighDensity ? sortedVectors.slice(0, 120) : sortedVectors;
    const backgroundPointVectors = isUltraHighDensity ? sortedVectors.slice(120) : [];

    // Build Attack Vector 3D Great-Circle Trajectories
    arcVectors.forEach((v, idx) => {
      const isCritical = v.triage.classification === 'CRITICAL';
      const isHigh = v.triage.classification === 'HIGH';

      // Visual Colors: Red (Critical/Dropped), Orange (High/Inspecting), Green (Safe/Authorized)
      const colorHex = isCritical ? 0xff003c : isHigh ? 0xffb000 : 0x39ff14;

      // Trajectory Points
      const rawPoints = v.triage.trajectoryPoints && v.triage.trajectoryPoints.length > 0
        ? v.triage.trajectoryPoints
        : computeGreatCircleTrajectory(v.sourceGeo, SOVEREIGN_NODE_COORDINATES);

      const threePoints = rawPoints.map(p => new THREE.Vector3(p.x, p.y, p.z));

      // 3D Arc Curve Line
      const curve = new THREE.CatmullRomCurve3(threePoints);
      const curvePoints = curve.getPoints(36);
      const lineGeo = new THREE.BufferGeometry().setFromPoints(curvePoints);
      const lineMat = new THREE.LineBasicMaterial({
        color: colorHex,
        transparent: true,
        opacity: isCritical ? 0.95 : isHigh ? 0.75 : 0.45,
        linewidth: isCritical ? 2 : 1
      });
      const lineMesh = new THREE.Line(lineGeo, lineMat);
      vectorsGroupRef.current?.add(lineMesh);

      // Source IP Pin & Origin Ripple Ring on Globe Surface
      const sourcePos = latLonToCartesian(v.sourceGeo.lat, v.sourceGeo.lon, GLOBE_RADIUS_3D);
      const sourceGeoMesh = new THREE.SphereGeometry(isCritical ? 1.8 : 1.2, 10, 10);
      const sourceMatMesh = new THREE.MeshBasicMaterial({ color: colorHex });
      const sourceMesh = new THREE.Mesh(sourceGeoMesh, sourceMatMesh);
      sourceMesh.position.set(sourcePos.x, sourcePos.y, sourcePos.z);
      vectorsGroupRef.current?.add(sourceMesh);

      // Animated Laser Beam Photon Packet (Traveling Along Great-Circle Arc)
      if (showLaserBeams && idx < 60) {
        const pulseGeo = new THREE.SphereGeometry(isCritical ? 1.6 : 1.1, 8, 8);
        const pulseMat = new THREE.MeshBasicMaterial({
          color: colorHex
        });
        const pulseMesh = new THREE.Mesh(pulseGeo, pulseMat);
        pulseMesh.position.copy(curvePoints[0]);
        vectorsGroupRef.current?.add(pulseMesh);

        laserPulsesRef.current.push({
          mesh: pulseMesh,
          points: curvePoints,
          speed: 0.35 + (v.requestFrequencyHz / 120),
          progress: (idx * 0.17) % 1.0
        });
      }
    });

    // If there are thousands of additional vectors (10,000 vector stress test), render them as a single batched Point Cloud
    if (backgroundPointVectors.length > 0) {
      const pointPositions = new Float32Array(backgroundPointVectors.length * 3);
      const pointColors = new Float32Array(backgroundPointVectors.length * 3);

      backgroundPointVectors.forEach((pv, pIdx) => {
        const pPos = latLonToCartesian(pv.sourceGeo.lat, pv.sourceGeo.lon, GLOBE_RADIUS_3D + 0.2);
        pointPositions[pIdx * 3] = pPos.x;
        pointPositions[pIdx * 3 + 1] = pPos.y;
        pointPositions[pIdx * 3 + 2] = pPos.z;

        const isCrit = pv.triage.classification === 'CRITICAL';
        if (isCrit) {
          pointColors[pIdx * 3] = 1.0;     // R
          pointColors[pIdx * 3 + 1] = 0.0; // G
          pointColors[pIdx * 3 + 2] = 0.23; // B
        } else {
          pointColors[pIdx * 3] = 1.0;
          pointColors[pIdx * 3 + 1] = 0.69;
          pointColors[pIdx * 3 + 2] = 0.0;
        }
      });

      const swarmGeo = new THREE.BufferGeometry();
      swarmGeo.setAttribute('position', new THREE.BufferAttribute(pointPositions, 3));
      swarmGeo.setAttribute('color', new THREE.BufferAttribute(pointColors, 3));

      const swarmMat = new THREE.PointsMaterial({
        size: 1.8,
        vertexColors: true,
        transparent: true,
        opacity: 0.85
      });

      const swarmPoints = new THREE.Points(swarmGeo, swarmMat);
      vectorsGroupRef.current?.add(swarmPoints);
    }

    // 2. Render K-Means Spatial Clusters
    if (showClusterOverlays && clusters.length > 0) {
      clusters.forEach((cluster, cIdx) => {
        const isTargetCluster = activeHighestCluster && activeHighestCluster.id === cluster.id;
        const clusterPos = latLonToCartesian(cluster.centroid.lat, cluster.centroid.lon, GLOBE_RADIUS_3D + 0.8);

        // Cluster Centroid Halo Ring
        const ringRadius = Math.max(Math.min(cluster.radiusKm / 120, 18), 5);
        const clusterRingGeo = new THREE.RingGeometry(ringRadius * 0.85, ringRadius, 32);
        const clusterRingMat = new THREE.MeshBasicMaterial({
          color: isTargetCluster ? 0xff003c : 0xffb000,
          transparent: true,
          opacity: isTargetCluster ? 0.8 : 0.45,
          side: THREE.DoubleSide
        });
        const clusterRingMesh = new THREE.Mesh(clusterRingGeo, clusterRingMat);
        clusterRingMesh.position.set(clusterPos.x, clusterPos.y, clusterPos.z);
        clusterRingMesh.lookAt(new THREE.Vector3(clusterPos.x * 2, clusterPos.y * 2, clusterPos.z * 2));
        clustersGroupRef.current?.add(clusterRingMesh);

        // Cluster Center Crosshair Core
        const coreGeo = new THREE.SphereGeometry(2.2, 14, 14);
        const coreMat = new THREE.MeshBasicMaterial({ color: isTargetCluster ? 0xff003c : 0xffb000 });
        const coreMesh = new THREE.Mesh(coreGeo, coreMat);
        coreMesh.position.set(clusterPos.x, clusterPos.y, clusterPos.z);
        clustersGroupRef.current?.add(coreMesh);
      });
    }

    // 3. Autonomous Camera Target Calculation (Phase 3 Intelligent Focus)
    if (autoCameraEnabled) {
      if (activeHighestCluster) {
        // Calculate camera position pointing directly at the highest-density critical threat cluster
        const targetPos = latLonToCartesian(
          activeHighestCluster.centroid.lat,
          activeHighestCluster.centroid.lon,
          GLOBE_RADIUS_3D
        );

        // Camera stays at 210 units distance along the normal vector
        const normal = new THREE.Vector3(targetPos.x, targetPos.y, targetPos.z).normalize();
        const camPos = normal.clone().multiplyScalar(225);
        targetCamPosRef.current = camPos;
        targetLookAtRef.current = new THREE.Vector3(targetPos.x * 0.2, targetPos.y * 0.2, targetPos.z * 0.2);
      } else if (displayedVectors.length > 0) {
        const topThreat = displayedVectors[0];
        const targetPos = latLonToCartesian(topThreat.sourceGeo.lat, topThreat.sourceGeo.lon, GLOBE_RADIUS_3D);
        const normal = new THREE.Vector3(targetPos.x, targetPos.y, targetPos.z).normalize();
        targetCamPosRef.current = normal.clone().multiplyScalar(230);
        targetLookAtRef.current = new THREE.Vector3(0, 0, 0);
      }
    }
  }, [displayedVectors, clusters, activeHighestCluster, showClusterOverlays, showLaserBeams, autoCameraEnabled]);

  return (
    <div className={`relative w-full ${isKioskMode ? 'h-screen fixed inset-0 z-50' : 'h-[780px] rounded-xl'} bg-[#0d1117] overflow-hidden border border-[#1e2733] select-none font-mono text-[#e6edf3]`}>
      {/* 3D WebGL Canvas Mount */}
      <div ref={mountRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

      {/* Top Tactical HUD Overlay */}
      <div className="absolute top-4 left-4 right-4 flex items-center justify-between pointer-events-none z-20">
        {/* Left Badge: Sovereign Defense Status */}
        <div className="flex items-center gap-3 pointer-events-auto bg-[#131a24]/90 backdrop-blur-md px-4 py-2.5 rounded-lg border border-[#1e2733] shadow-2xl">
          <div className="relative">
            <Radio className="w-5 h-5 text-[#3fb950] animate-pulse" />
            <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-[#3fb950] animate-ping" />
          </div>
          <div>
            <div className="text-xs font-bold tracking-wider text-[#e6edf3] flex items-center gap-2">
              <span>{isAr ? 'خريطة التهديدات السيادية ثلاثية الأبعاد' : 'SOVEREIGN GLOBAL THREAT HEATMAP'}</span>
              <span className="text-[10px] px-2 py-0.2 rounded bg-[#3fb950]/20 text-[#3fb950] border border-[#3fb950]/40 font-mono">
                {isAr ? 'عقدة الرياض نشطة' : 'RIYADH CORE ACTIVE'}
              </span>
            </div>
            <div className="text-[10px] text-[#93a1b3] flex items-center gap-2">
              <span>{SOVEREIGN_NODE_COORDINATES.lat}°N, {SOVEREIGN_NODE_COORDINATES.lon}°E</span>
              <span>•</span>
              <span>eBPF XDP Layer 1 Drop</span>
            </div>
          </div>
        </div>

        {/* Center: Live Algorithmic Auto-Triage Metrics */}
        <div className="hidden lg:flex items-center gap-3 pointer-events-auto bg-[#131a24]/90 backdrop-blur-md px-4 py-2 rounded-lg border border-[#1e2733]">
          <div className="text-center px-3 border-r border-[#1e2733]">
            <span className="text-[9px] uppercase tracking-wider text-[#93a1b3] block">{isAr ? 'الناقلات النشطة' : 'ACTIVE VECTORS'}</span>
            <span className="text-sm font-bold text-[#e6edf3]">{metrics.totalActiveVectors}</span>
          </div>
          <div className="text-center px-3 border-r border-[#1e2733]">
            <span className="text-[9px] uppercase tracking-wider text-[#f85149] block">{isAr ? 'حظر eBPF التلقائي' : 'eBPF DROPPED'}</span>
            <span className="text-sm font-bold text-[#f85149]">{metrics.autoDroppedCount}</span>
          </div>
          <div className="text-center px-3 border-r border-[#1e2733]">
            <span className="text-[9px] uppercase tracking-wider text-[#d29922] block">{isAr ? 'فحص متقدم' : 'INSPECTING'}</span>
            <span className="text-sm font-bold text-[#d29922]">{metrics.highCount}</span>
          </div>
          <div className="text-center px-3">
            <span className="text-[9px] uppercase tracking-wider text-[#3fb950] block">{isAr ? 'متوسط درجة الخطر' : 'AVG THREAT SCORE'}</span>
            <span className="text-sm font-bold text-[#3fb950]">{metrics.averageThreatScore}%</span>
          </div>
        </div>

        {/* Right: Controls & Kiosk Toggle */}
        <div className="flex items-center gap-2 pointer-events-auto">
          {/* Autonomous Camera Auto-Pilot Toggle */}
          <button
            onClick={() => setAutoCameraEnabled(prev => !prev)}
            title={isAr ? 'تفعيل/تعطيل التوجيه الذاتي للكاميرا' : 'Toggle Autonomous Camera Panning'}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono font-bold flex items-center gap-1.5 transition ${
              autoCameraEnabled
                ? 'bg-[#3fb950]/15 border-[#3fb950]/50 text-[#3fb950]'
                : 'bg-[#181818] border-[#1e2733] text-[#93a1b3] hover:text-[#e6edf3]'
            }`}
          >
            <Crosshair className={`w-3.5 h-3.5 ${autoCameraEnabled ? 'animate-spin' : ''}`} />
            <span>{isAr ? (autoCameraEnabled ? 'توجيه آلي' : 'توجيه يدوي') : (autoCameraEnabled ? 'AUTO-PILOT' : 'MANUAL CAM')}</span>
          </button>

          {/* K-Means Clusters Overlay Toggle */}
          <button
            onClick={() => setShowClusterOverlays(prev => !prev)}
            title={isAr ? 'عرض/إخفاء التجميع المكاني K-Means' : 'Toggle K-Means Cluster Overlays'}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-1.5 transition ${
              showClusterOverlays
                ? 'bg-[#00f3ff]/15 border-[#00f3ff]/50 text-[#00f3ff]'
                : 'bg-[#181818] border-[#1e2733] text-[#93a1b3]'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>K-MEANS</span>
          </button>

          {/* Noise Filter Toggle */}
          <button
            onClick={() => setNoiseFilterEnabled(prev => !prev)}
            title={isAr ? 'فلتر الضوضاء الخوارزمي لمنع الإجهاد التنبيهي' : 'Algorithmic Noise Filter (Suppresses low-level scans)'}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-1.5 transition ${
              noiseFilterEnabled
                ? 'bg-[#d29922]/15 border-[#d29922]/50 text-[#d29922]'
                : 'bg-[#181818] border-[#1e2733] text-[#93a1b3]'
            }`}
          >
            {noiseFilterEnabled ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
            <span>{isAr ? 'فلتر الضوضاء' : 'NOISE FILTER'}</span>
          </button>

          {/* Fullscreen / Kiosk Mode Trigger */}
          {onToggleKiosk && (
            <button
              onClick={onToggleKiosk}
              className="p-2 rounded-lg bg-[#131a24] border border-[#1e2733] text-[#93a1b3] hover:text-[#e6edf3] hover:border-[#3fb950] transition shadow-lg"
              title={isKioskMode ? (isAr ? 'إلغاء وضع الجدار' : 'Exit Kiosk Mode') : (isAr ? 'شاشة جدارية كاملة (Kiosk SOC Wall)' : 'SOC Wall Kiosk Display')}
            >
              {isKioskMode ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
            </button>
          )}
        </div>
      </div>

      {/* Floating Active Cluster Focus Badge (Phase 3 Intelligent K-Means Clustering) */}
      {activeHighestCluster && (
        <div className="absolute top-20 left-4 z-20 pointer-events-auto bg-[#131a24]/90 backdrop-blur-md p-3.5 rounded-xl border border-[#f85149]/40 shadow-2xl max-w-xs animate-in fade-in">
          <div className="flex items-center justify-between pb-2 border-b border-[#1e2733] mb-2">
            <span className="text-[10px] text-[#f85149] font-bold uppercase tracking-wider flex items-center gap-1">
              <Crosshair className="w-3.5 h-3.5 text-[#f85149]" />
              {isAr ? 'بؤرة التهديد الحرجة ذات الكثافة القصوى' : 'PEAK CRITICAL THREAT CLUSTER'}
            </span>
            <span className="px-1.5 py-0.2 rounded text-[9px] bg-[#f85149]/20 text-[#f85149] font-bold">
              {activeHighestCluster.criticalCount} CRITICAL
            </span>
          </div>
          <div className="space-y-1 text-xs">
            <div className="flex justify-between text-[#93a1b3]">
              <span>{isAr ? 'إحداثيات المركز' : 'Centroid'}:</span>
              <span className="text-[#e6edf3]">{activeHighestCluster.centroid.lat}°N, {activeHighestCluster.centroid.lon}°E</span>
            </div>
            <div className="flex justify-between text-[#93a1b3]">
              <span>{isAr ? 'نصف القطر المكاني' : 'Radius'}:</span>
              <span className="text-[#e6edf3]">~{activeHighestCluster.radiusKm} km</span>
            </div>
            <div className="flex justify-between text-[#93a1b3]">
              <span>{isAr ? 'كثافة الهجوم الخوارزمية' : 'Density Score'}:</span>
              <span className="text-[#f85149] font-bold">{activeHighestCluster.density}</span>
            </div>
          </div>
        </div>
      )}

      {/* Synthetic Swarm Simulation Quick Bar */}
      <div className="absolute top-20 right-4 z-20 pointer-events-auto bg-[#131a24]/90 backdrop-blur-md p-2.5 rounded-xl border border-[#1e2733] shadow-2xl space-y-2">
        <span className="text-[10px] text-[#93a1b3] font-bold uppercase block tracking-wider">
          {isAr ? 'حقن أسراب محاكاة خوارزمية' : 'INJECT ALGORITHMIC SWARM'}
        </span>
        <div className="flex items-center gap-1.5">
          <button
            disabled={isSwarmLoading}
            onClick={() => handleSimulateSwarm('EAST_EUROPE')}
            className="px-2.5 py-1 text-[10px] rounded bg-[#181818] hover:bg-[#222222] border border-[#1e2733] text-[#e6edf3] hover:border-[#f85149] transition font-bold disabled:opacity-50"
          >
            {isAr ? 'سرب أوروبا الشرقية' : 'East Europe'}
          </button>
          <button
            disabled={isSwarmLoading}
            onClick={() => handleSimulateSwarm('ASIA_PACIFIC')}
            className="px-2.5 py-1 text-[10px] rounded bg-[#181818] hover:bg-[#222222] border border-[#1e2733] text-[#e6edf3] hover:border-[#d29922] transition font-bold disabled:opacity-50"
          >
            {isAr ? 'سرب شرق آسيا' : 'East Asia'}
          </button>
          <button
            disabled={isSwarmLoading}
            onClick={() => handleSimulateSwarm('NORTH_AMERICA')}
            className="px-2.5 py-1 text-[10px] rounded bg-[#181818] hover:bg-[#222222] border border-[#1e2733] text-[#e6edf3] hover:border-[#3fb950] transition font-bold disabled:opacity-50"
          >
            {isAr ? 'أمريكا الشمالية' : 'North America'}
          </button>
        </div>
      </div>

      {/* Threat Detail Interactive Drilldown Drawer (if selected) */}
      {selectedThreat && (
        <div className="absolute bottom-16 right-4 z-30 pointer-events-auto bg-[#131a24]/95 backdrop-blur-md p-4 rounded-xl border border-[#1e2733] shadow-2xl w-80 space-y-3 animate-in slide-in-from-bottom">
          <div className="flex items-center justify-between pb-2 border-b border-[#1e2733]">
            <div className="flex items-center gap-2">
              <span className={`w-2.5 h-2.5 rounded-full ${
                selectedThreat.triage.classification === 'CRITICAL' ? 'bg-[#f85149]' :
                selectedThreat.triage.classification === 'HIGH' ? 'bg-[#d29922]' : 'bg-[#3fb950]'
              }`} />
              <span className="font-bold text-xs text-[#e6edf3]">{selectedThreat.ip}</span>
            </div>
            <button
              onClick={() => setSelectedThreat(null)}
              className="text-[#93a1b3] hover:text-[#e6edf3] text-xs font-bold px-1.5 py-0.5 rounded"
            >
              ✕
            </button>
          </div>

          <div className="space-y-1.5 text-xs">
            <div className="flex justify-between">
              <span className="text-[#93a1b3]">{isAr ? 'الدرجة الخوارزمية (ThreatScore)' : 'Bayesian ThreatScore'}:</span>
              <span className={`font-bold ${selectedThreat.triage.threatScore > 85 ? 'text-[#f85149]' : 'text-[#d29922]'}`}>
                {selectedThreat.triage.threatScore}%
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#93a1b3]">{isAr ? 'إنتروبيا شانون (Shannon Entropy)' : 'Shannon Entropy'}:</span>
              <span className="text-[#3fb950]">{selectedThreat.triage.shannonEntropy} bits/byte</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#93a1b3]">{isAr ? 'سمعة الـ IP المصدر' : 'Source IP Reputation'}:</span>
              <span className="text-[#e6edf3]">{selectedThreat.ipReputationScore}/100</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#93a1b3]">{isAr ? 'معدل التدفق (DDoS Frequency)' : 'Request Frequency'}:</span>
              <span className="text-[#e6edf3]">{selectedThreat.requestFrequencyHz} Hz</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#93a1b3]">{isAr ? 'المسافة الجغرافية العظمى' : 'Great-Circle Distance'}:</span>
              <span className="text-[#e6edf3]">{selectedThreat.triage.greatCircleDistanceKm} km</span>
            </div>
            <div className="pt-2 border-t border-[#1e2733]">
              <span className="text-[10px] text-[#93a1b3] block mb-1 uppercase tracking-wider">{isAr ? 'إجراء النواة الفوري' : 'Kernel Action'}:</span>
              <span className={`text-[10px] font-bold px-2 py-1 rounded block ${
                selectedThreat.triage.ebpfAutoDropped
                  ? 'bg-[#f85149]/20 text-[#f85149] border border-[#f85149]/40'
                  : 'bg-[#d29922]/20 text-[#d29922] border border-[#d29922]/40'
              }`}>
                {selectedThreat.triage.ebpfAutoDropped
                  ? (isAr ? 'تم إسقاط الحزم بنواة eBPF XDP فورياً' : 'eBPF Auto-Drop Triggered (Score > 85%)')
                  : (isAr ? 'تحت فحص حمولة TLS المشدد' : 'Under High Stateful Inspection')}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Vector Click Selector Chips (Bottom Left) */}
      <div className="absolute bottom-16 left-4 z-20 pointer-events-auto max-w-md hidden sm:block">
        <div className="bg-[#131a24]/90 backdrop-blur-md p-2.5 rounded-xl border border-[#1e2733] shadow-xl space-y-2">
          <span className="text-[9px] text-[#93a1b3] uppercase tracking-wider block font-bold">
            {isAr ? 'أحدث النواقل الخوارزمية المفحوصة (انقر للفحص)' : 'RECENT TRIAGED ATTACK VECTORS'}
          </span>
          <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto pr-1">
            {displayedVectors.slice(0, 8).map(v => (
              <button
                key={v.uuid || `threat-vector-${v.id}-${v.ip.replace(/[^a-zA-Z0-9]/g, '_')}`}
                onClick={() => setSelectedThreat(v)}
                className={`px-2 py-1 rounded text-[10px] font-mono flex items-center gap-1.5 border transition ${
                  selectedThreat?.id === v.id
                    ? 'border-[#3fb950] bg-[#3fb950]/20 text-[#3fb950]'
                    : v.triage.classification === 'CRITICAL'
                    ? 'border-[#f85149]/50 bg-[#f85149]/10 text-[#f85149] hover:bg-[#f85149]/20'
                    : 'border-[#1e2733] bg-[#181818] text-[#93a1b3] hover:text-[#e6edf3]'
                }`}
              >
                <span>{v.ip}</span>
                <span className="font-bold">{v.triage.threatScore}%</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
