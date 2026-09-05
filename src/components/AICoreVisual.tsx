import React, { useEffect, useRef } from 'react';

export const AICoreVisual: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const mouseRef = useRef({ x: 0, y: 0, targetX: 0, targetY: 0 });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    canvas.width = canvas.offsetWidth * window.devicePixelRatio;
    canvas.height = canvas.offsetHeight * window.devicePixelRatio;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

    const handleResize = () => {
      if (!canvas) return;
      canvas.width = canvas.offsetWidth * window.devicePixelRatio;
      canvas.height = canvas.offsetHeight * window.devicePixelRatio;
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    };

    window.addEventListener('resize', handleResize);

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Node definitions for autonomous topology
    const nodeCount = 14;
    const nodes: {
      angle: number;
      distance: number;
      speed: number;
      size: number;
      label: string;
      pulse: number;
    }[] = [];

    const labels = [
      'POLICY_GUARD',
      'TOPOLOGY_GRAPH',
      'NEURAL_SYNTH',
      'SCOPE_VALIDATOR',
      'TELEMETRY_LOG',
      'VECTOR_INDEX',
      'FINDING_RESOLVER',
    ];

    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        angle: (i / nodeCount) * Math.PI * 2,
        distance: 70 + (i % 3) * 45,
        speed: (0.0008 + (i % 4) * 0.0004) * (i % 2 === 0 ? 1 : -1),
        size: 3 + (i % 3) * 1.5,
        label: labels[i % labels.length],
        pulse: Math.random() * Math.PI * 2,
      });
    }

    let angleRing1 = 0;
    let angleRing2 = 0;
    let angleRing3 = 0;

    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left - rect.width / 2;
      const y = e.clientY - rect.top - rect.height / 2;
      mouseRef.current.targetX = x * 0.05;
      mouseRef.current.targetY = y * 0.05;
    };

    window.addEventListener('mousemove', handleMouseMove, { passive: true });

    const render = () => {
      const logicalWidth = canvas.offsetWidth;
      const logicalHeight = canvas.offsetHeight;
      const centerX = logicalWidth / 2 + mouseRef.current.x;
      const centerY = logicalHeight / 2 + mouseRef.current.y;

      // Mouse smoothing
      mouseRef.current.x += (mouseRef.current.targetX - mouseRef.current.x) * 0.08;
      mouseRef.current.y += (mouseRef.current.targetY - mouseRef.current.y) * 0.08;

      ctx.clearRect(0, 0, logicalWidth, logicalHeight);

      // 1. Subtle Outer Cyber Shield (Hexagonal Boundary)
      const hexRadius = Math.min(logicalWidth, logicalHeight) * 0.44;
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const a = (i * Math.PI) / 3 + (angleRing1 * 0.2);
        const hx = centerX + hexRadius * Math.cos(a);
        const hy = centerY + hexRadius * Math.sin(a);
        if (i === 0) ctx.moveTo(hx, hy);
        else ctx.lineTo(hx, hy);
      }
      ctx.closePath();
      ctx.strokeStyle = 'rgba(0, 102, 255, 0.15)';
      ctx.lineWidth = 1;
      ctx.stroke();

      // 2. Concentric Scanning Rings
      // Ring 1
      ctx.beginPath();
      ctx.arc(centerX, centerY, hexRadius * 0.78, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.06)';
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 8]);
      ctx.stroke();

      // Ring 2 (Segmented)
      ctx.save();
      ctx.translate(centerX, centerY);
      ctx.rotate(angleRing2);
      ctx.beginPath();
      ctx.arc(0, 0, hexRadius * 0.55, 0, Math.PI * 1.4);
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.22)';
      ctx.lineWidth = 1.5;
      ctx.setLineDash([12, 16]);
      ctx.stroke();
      ctx.restore();

      // Ring 3 (Opposite Rotation)
      ctx.save();
      ctx.translate(centerX, centerY);
      ctx.rotate(-angleRing3);
      ctx.beginPath();
      ctx.arc(0, 0, hexRadius * 0.35, 0, Math.PI * 1.8);
      ctx.strokeStyle = 'rgba(0, 102, 255, 0.3)';
      ctx.lineWidth = 1.2;
      ctx.setLineDash([6, 10]);
      ctx.stroke();
      ctx.restore();

      ctx.setLineDash([]); // reset

      // 3. Central Autonomous AI Core
      // Outer glow circle
      const coreGrad = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, 48);
      coreGrad.addColorStop(0, 'rgba(0, 240, 255, 0.35)');
      coreGrad.addColorStop(0.4, 'rgba(0, 102, 255, 0.2)');
      coreGrad.addColorStop(1, 'rgba(2, 5, 10, 0)');

      ctx.fillStyle = coreGrad;
      ctx.beginPath();
      ctx.arc(centerX, centerY, 48, 0, Math.PI * 2);
      ctx.fill();

      // Central core node
      ctx.beginPath();
      ctx.arc(centerX, centerY, 12, 0, Math.PI * 2);
      ctx.fillStyle = '#07101A';
      ctx.fill();
      ctx.strokeStyle = '#00F0FF';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(centerX, centerY, 5, 0, Math.PI * 2);
      ctx.fillStyle = '#FFFFFF';
      ctx.fill();

      // 4. Autonomous Topology Nodes & Conduit Vectors
      const activePositions: { x: number; y: number; label: string }[] = [];

      nodes.forEach((node) => {
        if (!prefersReducedMotion) {
          node.angle += node.speed;
          node.pulse += 0.03;
        }

        const nx = centerX + Math.cos(node.angle) * node.distance;
        const ny = centerY + Math.sin(node.angle) * (node.distance * 0.85);
        activePositions.push({ x: nx, y: ny, label: node.label });

        // Conduit line back to core
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(nx, ny);
        ctx.strokeStyle = 'rgba(0, 102, 255, 0.08)';
        ctx.lineWidth = 0.8;
        ctx.stroke();

        // Node dot
        const currentSize = node.size + Math.sin(node.pulse) * 0.8;
        ctx.beginPath();
        ctx.arc(nx, ny, Math.max(2, currentSize), 0, Math.PI * 2);
        ctx.fillStyle = '#00F0FF';
        ctx.fill();

        // Node glow
        ctx.beginPath();
        ctx.arc(nx, ny, Math.max(4, currentSize * 2.2), 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0, 102, 255, 0.15)';
        ctx.fill();
      });

      // Interconnect closest nodes with telemetry vectors
      for (let i = 0; i < activePositions.length; i++) {
        for (let j = i + 1; j < activePositions.length; j++) {
          const dx = activePositions[i].x - activePositions[j].x;
          const dy = activePositions[i].y - activePositions[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 75) {
            ctx.beginPath();
            ctx.moveTo(activePositions[i].x, activePositions[i].y);
            ctx.lineTo(activePositions[j].x, activePositions[j].y);
            ctx.strokeStyle = `rgba(0, 240, 255, ${0.18 - dist / 75 * 0.15})`;
            ctx.lineWidth = 0.75;
            ctx.stroke();
          }
        }
      }

      // Increment rotation angles
      if (!prefersReducedMotion) {
        angleRing1 += 0.002;
        angleRing2 += 0.0035;
        angleRing3 += 0.0025;
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
    };
  }, []);

  return (
    <div className="relative w-full aspect-square max-w-[480px] lg:max-w-[540px] mx-auto flex items-center justify-center select-none">
      {/* Background radial ambient glow */}
      <div className="absolute inset-0 bg-radial-gradient opacity-80 pointer-events-none" />

      {/* Cyber radar canvas */}
      <canvas
        ref={canvasRef}
        className="relative z-10 w-full h-full block"
        style={{ width: '100%', height: '100%' }}
        aria-label="Abstract Autonomous AI Security Core Visualization"
      />

      {/* Tech Overlay Readouts */}
      <div className="absolute top-4 left-4 z-20 pointer-events-none hidden sm:flex flex-col gap-1 font-mono text-[10px] text-text-muted">
        <div className="flex items-center gap-1.5 text-text-secondary">
          <span className="w-1.5 h-1.5 rounded-full bg-electric-blue animate-pulse"></span>
          <span>AUTONOMOUS_CORE // IDLE</span>
        </div>
        <span>ARCH: DETERMINISTIC_REASONER</span>
      </div>

      <div className="absolute bottom-4 right-4 z-20 pointer-events-none hidden sm:flex flex-col items-end gap-1 font-mono text-[10px] text-text-muted">
        <div className="text-subtle-cyan/80">GUARDRAIL_LEVEL: STRICT</div>
        <span>PREVIEW // CONCEPTUAL_TOPOLOGY</span>
      </div>
    </div>
  );
};
