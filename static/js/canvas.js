// Detecto - Immersive Scroll-Based Canvas Visual Engine
// Lightweight pure HTML5 Canvas particle system with smooth state interpolation

(function () {
  const canvas = document.getElementById("bgCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  const PARTICLE_COUNT = Math.min(85, Math.floor(window.innerWidth / 16));
  const particles = [];

  // Color definitions (Clean Minimal Light Palette)
  const COLOR_NEUTRAL = { r: 148, g: 163, b: 184, a: 0.45 }; // Slate 400
  const COLOR_SAFE = { r: 5, g: 150, b: 105, a: 0.75 };      // Emerald 600
  const COLOR_DANGER = { r: 220, g: 38, b: 38, a: 0.75 };    // Red 600
  const COLOR_BLUE = { r: 37, g: 99, b: 235, a: 0.65 };      // Royal Blue

  // Initialize Particles
  for (let i = 0; i < PARTICLE_COUNT; i++) {
    particles.push({
      // Current position
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.6,
      vy: (Math.random() - 0.5) * 0.6,
      radius: Math.random() * 2 + 1.8,
      baseRadius: Math.random() * 2 + 1.8,

      // Target targets for morphing
      targetX: 0,
      targetY: 0,
      targetColor: { ...COLOR_NEUTRAL },
      currentColor: { ...COLOR_NEUTRAL },

      // Identity & Classification in Stage 3
      isMalicious: i % 3 === 0,
      bandIndex: i % 4, // for stage 2
      phase: Math.random() * Math.PI * 2,
    });
  }

  // Handle Resize
  window.addEventListener("resize", () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  // Calculate normalized scroll progress [0.0 - 1.0]
  function getScrollProgress() {
    const docHeight = document.documentElement.scrollHeight - window.innerHeight;
    if (docHeight <= 0) return 0;
    return Math.min(1, Math.max(0, window.scrollY / docHeight));
  }

  // Linear Interpolation helper
  function lerp(start, end, amt) {
    return (1 - amt) * start + amt * end;
  }

  function lerpColor(c1, c2, amt) {
    return {
      r: Math.round(lerp(c1.r, c2.r, amt)),
      g: Math.round(lerp(c1.g, c2.g, amt)),
      b: Math.round(lerp(c1.b, c2.b, amt)),
      a: lerp(c1.a, c2.a, amt),
    };
  }

  let animationFrameId;

  function render(time) {
    ctx.clearRect(0, 0, width, height);

    const progress = getScrollProgress();
    // 4 stages mapped across scroll progress:
    // Stage 1 (Hero Constellation): 0.00 - 0.22
    // Stage 2 (Deconstruction Bands): 0.22 - 0.50
    // Stage 3 (Decision Boundary Field): 0.50 - 0.78
    // Stage 4 (Calm Wave Terminal): 0.78 - 1.00

    let stage = 1;
    let stageProgress = 0;

    if (progress < 0.22) {
      stage = 1;
      stageProgress = progress / 0.22;
    } else if (progress < 0.50) {
      stage = 2;
      stageProgress = (progress - 0.22) / 0.28;
    } else if (progress < 0.78) {
      stage = 3;
      stageProgress = (progress - 0.50) / 0.28;
    } else {
      stage = 4;
      stageProgress = (progress - 0.78) / 0.22;
    }

    // Update & draw particles based on stage
    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.phase += 0.02;

      // STAGE 1: Hero Floating Network Mesh
      if (stage === 1) {
        p.x += p.vx;
        p.y += p.vy;

        // Bounce on boundaries
        if (p.x < 0 || p.x > width) p.vx *= -1;
        if (p.y < 0 || p.y > height) p.vy *= -1;

        p.targetColor = COLOR_NEUTRAL;
        p.radius = p.baseRadius;
      }

      // STAGE 2: URL Structural Decomposition Bands
      else if (stage === 2) {
        // Particles organize into 4 horizontal data streams:
        // Band 0: Protocol & Scheme
        // Band 1: Hostname & Subdomains
        // Band 2: Path & Resource
        // Band 3: Query & Entropy tokens
        const bandY = (height * 0.25) + (p.bandIndex * (height * 0.16));
        const spacing = width / (PARTICLE_COUNT / 4);
        const colIndex = Math.floor(i / 4);

        p.targetX = (colIndex * spacing + Math.sin(p.phase) * 20) % width;
        p.targetY = bandY + Math.cos(p.phase) * 12;

        p.x = lerp(p.x, p.targetX, 0.06);
        p.y = lerp(p.y, p.targetY, 0.06);

        p.targetColor = COLOR_BLUE;
      }

      // STAGE 3: Machine Learning Decision Boundary Field
      else if (stage === 3) {
        // Particles diverge: Safe (green) particles flow to left, Threat (red) flow to right
        if (p.isMalicious) {
          p.targetX = width * 0.65 + Math.sin(p.phase + i) * (width * 0.25);
          p.targetY = (i / PARTICLE_COUNT) * height + Math.cos(p.phase) * 20;
          p.targetColor = COLOR_DANGER;
          p.radius = p.baseRadius * 1.3;
        } else {
          p.targetX = width * 0.35 - Math.sin(p.phase + i) * (width * 0.25);
          p.targetY = (i / PARTICLE_COUNT) * height + Math.cos(p.phase) * 20;
          p.targetColor = COLOR_SAFE;
          p.radius = p.baseRadius;
        }

        p.x = lerp(p.x, p.targetX, 0.05);
        p.y = lerp(p.y, p.targetY, 0.05);
      }

      // STAGE 4: Calm Ambient Wave Behind Scanner Console
      else {
        const waveY = (height * 0.5) + Math.sin(p.x * 0.005 + p.phase) * 80;
        p.x = (p.x + 0.35) % width;
        p.y = lerp(p.y, waveY, 0.04);
        p.targetColor = COLOR_NEUTRAL;
        p.radius = p.baseRadius * 0.85;
      }

      // Smoothly blend color
      p.currentColor = lerpColor(p.currentColor, p.targetColor, 0.08);

      // Draw particle
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${p.currentColor.r}, ${p.currentColor.g}, ${p.currentColor.b}, ${p.currentColor.a})`;
      ctx.fill();

      // In Stage 3, draw subtle warning ring around malicious clusters
      if (stage === 3 && p.isMalicious) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius * 2.2, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(220, 38, 38, 0.2)`;
        ctx.lineWidth = 1;
        ctx.stroke();
      }
    }

    // Draw connecting constellation lines in Stage 1 & Stage 2
    if (stage === 1 || stage === 2) {
      const maxDistance = stage === 1 ? 110 : 80;
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < maxDistance) {
            const alpha = (1 - dist / maxDistance) * (stage === 1 ? 0.25 : 0.18);
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = `rgba(${particles[i].currentColor.r}, ${particles[i].currentColor.g}, ${particles[i].currentColor.b}, ${alpha})`;
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
      }
    }

    // In Stage 3, draw a subtle vertical decision boundary axis
    if (stage === 3) {
      ctx.beginPath();
      ctx.setLineDash([4, 6]);
      ctx.moveTo(width * 0.5, 0);
      ctx.lineTo(width * 0.5, height);
      ctx.strokeStyle = "rgba(148, 163, 184, 0.25)";
      ctx.lineWidth = 1.2;
      ctx.stroke();
      ctx.setLineDash([]); // reset
    }

    animationFrameId = requestAnimationFrame(render);
  }

  // Start rendering
  render(0);
})();
