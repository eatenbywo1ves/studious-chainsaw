import React, { useState, useRef, useEffect } from 'react';
import '../styles/vibrant-system.css';

// Animated Gradient Button
export const GradientButton = ({ children, onClick, variant = 'aurora' }) => {
  const [ripples, setRipples] = useState([]);

  const handleClick = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const ripple = {
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
      id: Date.now()
    };

    setRipples([...ripples, ripple]);
    setTimeout(() => {
      setRipples(prev => prev.filter(r => r.id !== ripple.id));
    }, 600);

    if (onClick) onClick(e);
  };

  return (
    <button className="morph-button" onClick={handleClick}>
      {ripples.map(ripple => (
        <span
          key={ripple.id}
          className="ripple"
          style={{
            left: ripple.x,
            top: ripple.y,
            position: 'absolute',
            width: '20px',
            height: '20px',
            borderRadius: '50%',
            background: 'rgba(255, 255, 255, 0.6)',
            transform: 'translate(-50%, -50%)',
            animation: 'rippleExpand 0.6s ease-out',
            pointerEvents: 'none'
          }}
        />
      ))}
      {children}
    </button>
  );
};

// Interactive Card with Tilt Effect
export const TiltCard = ({ children, maxTilt = 15 }) => {
  const cardRef = useRef(null);
  const [transform, setTransform] = useState('');

  const handleMouseMove = (e) => {
    if (!cardRef.current) return;

    const rect = cardRef.current.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width;
    const y = (e.clientY - rect.top) / rect.height;

    const tiltX = (y - 0.5) * maxTilt;
    const tiltY = (x - 0.5) * -maxTilt;

    setTransform(`perspective(1000px) rotateX(${tiltX}deg) rotateY(${tiltY}deg)`);
  };

  const handleMouseLeave = () => {
    setTransform('perspective(1000px) rotateX(0) rotateY(0)');
  };

  return (
    <div
      ref={cardRef}
      className="glass-card"
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      style={{
        transform,
        transition: 'transform 0.1s ease-out',
        transformStyle: 'preserve-3d'
      }}
    >
      {children}
    </div>
  );
};

// Magnetic Button
export const MagneticButton = ({ children }) => {
  const buttonRef = useRef(null);
  const [position, setPosition] = useState({ x: 0, y: 0 });

  const handleMouseMove = (e) => {
    if (!buttonRef.current) return;

    const rect = buttonRef.current.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;

    const distanceX = e.clientX - centerX;
    const distanceY = e.clientY - centerY;

    const maxDistance = 50;
    const distance = Math.sqrt(distanceX * distanceX + distanceY * distanceY);

    if (distance < maxDistance) {
      const force = (maxDistance - distance) / maxDistance;
      setPosition({
        x: distanceX * force * 0.5,
        y: distanceY * force * 0.5
      });
    }
  };

  const handleMouseLeave = () => {
    setPosition({ x: 0, y: 0 });
  };

  useEffect(() => {
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  return (
    <button
      ref={buttonRef}
      className="morph-button"
      onMouseLeave={handleMouseLeave}
      style={{
        transform: `translate(${position.x}px, ${position.y}px)`,
        transition: 'transform 0.2s ease-out'
      }}
    >
      {children}
    </button>
  );
};

// Particle Field Background
export const ParticleField = ({ particleCount = 50 }) => {
  const particles = Array.from({ length: particleCount }, (_, i) => ({
    id: i,
    x: Math.random() * 100,
    delay: Math.random() * 10,
    duration: 10 + Math.random() * 20,
    size: 2 + Math.random() * 4
  }));

  return (
    <div className="particle-container" style={{
      position: 'absolute',
      top: 0,
      left: 0,
      width: '100%',
      height: '100%',
      overflow: 'hidden',
      pointerEvents: 'none'
    }}>
      {particles.map(particle => (
        <div
          key={particle.id}
          className="particle"
          style={{
            left: `${particle.x}%`,
            width: `${particle.size}px`,
            height: `${particle.size}px`,
            animationDelay: `${particle.delay}s`,
            animationDuration: `${particle.duration}s`
          }}
        />
      ))}
    </div>
  );
};

// Liquid Loader
export const LiquidLoader = ({ size = 100 }) => {
  return (
    <div style={{
      width: `${size}px`,
      height: `${size}px`,
      position: 'relative'
    }}>
      <svg viewBox="0 0 100 100" style={{ width: '100%', height: '100%' }}>
        <defs>
          <linearGradient id="liquidGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#667eea" />
            <stop offset="50%" stopColor="#764ba2" />
            <stop offset="100%" stopColor="#f093fb" />
          </linearGradient>
        </defs>
        <circle
          cx="50"
          cy="50"
          r="45"
          fill="none"
          stroke="url(#liquidGradient)"
          strokeWidth="3"
          strokeLinecap="round"
          strokeDasharray="70 30"
          style={{
            animation: 'rotate3d 2s linear infinite'
          }}
        />
        <circle
          cx="50"
          cy="50"
          r="35"
          fill="none"
          stroke="url(#liquidGradient)"
          strokeWidth="3"
          strokeLinecap="round"
          strokeDasharray="50 50"
          style={{
            animation: 'rotate3d 3s linear reverse infinite',
            opacity: 0.6
          }}
        />
      </svg>
    </div>
  );
};

// Glitch Text Effect
export const GlitchText = ({ children, intensity = 'medium' }) => {
  const [glitching, setGlitching] = useState(false);

  useEffect(() => {
    const interval = setInterval(() => {
      setGlitching(true);
      setTimeout(() => setGlitching(false), 200);
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  const glitchStyle = glitching ? {
    textShadow: `
      2px 2px 0 #FF00E5,
      -2px -2px 0 #00F5FF,
      0 0 10px rgba(255, 0, 229, 0.5)
    `,
    transform: `translate(${Math.random() * 4 - 2}px, ${Math.random() * 4 - 2}px)`
  } : {};

  return (
    <span style={{
      display: 'inline-block',
      position: 'relative',
      transition: 'all 0.1s ease-out',
      ...glitchStyle
    }}>
      {children}
      {glitching && (
        <>
          <span style={{
            position: 'absolute',
            top: 0,
            left: '2px',
            color: '#FF00E5',
            opacity: 0.8,
            clipPath: 'polygon(0 0, 100% 0, 100% 45%, 0 45%)'
          }}>
            {children}
          </span>
          <span style={{
            position: 'absolute',
            top: 0,
            left: '-2px',
            color: '#00F5FF',
            opacity: 0.8,
            clipPath: 'polygon(0 55%, 100% 55%, 100% 100%, 0 100%)'
          }}>
            {children}
          </span>
        </>
      )}
    </span>
  );
};

// Wave Text Animation
export const WaveText = ({ text, delay = 0.05 }) => {
  return (
    <span style={{ display: 'inline-flex' }}>
      {text.split('').map((char, index) => (
        <span
          key={index}
          style={{
            display: 'inline-block',
            animation: 'float 2s ease-in-out infinite',
            animationDelay: `${index * delay}s`
          }}
        >
          {char === ' ' ? '\u00A0' : char}
        </span>
      ))}
    </span>
  );
};

// Morphing Shape Background
export const MorphingBackground = () => {
  return (
    <div style={{
      position: 'absolute',
      top: 0,
      left: 0,
      width: '100%',
      height: '100%',
      overflow: 'hidden',
      zIndex: -1
    }}>
      <svg viewBox="0 0 1000 1000" style={{
        width: '150%',
        height: '150%',
        position: 'absolute',
        top: '-25%',
        left: '-25%'
      }}>
        <defs>
          <linearGradient id="morphGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#667eea" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#f093fb" stopOpacity="0.3" />
          </linearGradient>
        </defs>
        <path
          fill="url(#morphGradient)"
          d="M 100 300 Q 200 100 400 200 T 700 300 Q 800 400 700 500 T 400 600 Q 200 700 100 500 Z"
          style={{
            animation: 'morphShape 10s ease-in-out infinite'
          }}
        />
      </svg>
    </div>
  );
};

// 3D Cube Menu
export const CubeMenu = ({ items }) => {
  const [rotation, setRotation] = useState({ x: 0, y: 0 });
  const [currentFace, setCurrentFace] = useState(0);

  const rotateCube = (direction) => {
    const rotations = [
      { x: 0, y: 0 },     // front
      { x: 0, y: -90 },   // right
      { x: 0, y: -180 },  // back
      { x: 0, y: -270 },  // left
      { x: -90, y: 0 },   // top
      { x: 90, y: 0 }     // bottom
    ];

    let newFace = currentFace;
    if (direction === 'next') {
      newFace = (currentFace + 1) % 6;
    } else {
      newFace = currentFace === 0 ? 5 : currentFace - 1;
    }

    setCurrentFace(newFace);
    setRotation(rotations[newFace]);
  };

  return (
    <div style={{
      perspective: '1000px',
      width: '200px',
      height: '200px',
      margin: '100px auto'
    }}>
      <div style={{
        width: '100%',
        height: '100%',
        position: 'relative',
        transformStyle: 'preserve-3d',
        transform: `rotateX(${rotation.x}deg) rotateY(${rotation.y}deg)`,
        transition: 'transform 0.6s ease-out'
      }}>
        <div className="cube-face" style={{
          position: 'absolute',
          width: '200px',
          height: '200px',
          background: 'var(--gradient-aurora)',
          border: '2px solid rgba(255, 255, 255, 0.3)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          transform: 'translateZ(100px)'
        }}>Front</div>

        <div className="cube-face" style={{
          position: 'absolute',
          width: '200px',
          height: '200px',
          background: 'var(--gradient-ocean)',
          border: '2px solid rgba(255, 255, 255, 0.3)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          transform: 'rotateY(90deg) translateZ(100px)'
        }}>Right</div>

        <div className="cube-face" style={{
          position: 'absolute',
          width: '200px',
          height: '200px',
          background: 'var(--gradient-fire)',
          border: '2px solid rgba(255, 255, 255, 0.3)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          transform: 'rotateY(180deg) translateZ(100px)'
        }}>Back</div>

        <div className="cube-face" style={{
          position: 'absolute',
          width: '200px',
          height: '200px',
          background: 'var(--gradient-dream)',
          border: '2px solid rgba(255, 255, 255, 0.3)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          transform: 'rotateY(-90deg) translateZ(100px)'
        }}>Left</div>

        <div className="cube-face" style={{
          position: 'absolute',
          width: '200px',
          height: '200px',
          background: 'var(--gradient-cosmic)',
          border: '2px solid rgba(255, 255, 255, 0.3)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          transform: 'rotateX(90deg) translateZ(100px)'
        }}>Top</div>

        <div className="cube-face" style={{
          position: 'absolute',
          width: '200px',
          height: '200px',
          background: 'var(--gradient-neon)',
          border: '2px solid rgba(255, 255, 255, 0.3)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          transform: 'rotateX(-90deg) translateZ(100px)'
        }}>Bottom</div>
      </div>

      <div style={{ marginTop: '50px', textAlign: 'center' }}>
        <button onClick={() => rotateCube('prev')} className="morph-button" style={{ marginRight: '10px' }}>
          Previous
        </button>
        <button onClick={() => rotateCube('next')} className="morph-button">
          Next
        </button>
      </div>
    </div>
  );
};

// Add ripple animation to CSS
const style = document.createElement('style');
style.textContent = `
  @keyframes rippleExpand {
    to {
      width: 400px;
      height: 400px;
      opacity: 0;
    }
  }

  @keyframes morphShape {
    0%, 100% {
      d: path("M 100 300 Q 200 100 400 200 T 700 300 Q 800 400 700 500 T 400 600 Q 200 700 100 500 Z");
    }
    25% {
      d: path("M 150 350 Q 250 150 450 250 T 650 350 Q 750 450 650 550 T 450 650 Q 250 750 150 550 Z");
    }
    50% {
      d: path("M 200 300 Q 300 200 500 300 T 600 400 Q 700 500 600 600 T 400 700 Q 200 600 200 400 Z");
    }
    75% {
      d: path("M 100 400 Q 300 100 500 200 T 700 400 Q 800 500 700 600 T 500 700 Q 300 800 100 600 Z");
    }
  }
`;
document.head.appendChild(style);