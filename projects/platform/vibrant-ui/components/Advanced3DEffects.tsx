import React, { useState, useRef, useEffect } from 'react';
import '../styles/vibrant-system.css';

// 3D Parallax Card
export const Parallax3DCard = ({ children, layers = 3 }) => {
  const containerRef = useRef(null);
  const [mousePosition, setMousePosition] = useState({ x: 0.5, y: 0.5 });

  const handleMouseMove = (e) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width;
    const y = (e.clientY - rect.top) / rect.height;
    setMousePosition({ x, y });
  };

  const handleMouseLeave = () => {
    setMousePosition({ x: 0.5, y: 0.5 });
  };

  return (
    <div
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      style={{
        position: 'relative',
        width: '400px',
        height: '500px',
        transformStyle: 'preserve-3d',
        perspective: '1000px'
      }}
    >
      {Array.from({ length: layers }, (_, i) => (
        <div
          key={i}
          style={{
            position: 'absolute',
            width: '100%',
            height: '100%',
            transform: `
              translateX(${(mousePosition.x - 0.5) * 20 * (i + 1)}px)
              translateY(${(mousePosition.y - 0.5) * 20 * (i + 1)}px)
              translateZ(${50 * i}px)
            `,
            transition: 'transform 0.1s ease-out',
            background: `linear-gradient(135deg,
              rgba(102, 126, 234, ${0.1 + i * 0.15}),
              rgba(240, 147, 251, ${0.1 + i * 0.15})
            )`,
            border: '1px solid rgba(255, 255, 255, 0.2)',
            borderRadius: '20px',
            backdropFilter: `blur(${2 + i * 2}px)`
          }}
        >
          {i === layers - 1 && children}
        </div>
      ))}
    </div>
  );
};

// 3D Carousel
export const Carousel3D = ({ items, autoRotate = false }) => {
  const [currentRotation, setCurrentRotation] = useState(0);
  const itemCount = items.length;
  const anglePerItem = 360 / itemCount;

  useEffect(() => {
    if (!autoRotate) return;

    const interval = setInterval(() => {
      setCurrentRotation(prev => prev + anglePerItem);
    }, 3000);

    return () => clearInterval(interval);
  }, [autoRotate, anglePerItem]);

  const handleNext = () => {
    setCurrentRotation(currentRotation + anglePerItem);
  };

  const handlePrev = () => {
    setCurrentRotation(currentRotation - anglePerItem);
  };

  return (
    <div style={{
      perspective: '1200px',
      width: '100%',
      height: '400px',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center'
    }}>
      <div style={{
        position: 'relative',
        width: '300px',
        height: '300px',
        transformStyle: 'preserve-3d',
        transform: `rotateY(${currentRotation}deg)`,
        transition: 'transform 0.6s ease-out'
      }}>
        {items.map((item, index) => {
          const rotation = index * anglePerItem;
          const translateZ = 150;

          return (
            <div
              key={index}
              style={{
                position: 'absolute',
                width: '280px',
                height: '280px',
                left: '10px',
                top: '10px',
                background: 'linear-gradient(135deg, rgba(255, 255, 255, 0.1), rgba(255, 255, 255, 0.05))',
                backdropFilter: 'blur(10px)',
                border: '1px solid rgba(255, 255, 255, 0.2)',
                borderRadius: '20px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                transform: `rotateY(${rotation}deg) translateZ(${translateZ}px)`,
                fontSize: '24px',
                fontWeight: 'bold',
                color: 'white',
                textShadow: '0 2px 4px rgba(0, 0, 0, 0.3)'
              }}
            >
              {item}
            </div>
          );
        })}
      </div>

      <div style={{ marginTop: '50px', display: 'flex', gap: '20px' }}>
        <button onClick={handlePrev} className="morph-button">Previous</button>
        <button onClick={handleNext} className="morph-button">Next</button>
      </div>
    </div>
  );
};

// 3D Sphere Menu
export const SphereMenu = ({ items, radius = 200 }) => {
  const [rotation, setRotation] = useState({ x: 0, y: 0 });
  const containerRef = useRef(null);

  const handleMouseMove = (e) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width - 0.5) * 2;
    const y = ((e.clientY - rect.top) / rect.height - 0.5) * 2;

    setRotation({
      x: y * 180,
      y: x * 180
    });
  };

  const handleMouseLeave = () => {
    setRotation({ x: 0, y: 0 });
  };

  const calculatePosition = (index, total) => {
    const phi = Math.acos(-1 + (2 * index) / total);
    const theta = Math.sqrt(total * Math.PI) * phi;

    return {
      x: radius * Math.cos(theta) * Math.sin(phi),
      y: radius * Math.sin(theta) * Math.sin(phi),
      z: radius * Math.cos(phi)
    };
  };

  return (
    <div
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      style={{
        width: '600px',
        height: '600px',
        perspective: '1000px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}
    >
      <div style={{
        position: 'relative',
        width: '100%',
        height: '100%',
        transformStyle: 'preserve-3d',
        transform: `rotateX(${rotation.x}deg) rotateY(${rotation.y}deg)`,
        transition: 'transform 0.1s ease-out'
      }}>
        {items.map((item, index) => {
          const position = calculatePosition(index, items.length);
          return (
            <div
              key={index}
              style={{
                position: 'absolute',
                width: '80px',
                height: '80px',
                left: '50%',
                top: '50%',
                marginLeft: '-40px',
                marginTop: '-40px',
                background: 'linear-gradient(135deg, #667eea, #764ba2)',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'white',
                fontWeight: 'bold',
                fontSize: '14px',
                transform: `translate3d(${position.x}px, ${position.y}px, ${position.z}px)`,
                boxShadow: '0 10px 30px rgba(0, 0, 0, 0.3)',
                cursor: 'pointer',
                transition: 'all 0.3s ease-out'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = `translate3d(${position.x * 1.1}px, ${position.y * 1.1}px, ${position.z * 1.1}px) scale(1.2)`;
                e.currentTarget.style.background = 'linear-gradient(135deg, #f093fb, #f5576c)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = `translate3d(${position.x}px, ${position.y}px, ${position.z}px) scale(1)`;
                e.currentTarget.style.background = 'linear-gradient(135deg, #667eea, #764ba2)';
              }}
            >
              {item}
            </div>
          );
        })}
      </div>
    </div>
  );
};

// 3D Flip Gallery
export const FlipGallery3D = ({ images }) => {
  const [flippedCards, setFlippedCards] = useState(new Set());

  const toggleFlip = (index) => {
    setFlippedCards(prev => {
      const newSet = new Set(prev);
      if (newSet.has(index)) {
        newSet.delete(index);
      } else {
        newSet.add(index);
      }
      return newSet;
    });
  };

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
      gap: '30px',
      padding: '20px'
    }}>
      {images.map((image, index) => (
        <div
          key={index}
          className="flip-card"
          style={{
            width: '100%',
            height: '350px',
            cursor: 'pointer'
          }}
          onClick={() => toggleFlip(index)}
        >
          <div
            className="flip-card-inner"
            style={{
              transform: flippedCards.has(index) ? 'rotateY(180deg)' : 'rotateY(0)'
            }}
          >
            <div className="flip-card-front" style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '20px'
            }}>
              <h3>{image.title}</h3>
              <p>Click to reveal</p>
            </div>
            <div className="flip-card-back" style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '20px'
            }}>
              <p>{image.description}</p>
              <button className="morph-button" style={{ marginTop: '20px' }}>
                Learn More
              </button>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

// 3D Layered Text
export const LayeredText3D = ({ text, layers = 5 }) => {
  const [hover, setHover] = useState(false);

  return (
    <div
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        position: 'relative',
        perspective: '1000px',
        transformStyle: 'preserve-3d',
        cursor: 'pointer'
      }}
    >
      {Array.from({ length: layers }, (_, i) => (
        <h1
          key={i}
          style={{
            position: i === 0 ? 'relative' : 'absolute',
            top: 0,
            left: 0,
            margin: 0,
            fontSize: '72px',
            fontWeight: 'bold',
            color: i === 0 ? 'white' : 'transparent',
            WebkitTextStroke: i > 0 ? '2px rgba(255, 255, 255, 0.3)' : 'none',
            transform: hover
              ? `translateZ(${i * 20}px) translateX(${i * 2}px) translateY(${i * 2}px)`
              : `translateZ(0)`,
            transition: 'transform 0.3s ease-out',
            userSelect: 'none'
          }}
        >
          {text}
        </h1>
      ))}
    </div>
  );
};

// 3D Ribbon Effect
export const Ribbon3D = ({ text }) => {
  return (
    <div style={{
      position: 'relative',
      perspective: '1000px',
      margin: '50px 0'
    }}>
      <div style={{
        position: 'relative',
        background: 'linear-gradient(135deg, #667eea, #764ba2)',
        color: 'white',
        padding: '20px 60px',
        fontSize: '24px',
        fontWeight: 'bold',
        textAlign: 'center',
        transform: 'rotateY(-5deg)',
        transformStyle: 'preserve-3d',
        boxShadow: '0 10px 30px rgba(0, 0, 0, 0.3)'
      }}>
        {text}

        <div style={{
          position: 'absolute',
          top: 0,
          left: '-40px',
          width: '40px',
          height: '100%',
          background: 'linear-gradient(135deg, #5a67d8, #6b46a1)',
          transform: 'rotateY(90deg) translateZ(20px)',
          transformOrigin: 'right'
        }} />

        <div style={{
          position: 'absolute',
          top: 0,
          right: '-40px',
          width: '40px',
          height: '100%',
          background: 'linear-gradient(135deg, #764ba2, #8b5fc7)',
          transform: 'rotateY(-90deg) translateZ(20px)',
          transformOrigin: 'left'
        }} />
      </div>
    </div>
  );
};

// 3D Isometric Grid
export const IsometricGrid = ({ gridSize = 5 }) => {
  const [activeCell, setActiveCell] = useState(null);

  const cells = Array.from({ length: gridSize * gridSize }, (_, i) => ({
    id: i,
    x: i % gridSize,
    y: Math.floor(i / gridSize)
  }));

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      transform: 'rotateX(60deg) rotateZ(45deg)',
      transformStyle: 'preserve-3d',
      margin: '100px'
    }}>
      {cells.map(cell => (
        <div
          key={cell.id}
          onMouseEnter={() => setActiveCell(cell.id)}
          onMouseLeave={() => setActiveCell(null)}
          style={{
            position: 'absolute',
            width: '60px',
            height: '60px',
            background: activeCell === cell.id
              ? 'linear-gradient(135deg, #f093fb, #f5576c)'
              : 'linear-gradient(135deg, #667eea, #764ba2)',
            border: '2px solid rgba(255, 255, 255, 0.3)',
            transform: `
              translateX(${cell.x * 70}px)
              translateY(${cell.y * 70}px)
              translateZ(${activeCell === cell.id ? '30px' : '0'})
            `,
            transition: 'all 0.3s ease-out',
            cursor: 'pointer',
            boxShadow: activeCell === cell.id
              ? '0 30px 60px rgba(0, 0, 0, 0.4)'
              : '0 10px 20px rgba(0, 0, 0, 0.2)'
          }}
        />
      ))}
    </div>
  );
};