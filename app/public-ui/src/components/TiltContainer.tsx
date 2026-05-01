import { useState, useRef, useCallback, type FC, type MouseEvent } from "react";

interface TiltState {
  x: number;
  y: number;
}

interface TiltContainerProps {
  children: React.ReactNode;
  className?: string;
}

const TiltContainer: FC<TiltContainerProps> = ({ children, className }) => {
  const [tilt, setTilt] = useState<TiltState>({ x: 0, y: 0 });
  const ref = useRef<HTMLDivElement>(null);

  const handleMove = useCallback((e: MouseEvent<HTMLDivElement>): void => {
    if (!ref.current) return;
    const r = ref.current.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - 0.5;
    const y = (e.clientY - r.top) / r.height - 0.5;
    setTilt({ x: y * -8, y: x * 8 });
  }, []);

  return (
    <div
      ref={ref}
      className={className}
      onMouseMove={handleMove}
      onMouseLeave={() => setTilt({ x: 0, y: 0 })}
      style={{
        perspective: "1200px",
        transform: `rotateX(${tilt.x}deg) rotateY(${tilt.y}deg)`,
        transition: "transform 0.08s ease-out",
        transformStyle: "preserve-3d",
      }}
    >
      {children}
    </div>
  );
};

export default TiltContainer;
