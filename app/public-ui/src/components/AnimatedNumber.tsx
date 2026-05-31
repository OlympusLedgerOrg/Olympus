import { useState, useEffect, type FC } from "react";

interface AnimatedNumberProps {
  value: number;
  duration?: number;
}

const AnimatedNumber: FC<AnimatedNumberProps> = ({ value, duration = 1200 }) => {
  const [display, setDisplay] = useState<number>(0);

  useEffect(() => {
    let startTime: number | null = null;
    let rafId: number | null = null;
    let cancelled = false;
    const step = (ts: number): void => {
      if (cancelled) return;
      if (!startTime) startTime = ts;
      const progress = Math.min((ts - startTime) / duration, 1);
      setDisplay(Math.floor(progress * value));
      if (progress < 1) rafId = requestAnimationFrame(step);
    };
    rafId = requestAnimationFrame(step);
    return () => {
      cancelled = true;
      if (rafId !== null) cancelAnimationFrame(rafId);
    };
  }, [value, duration]);

  return <span>{display.toLocaleString()}</span>;
};

export default AnimatedNumber;
