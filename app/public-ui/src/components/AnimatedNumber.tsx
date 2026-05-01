import { useState, useEffect, type FC } from "react";

interface AnimatedNumberProps {
  value: number;
  duration?: number;
}

const AnimatedNumber: FC<AnimatedNumberProps> = ({ value, duration = 1200 }) => {
  const [display, setDisplay] = useState<number>(0);

  useEffect(() => {
    let startTime: number | null = null;
    const step = (ts: number): void => {
      if (!startTime) startTime = ts;
      const progress = Math.min((ts - startTime) / duration, 1);
      setDisplay(Math.floor(progress * value));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [value, duration]);

  return <span>{display.toLocaleString()}</span>;
};

export default AnimatedNumber;
