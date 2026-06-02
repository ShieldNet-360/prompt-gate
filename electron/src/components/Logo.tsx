import React from 'react';

interface LogoProps {
  size?: number;
  className?: string;
}

/**
 * Prompt Gate logo — built from design CSS specs:
 *   Outer: 100×98, blue rounded-square
 *   Inner: 84×83, white #FFF, border-radius 17 17 16 16, centered
 *   Dots: blue rounded squares in a diamond on the white area
 */
export const Logo: React.FC<LogoProps> = ({ size = 48, className }) => {
  // Design spec: outer 100×98, inner 84×83
  const W = 100;
  const H = 98;
  const outerR = 22;

  const innerW = 84;
  const innerH = 83;
  const innerX = (W - innerW) / 2;
  const innerY = (H - innerH) / 2 + 0.5;

  // Shield dots SVG is 30×36; scale to fit inside the inner area
  const dotsNativeW = 30;
  const dotsNativeH = 36;
  const scale = 1.85;
  const dotsW = dotsNativeW * scale;
  const dotsH = dotsNativeH * scale;
  const dotsX = innerX + (innerW - dotsW) / 2;
  const dotsY = innerY + (innerH - dotsH) / 2;

  const h = size * (H / W);

  return (
    <svg
      width={size}
      height={h}
      viewBox={`0 0 ${W} ${H}`}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-label="Prompt Gate logo"
    >
      <defs>
        {/* Outer body gradient — vibrant blue */}
        <linearGradient id="se-bg" x1="10" y1="0" x2="90" y2="98" gradientUnits="userSpaceOnUse">
          <stop offset="0%"  stopColor="#72b8ff" />
          <stop offset="30%" stopColor="#4d9af8" />
          <stop offset="60%" stopColor="#3678f0" />
          <stop offset="100%" stopColor="#2454e0" />
        </linearGradient>

        {/* Top-left glossy highlight */}
        <radialGradient id="se-gloss" cx="30%" cy="15%" r="65%" gradientUnits="objectBoundingBox">
          <stop offset="0%"  stopColor="white" stopOpacity="0.45" />
          <stop offset="50%" stopColor="white" stopOpacity="0.10" />
          <stop offset="100%" stopColor="white" stopOpacity="0" />
        </radialGradient>

        {/* Inner recessed area gradient — darker blue */}
        <linearGradient id="se-inner" x1="15" y1="8" x2="85" y2="91" gradientUnits="userSpaceOnUse">
          <stop offset="0%"  stopColor="#3a7ae8" />
          <stop offset="50%" stopColor="#2d65d8" />
          <stop offset="100%" stopColor="#1f4cc0" />
        </linearGradient>

        {/* Inner inset shadow (top edge darker) */}
        <linearGradient id="se-inset-top" x1="50" y1="8" x2="50" y2="35" gradientUnits="userSpaceOnUse">
          <stop offset="0%"  stopColor="#0a2a80" stopOpacity="0.35" />
          <stop offset="100%" stopColor="#0a2a80" stopOpacity="0" />
        </linearGradient>

        {/* Drop shadow */}
        <filter id="se-shadow" x="-10%" y="-5%" width="120%" height="125%">
          <feDropShadow dx="0" dy="3" stdDeviation="4" floodColor="#0f2a6e" floodOpacity="0.40" />
        </filter>

        {/* Bottom edge highlight on outer (reflected light) */}
        <linearGradient id="se-edge" x1="50" y1="85" x2="50" y2="98" gradientUnits="userSpaceOnUse">
          <stop offset="0%"  stopColor="white" stopOpacity="0" />
          <stop offset="100%" stopColor="white" stopOpacity="0.12" />
        </linearGradient>
      </defs>

      {/* Outer blue rounded square */}
      <rect
        width={W} height={H}
        rx={outerR}
        fill="url(#se-bg)"
        filter="url(#se-shadow)"
      />

      {/* Glossy highlight overlay */}
      <rect
        width={W} height={H}
        rx={outerR}
        fill="url(#se-gloss)"
      />

      {/* Bottom edge subtle highlight */}
      <rect
        width={W} height={H}
        rx={outerR}
        fill="url(#se-edge)"
      />

      {/* Inner recessed area — dark blue inset, 84×83 */}
      <rect
        x={innerX} y={innerY}
        width={innerW} height={innerH}
        rx={17}
        fill="url(#se-inner)"
      />

      {/* Inset shadow on top of inner area */}
      <rect
        x={innerX} y={innerY}
        width={innerW} height={innerH}
        rx={17}
        fill="url(#se-inset-top)"
      />

      {/* Exact shield dots from design (30×36 SVG, scaled & centered) */}
      <g transform={`translate(${dotsX}, ${dotsY}) scale(${scale})`}>
        <path
          d="M16.1162 4.71364H13.902C13.2123 4.71364 12.6316 4.15592 12.6316 3.45427V1.25937C12.6316 0.575713 13.1942 0 13.902 0H16.1162C16.8058 0 17.3866 0.557722 17.3866 1.25937V3.45427C17.3866 4.13793 16.824 4.71364 16.1162 4.71364ZM4.75499 9.71514V7.52024C4.75499 6.83658 4.19238 6.26087 3.48457 6.26087H1.27042C0.580763 6.26087 0 6.81859 0 7.52024V9.71514C0 10.3988 0.562614 10.9745 1.27042 10.9745H3.48457C4.17423 10.9745 4.75499 10.4168 4.75499 9.71514ZM11.0708 9.71514V7.52024C11.0708 6.83658 10.5082 6.26087 9.80036 6.26087H7.58621C6.89655 6.26087 6.31579 6.81859 6.31579 7.52024V9.71514C6.31579 10.3988 6.8784 10.9745 7.58621 10.9745H9.80036C10.49 10.9745 11.0708 10.4168 11.0708 9.71514ZM17.3684 9.71514V7.52024C17.3684 6.83658 16.8058 6.26087 16.098 6.26087H13.8838C13.1942 6.26087 12.6134 6.81859 12.6134 7.52024V9.71514C12.6134 10.3988 13.176 10.9745 13.8838 10.9745H16.098C16.7877 10.9745 17.3684 10.4168 17.3684 9.71514ZM23.6842 9.71514V7.52024C23.6842 6.83658 23.1216 6.26087 22.4138 6.26087H20.1996C19.51 6.26087 18.9292 6.81859 18.9292 7.52024V9.71514C18.9292 10.3988 19.4918 10.9745 20.1996 10.9745H22.4138C23.1034 10.9745 23.6842 10.4168 23.6842 9.71514ZM30 9.71514V7.52024C30 6.83658 29.4374 6.26087 28.7296 6.26087H26.5154C25.8258 6.26087 25.245 6.81859 25.245 7.52024V9.71514C25.245 10.3988 25.8076 10.9745 26.5154 10.9745H28.7296C29.4192 10.9745 30 10.4168 30 9.71514ZM4.75499 15.976V13.7811C4.75499 13.0975 4.19238 12.5217 3.48457 12.5217H1.27042C0.580763 12.5217 0 13.0795 0 13.7811V15.976C0 16.6597 0.562614 17.2354 1.27042 17.2354H3.48457C4.17423 17.2354 4.75499 16.6777 4.75499 15.976ZM11.0708 15.976V13.7811C11.0708 13.0975 10.5082 12.5217 9.80036 12.5217H7.58621C6.89655 12.5217 6.31579 13.0795 6.31579 13.7811V15.976C6.31579 16.6597 6.8784 17.2354 7.58621 17.2354H9.80036C10.49 17.2354 11.0708 16.6777 11.0708 15.976ZM17.3684 15.976V13.7811C17.3684 13.0975 16.8058 12.5217 16.098 12.5217H13.8838C13.1942 12.5217 12.6134 13.0795 12.6134 13.7811V15.976C12.6134 16.6597 13.176 17.2354 13.8838 17.2354H16.098C16.7877 17.2354 17.3684 16.6777 17.3684 15.976ZM23.6842 15.976V13.7811C23.6842 13.0975 23.1216 12.5217 22.4138 12.5217H20.1996C19.51 12.5217 18.9292 13.0795 18.9292 13.7811V15.976C18.9292 16.6597 19.4918 17.2354 20.1996 17.2354H22.4138C23.1034 17.2354 23.6842 16.6777 23.6842 15.976ZM30 15.976V13.7811C30 13.0975 29.4374 12.5217 28.7296 12.5217H26.5154C25.8258 12.5217 25.245 13.0795 25.245 13.7811V15.976C25.245 16.6597 25.8076 17.2354 26.5154 17.2354H28.7296C29.4192 17.2354 30 16.6777 30 15.976ZM4.75499 22.2369V20.042C4.75499 19.3583 4.19238 18.7826 3.48457 18.7826H1.27042C0.580763 18.7826 0 19.3403 0 20.042V22.2369C0 22.9205 0.562614 23.4963 1.27042 23.4963H3.48457C4.17423 23.4963 4.75499 22.9385 4.75499 22.2369ZM11.0708 22.2369V20.042C11.0708 19.3583 10.5082 18.7826 9.80036 18.7826H7.58621C6.89655 18.7826 6.31579 19.3403 6.31579 20.042V22.2369C6.31579 22.9205 6.8784 23.4963 7.58621 23.4963H9.80036C10.49 23.4963 11.0708 22.9385 11.0708 22.2369ZM17.3684 22.2369V20.042C17.3684 19.3583 16.8058 18.7826 16.098 18.7826H13.8838C13.1942 18.7826 12.6134 19.3403 12.6134 20.042V22.2369C12.6134 22.9205 13.176 23.4963 13.8838 23.4963H16.098C16.7877 23.4963 17.3684 22.9385 17.3684 22.2369ZM23.6842 22.2369V20.042C23.6842 19.3583 23.1216 18.7826 22.4138 18.7826H20.1996C19.51 18.7826 18.9292 19.3403 18.9292 20.042V22.2369C18.9292 22.9205 19.4918 23.4963 20.1996 23.4963H22.4138C23.1034 23.4963 23.6842 22.9385 23.6842 22.2369ZM30 22.2369V20.042C30 19.3583 29.4374 18.7826 28.7296 18.7826H26.5154C25.8258 18.7826 25.245 19.3403 25.245 20.042V22.2369C25.245 22.9205 25.8076 23.4963 26.5154 23.4963H28.7296C29.4192 23.4963 30 22.9385 30 22.2369ZM11.0708 28.4977V26.3028C11.0708 25.6192 10.5082 25.0435 9.80036 25.0435H7.58621C6.89655 25.0435 6.31579 25.6012 6.31579 26.3028V28.4977C6.31579 29.1814 6.8784 29.7571 7.58621 29.7571H9.80036C10.49 29.7571 11.0708 29.1994 11.0708 28.4977ZM17.3684 28.4977V26.3028C17.3684 25.6192 16.8058 25.0435 16.098 25.0435H13.8838C13.1942 25.0435 12.6134 25.6012 12.6134 26.3028V28.4977C12.6134 29.1814 13.176 29.7571 13.8838 29.7571H16.098C16.7877 29.7571 17.3684 29.1994 17.3684 28.4977ZM23.6842 28.4977V26.3028C23.6842 25.6192 23.1216 25.0435 22.4138 25.0435H20.1996C19.51 25.0435 18.9292 25.6012 18.9292 26.3028V28.4977C18.9292 29.1814 19.4918 29.7571 20.1996 29.7571H22.4138C23.1034 29.7571 23.6842 29.1994 23.6842 28.4977ZM17.3684 34.7406V32.5457C17.3684 31.8621 16.8058 31.2864 16.098 31.2864H13.8838C13.1942 31.2864 12.6134 31.8441 12.6134 32.5457V34.7406C12.6134 35.4243 13.176 36 13.8838 36H16.098C16.7877 36 17.3684 35.4423 17.3684 34.7406Z"
          fill="#F3F4F6"
          fillOpacity="0.8"
        />
      </g>
    </svg>
  );
};
