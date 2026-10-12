interface ScoreRingProps {
  score: number   // 0–100
  size?: number   // px diameter
}

/**
 * ScoreRing — circular SVG gauge displaying security posture score.
 * Emerald ≥ 80 / Amber ≥ 50 / Crimson < 50.
 */
export default function ScoreRing({ score, size = 76 }: ScoreRingProps) {
  const strokeWidth = 7
  const radius = (size - strokeWidth * 2) / 2
  const circumference = 2 * Math.PI * radius
  const filled = Math.max(0, Math.min(100, score)) / 100 * circumference
  const dashOffset = circumference - filled

  const color =
    score >= 80 ? '#10b981' // brand-500 emerald
    : score >= 50 ? '#f59e0b' // amber
    : '#ef4444'             // red

  const label =
    score >= 80 ? 'Good'
    : score >= 50 ? 'Fair'
    : 'Poor'

  return (
    <div className="flex flex-col items-center gap-1.5 shrink-0">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        {/* Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#262830"
          strokeWidth={strokeWidth}
        />
        {/* Progress */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          strokeLinecap="round"
          className="transition-all duration-300"
        />
        {/* Score number */}
        <text
          x="50%"
          y="50%"
          dominantBaseline="central"
          textAnchor="middle"
          fontSize={Math.round(size * 0.28)}
          fontWeight="700"
          fill="#f4f4f5"
          style={{ transform: 'rotate(90deg)', transformOrigin: 'center', fontFamily: '"IBM Plex Mono", monospace' }}
        >
          {score}
        </text>
      </svg>
      <span className="text-xs font-semibold tracking-wide uppercase text-zinc-300">{label}</span>
    </div>
  )
}
