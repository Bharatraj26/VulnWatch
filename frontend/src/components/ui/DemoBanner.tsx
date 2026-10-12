/**
 * DemoBanner — Notice that a section displays demo/placeholder data.
 */
export default function DemoBanner() {
  return (
    <div className="flex items-center gap-3.5 px-4 py-3 mb-6 rounded-lg bg-amber-950/40 border border-amber-700/50 text-sm md:text-base">
      <span className="text-amber-400 text-lg shrink-0" aria-hidden="true">⚠</span>
      <div>
        <span className="font-semibold text-amber-300">Demo data — </span>
        <span className="text-amber-200/80 leading-normal">
          The statistics, scans, and reports shown below are placeholder records.
          Live data is loaded from the SQLite backend.
        </span>
      </div>
    </div>
  )
}
