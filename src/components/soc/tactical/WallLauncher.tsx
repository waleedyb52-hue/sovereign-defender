import React from 'react';
import { MonitorUp } from 'lucide-react';
import { openWall, WALL_PANELS } from './wallChannel';

/**
 * Opens a theatre in its own window, to drag onto another screen. One icon in the header;
 * the list appears only when asked for.
 */
export const WallLauncher: React.FC<{ isAr: boolean }> = ({ isAr }) => {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && setOpen(false);
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div ref={ref} className="relative shrink-0">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        aria-expanded={open}
        aria-haspopup="menu"
        title={isAr ? 'عرض على شاشة أخرى' : 'Show on another screen'}
        className="grid h-6 w-7 place-items-center border border-cyan-800/60 bg-black/40 text-cyan-300 transition-colors hover:bg-cyan-500/10 focus-visible:ring-1 focus-visible:ring-cyan-400 focus-visible:outline-none"
      >
        <MonitorUp className="h-3.5 w-3.5" aria-hidden />
      </button>
      {open && (
        <div role="menu" className="absolute end-0 top-full z-50 mt-1 w-56 border border-cyan-500/40 bg-[#030712]/95 p-1.5 shadow-[0_0_30px_rgba(0,0,0,0.9)] backdrop-blur-2xl">
          <p className="px-1.5 pb-1 text-[10px] text-slate-400">
            {isAr ? 'افتح في نافذة واسحبها إلى شاشة أخرى. النوافذ متزامنة.' : 'Opens a window to drag to another screen. Windows stay in sync.'}
          </p>
          {WALL_PANELS.map(p => (
            <button
              key={p.id}
              type="button"
              role="menuitem"
              onClick={() => {
                openWall(p.id);
                setOpen(false);
              }}
              className="block w-full px-1.5 py-1 text-start font-mono text-[11px] tracking-wider text-cyan-200 hover:bg-cyan-500/10"
            >
              {isAr ? p.ar : p.en}
            </button>
          ))}
        </div>
      )}
    </div>
  );
};

export default WallLauncher;
