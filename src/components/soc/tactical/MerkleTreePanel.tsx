import React from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { GitBranch, ShieldCheck, ShieldAlert } from 'lucide-react';
import { useMerkleTree, type MerkleNode } from './useMerkleTree';

/**
 * MERKLE INTEGRITY TREE — one picture of "has anything changed, and what".
 *
 * Each parent is the hash of its two children, so altering one file changes every hash
 * above it. The tree is drawn from the baseline; a file that no longer matches lights its
 * leaf and its whole branch to the root, one level after another, so the eye follows the
 * change the way the hash does. The badge states whether this browser, rebuilding the
 * tree from the same inputs, arrived at the root the server reports.
 */

const NODE_W = 96;
const NODE_H = 30;
const LEVEL_GAP = 66;
const CYAN = '#22d3ee';
const RED = '#f43f5e';

export const MerkleTreePanel: React.FC<{ isAr: boolean }> = ({ isAr }) => {
  const { view, empty, error } = useMerkleTree();
  const reduce = useReducedMotion() ?? false;

  const layout = React.useMemo(() => {
    if (!view) return null;
    const leafCount = view.levels[0].length;
    const width = Math.max(560, leafCount * (NODE_W + 18) + 40);
    const height = view.levels.length * LEVEL_GAP + 56;
    // x for leaves evenly spaced; each parent centred over its children.
    const xs: number[][] = [view.levels[0].map((_, i) => 20 + NODE_W / 2 + i * ((width - 40 - NODE_W) / Math.max(1, leafCount - 1 || 1)))];
    if (leafCount === 1) xs[0] = [width / 2];
    for (let l = 1; l < view.levels.length; l++) {
      xs.push(view.levels[l].map((_, i) => {
        const a = xs[l - 1][2 * i];
        const b = xs[l - 1][2 * i + 1] ?? a;
        return (a + b) / 2;
      }));
    }
    const y = (l: number) => height - 48 - l * LEVEL_GAP;
    return { width, height, xs, y };
  }, [view]);

  const nodeTone = (n: MerkleNode) => (n.broken ? RED : CYAN);

  return (
    <section className="mt-3 border border-cyan-900/50 bg-black/40 p-3" dir={isAr ? 'rtl' : 'ltr'} aria-label={isAr ? 'شجرة سلامة الملفات' : 'Merkle integrity tree'}>
      <div className="flex flex-wrap items-center gap-2">
        <GitBranch className="h-4 w-4 text-cyan-300" aria-hidden />
        <h3 className="text-sm font-semibold text-cyan-100">{isAr ? 'شجرة سلامة الملفات (Merkle)' : 'Merkle integrity tree'}</h3>
        {view && (
          <span
            className={`ms-auto flex items-center gap-1 border px-2 py-0.5 text-[11px] ${
              view.verified ? 'border-emerald-500/50 text-emerald-300' : 'border-amber-500/60 text-amber-300'
            }`}
            title={`${isAr ? 'جذر الخادم' : 'server root'} ${view.serverRoot}\n${isAr ? 'المحسوب هنا' : 'computed here'} ${view.computedRoot}`}
          >
            {view.verified ? <ShieldCheck className="h-3.5 w-3.5" aria-hidden /> : <ShieldAlert className="h-3.5 w-3.5" aria-hidden />}
            {view.verified
              ? isAr ? 'أعاد المتصفح حساب الجذر: مطابق' : 'root recomputed in your browser: match'
              : !view.serverRoot
                ? isAr ? 'الخادم لم يحسب جذرًا بعد' : 'the server has not computed a root yet'
                : isAr ? 'الجذر المحسوب لا يطابق جذر الخادم (قد يكون قديمًا)' : 'computed root differs from the server root (it may be stale)'}
          </span>
        )}
      </div>

      {error && <p className="mt-2 font-mono text-xs text-amber-300" dir="ltr">{error}</p>}
      {empty && <p className="mt-2 text-xs text-slate-400">{isAr ? 'لا ملفات في خط الأساس بعد.' : 'no files in the baseline yet.'} <span className="font-mono text-slate-500" dir="ltr">/fim/merkle-inputs</span></p>}

      {view && layout && (
        <>
          <p className="mt-1.5 text-[11px] text-slate-400">
            {view.broken === 0
              ? isAr ? `كل الملفات (${view.levels[0].length}) تطابق خط الأساس.` : `All ${view.levels[0].length} files match the baseline.`
              : isAr
                ? `${view.broken} ملف لا يطابق خط الأساس — المسار الأحمر يُظهر كل بصمة انكسرت حتى الجذر.`
                : `${view.broken} file(s) no longer match the baseline — the red path shows every hash that broke, up to the root.`}
          </p>
          <div className="mt-2 overflow-x-auto" dir="ltr">
            <svg
              width={layout.width}
              height={layout.height}
              viewBox={`0 0 ${layout.width} ${layout.height}`}
              role="img"
              aria-label={
                view.broken === 0
                  ? 'Merkle tree: all leaves intact'
                  : `Merkle tree: ${view.levels[0].filter(l => l.broken).map(l => l.leaf?.name).join(', ')} altered`
              }
            >
              <defs>
                <filter id="mk-glow" x="-50%" y="-50%" width="200%" height="200%">
                  <feGaussianBlur stdDeviation="3" result="b" />
                  <feMerge>
                    <feMergeNode in="b" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>

              {/* Edges */}
              {view.levels.slice(1).map((lvl, li) =>
                lvl.map((parent, pi) => {
                  const l = li + 1;
                  const children = [2 * pi, 2 * pi + 1].filter(ci => ci < view.levels[l - 1].length);
                  return children.map(ci => {
                    const child = view.levels[l - 1][ci];
                    const hot = child.broken;
                    return (
                      <motion.line
                        key={`${l}-${pi}-${ci}`}
                        x1={layout.xs[l][pi]}
                        y1={layout.y(l) + NODE_H / 2}
                        x2={layout.xs[l - 1][ci]}
                        y2={layout.y(l - 1) - NODE_H / 2}
                        stroke={hot ? RED : CYAN}
                        strokeOpacity={hot ? 0.9 : 0.3}
                        strokeWidth={hot ? 2 : 1}
                        filter={hot ? 'url(#mk-glow)' : undefined}
                        initial={hot && !reduce ? { opacity: 0 } : false}
                        animate={{ opacity: 1 }}
                        transition={{ delay: (l - 1) * 0.12 + 0.06, duration: 0.2 }}
                      />
                    );
                  });
                })
              )}

              {/* Nodes */}
              {view.levels.map((lvl, l) =>
                lvl.map((n, i) => {
                  const x = layout.xs[l][i] - NODE_W / 2;
                  const y = layout.y(l) - NODE_H / 2;
                  const isRoot = l === view.levels.length - 1;
                  const tone = nodeTone(n);
                  return (
                    <motion.g
                      key={`${l}-${i}`}
                      initial={n.broken && !reduce ? { opacity: 0, scale: 0.9 } : false}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: l * 0.12, duration: 0.2 }}
                      style={{ transformOrigin: `${x + NODE_W / 2}px ${y + NODE_H / 2}px` }}
                    >
                      <title>{n.hash}</title>
                      <path
                        d={`M ${x + 7} ${y} H ${x + NODE_W} V ${y + NODE_H - 7} L ${x + NODE_W - 7} ${y + NODE_H} H ${x} V ${y + 7} Z`}
                        fill={n.broken ? 'rgba(76,5,25,0.85)' : 'rgba(3,7,18,0.92)'}
                        stroke={tone}
                        strokeWidth={isRoot ? 1.8 : 1.1}
                        filter={n.broken || isRoot ? 'url(#mk-glow)' : undefined}
                      />
                      <text x={x + NODE_W / 2} y={y + (isRoot ? 12 : 19)} textAnchor="middle" fontFamily="var(--font-mono)" fontSize="11" fill={n.broken ? '#fecdd3' : '#cffafe'}>
                        {isRoot ? 'ROOT' : n.hash.slice(0, 10)}
                      </text>
                      {isRoot && (
                        <text x={x + NODE_W / 2} y={y + 25} textAnchor="middle" fontFamily="var(--font-mono)" fontSize="10" fill={n.broken ? '#fda4af' : '#67e8f9'}>
                          {n.hash.slice(0, 12)}
                        </text>
                      )}
                      {n.leaf && (
                        <>
                          <text x={x + NODE_W / 2} y={y + NODE_H + 14} textAnchor="middle" fontFamily="var(--font-mono)" fontSize="10" fill="#cbd5e1">
                            {n.leaf.name.length > 16 ? n.leaf.name.slice(0, 15) + '…' : n.leaf.name}
                          </text>
                          {n.leaf.state !== 'INTACT' && (
                            <text x={x + NODE_W / 2} y={y + NODE_H + 26} textAnchor="middle" fontFamily="var(--font-mono)" fontSize="10" fontWeight="bold" fill={RED}>
                              {n.leaf.state}
                            </text>
                          )}
                        </>
                      )}
                    </motion.g>
                  );
                })
              )}
            </svg>
          </div>
          <p className="mt-1 font-mono text-[10px] text-slate-500" dir="ltr">
            leaf = sha256(path:hash) · sorted · parent = sha256(left‖right) · {isAr ? 'آخر حساب للخادم' : 'server computed'} {view.lastCalculated.slice(11, 19)}
          </p>
        </>
      )}
    </section>
  );
};

export default MerkleTreePanel;
