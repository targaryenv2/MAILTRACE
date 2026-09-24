/**
 * The 3-D backdrop.
 *
 * Two fixed layers behind everything: radial colour washes and a perspective
 * grid that reads as a receding floor. It is pure CSS (see index.css) rather
 * than a WebGL canvas on purpose — no bundle weight, no GPU context to lose, and
 * it renders on a locked-down demo laptop. Both layers respect the depth and
 * backdrop preferences, so a user on weak hardware can switch them off entirely.
 */

import { usePrefs } from '../lib/theme';

export function Scene() {
  const { prefs } = usePrefs();
  if (!prefs.backdrop || prefs.depth === 0) return null;
  return (
    <>
      <div className="backdrop-scene" aria-hidden />
      <div className="backdrop-grid" aria-hidden />
    </>
  );
}
