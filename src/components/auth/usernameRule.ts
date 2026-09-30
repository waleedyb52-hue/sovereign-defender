/**
 * The username rule, as the server enforces it (server/services/operatorAuth.service.ts —
 * keep the two in step). Checked here only so the setup form can say what is wrong
 * instead of leaving its button disabled without a word.
 *
 * Arabic or Latin letters, digits (Western or Arabic-Indic), dot, dash, underscore;
 * 3–32 characters. Other scripts stay out: Cyrillic "а" would let "аdmin" pass for "admin".
 */
const USERNAME_CHARS = /^(?:(?=\p{L})[\p{Script=Latin}\p{Script=Arabic}]|[0-9٠-٩۰-۹._-])+$/u;

export function normalizeUsername(username: string): string {
  return username.normalize('NFKC').trim();
}

export function usernameValid(username: string): boolean {
  const u = normalizeUsername(username);
  const len = [...u].length;
  return len >= 3 && len <= 32 && USERNAME_CHARS.test(u);
}
