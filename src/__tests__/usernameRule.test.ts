import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { normalizeUsername, usernameValid } from '../components/auth/usernameRule';

describe('username rule', () => {
  it('accepts Arabic names, not only Latin ones', () => {
    for (const u of ['وليد', 'محمد_العتيبي', 'سارة.٢٠٢٦', 'waleed', 'w.al-eed_1', 'أحمد1']) {
      expect(usernameValid(u), u).toBe(true);
    }
  });

  it('refuses lookalike scripts, marks, invisible characters and bad lengths', () => {
    for (const u of [
      'аdmin', // Cyrillic а
      'αdmin', // Greek α
      'مُحمد', // harakat
      'محــمد', // tatweel
      'و‍ليد', // zero-width joiner
      'ab',
      'a b c',
      'x'.repeat(33),
      ''
    ]) {
      expect(usernameValid(u), JSON.stringify(u)).toBe(false);
    }
  });

  it('folds Arabic presentation forms to plain letters, as the server does', () => {
    expect(normalizeUsername('ﻣﺤﻤﺪ')).toBe('محمد');
    expect(usernameValid('ﻣﺤﻤﺪ')).toBe(true);
  });

  it('matches the rule the server enforces', () => {
    const pattern = /const USERNAME_CHARS = (\/.+\/u);/;
    const client = fs.readFileSync(path.join(__dirname, '../components/auth/usernameRule.ts'), 'utf8').match(pattern)?.[1];
    const server = fs.readFileSync(path.join(__dirname, '../../server/services/operatorAuth.service.ts'), 'utf8').match(pattern)?.[1];
    expect(client).toBeTruthy();
    expect(client).toBe(server);
  });
});
