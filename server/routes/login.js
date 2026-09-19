/**
 * 登录接口 —— 移植自 functions/api/login.ts
 * POST /api/login
 */

const { Router } = require('express');

const MAX_AGE_SECONDS = 48 * 60 * 60; // 48 小时

function parsePasswords(value) {
  return typeof value === 'string'
    ? value.split(',').map(password => password.trim()).filter(Boolean)
    : [];
}

/**
 * @param {string|null} passwordConfig
 * @returns {import('express').Router}
 */
module.exports = function createLoginRouter(passwordConfig) {
  const router = Router();
  const passwords = parsePasswords(passwordConfig);

  router.post('/', async (req, res) => {
    const body = req.body || {};
    const providedPassword = typeof body.password === 'string' ? body.password : '';

    // 未配置密码时直接成功
    if (passwords.length === 0) {
      return res.json({ success: true });
    }

    if (passwords.includes(providedPassword)) {
      const encoded = Buffer.from(providedPassword).toString('base64'); // 等价于 btoa(password)
      const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';

      const cookieParts = [
        `auth=${encoded}`,
        `Max-Age=${MAX_AGE_SECONDS}`,
        'Path=/',
        'SameSite=Lax',
        'HttpOnly',
      ];
      if (isHttps) cookieParts.push('Secure');

      res.setHeader('Set-Cookie', cookieParts.join('; '));
      return res.json({ success: true });
    }

    return res.status(401).json({ success: false });
  });

  return router;
};
