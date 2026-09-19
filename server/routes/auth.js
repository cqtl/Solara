/**
 * 认证中间件 —— 移植自 functions/_middleware.ts（authMiddleware 部分）
 *
 * 逻辑完全一致：
 *   - 公开路径（/login, /api/login, 静态资源文件）直接放行
 *   - 其余路径检查 cookie auth === btoa(PASSWORD)
 *   - 验证失败则重定向到 /login
 */

const PUBLIC_PATH_PATTERNS = [
  /^\/login(?:\/|$)/,
  /^\/api\/login(?:\/|$)/,
];

const PUBLIC_FILE_EXTENSIONS = new Set([
  '.css', '.js', '.png', '.svg', '.jpg', '.jpeg',
  '.gif', '.webp', '.ico', '.txt', '.map', '.json',
  '.woff', '.woff2',
]);

function hasPublicExtension(pathname) {
  const lastDotIndex = pathname.lastIndexOf('.');
  if (lastDotIndex === -1) return false;
  return PUBLIC_FILE_EXTENSIONS.has(pathname.slice(lastDotIndex).toLowerCase());
}

function isPublicPath(pathname) {
  return (
    PUBLIC_PATH_PATTERNS.some(pattern => pattern.test(pathname)) ||
    hasPublicExtension(pathname)
  );
}

function parsePasswords(value) {
  return typeof value === 'string'
    ? value.split(',').map(password => password.trim()).filter(Boolean)
    : [];
}

/**
 * @param {string|null} passwordConfig - 来自环境变量 PASSWORD
 * @returns {import('express').RequestHandler}
 */
module.exports = function createAuthMiddleware(passwordConfig) {
  const passwords = parsePasswords(passwordConfig);

  return (req, res, next) => {
    // 未配置密码时，全部放行
    if (passwords.length === 0) return next();

    // 公开路径直接放行
    if (isPublicPath(req.path)) return next();

    // 验证 cookie（与 Cloudflare 版本完全一致：cookie auth = btoa(password)）
    const cookieAuth = req.cookies && req.cookies.auth;
    const isAuthenticated = cookieAuth && passwords.some(password =>
      cookieAuth === Buffer.from(password).toString('base64')
    );
    if (isAuthenticated) return next();

    // 验证失败，重定向到登录页
    return res.redirect(302, '/login');
  };
};
