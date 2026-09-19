const MAX_AGE_SECONDS = 48 * 60 * 60;

function parsePasswords(value: unknown): string[] {
  return typeof value === "string"
    ? value.split(",").map((password) => password.trim()).filter(Boolean)
    : [];
}

export async function onRequestPost(context: any) {
  const { request, env } = context;
  const passwords = parsePasswords(env.PASSWORD);
  const url = new URL(request.url);

  const body = await request.json().catch(() => ({ password: "" }));
  const providedPassword = typeof body.password === "string" ? body.password : "";

  if (passwords.length === 0) {
    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (passwords.includes(providedPassword)) {
    const encodedPassword = btoa(providedPassword);
    const cookieSegments = [
      `auth=${encodedPassword}`,
      `Max-Age=${MAX_AGE_SECONDS}`,
      "Path=/",
      "SameSite=Lax",
      "HttpOnly",
    ];
    if (url.protocol === "https:") {
      cookieSegments.push("Secure");
    }

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": cookieSegments.join("; "),
      },
    });
  }

  return new Response(JSON.stringify({ success: false }), {
    status: 401,
    headers: { "Content-Type": "application/json" },
  });
}
