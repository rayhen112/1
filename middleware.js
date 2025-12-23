// /middleware.js
import { NextResponse } from "next/server";
import { jwtVerify } from "jose";

const COOKIE_NAME = "auth_token";
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Public routes (no auth required)
const PUBLIC = new Set([
  "/",
  "/users/sign-in",
  "/users/sign-up",
  "/users/send-otp",
  "/users/verify-otp",
  "/not-found",
]);

// Role-wise allowlists
const ROLE_ROUTES = {
  user: [
    '/users/home',
    '/users/profile',
    '/users/referral',
    '/users/result',
    '/users/diposit',
    '/users/transaction',
    '/users/support',
    '/users/company',
    '/users/withdraw',
    '/users/history',
    '/users/transfer',
    '/users/bank',
    '/users/freefire',
    '/users/bingo',
    '/users/freefire-profile'
  ],
  agent: ['/agents'],
  admin: ['/admins'],
}

const normalize = (p) => (p.length > 1 && p.endsWith("/") ? p.slice(0, -1) : p);
const startsWithAny = (path, bases = []) =>
  bases.some((base) => path === base || path.startsWith(base + "/"));

async function readToken(req) {
  try {
    const raw = req.cookies.get(COOKIE_NAME)?.value;
    if (!raw) return null;
    const { payload } = await jwtVerify(raw, new TextEncoder().encode(JWT_SECRET));
    return payload; // {_id, email, role}
  } catch {
    return null;
  }
}

export async function middleware(req) {
  const { pathname } = req.nextUrl;
  const path = normalize(pathname);

  // Allow Next internals & static assets
  if (
    path.startsWith("/_next/") ||
    path === "/favicon.ico" ||
    path === "/robots.txt" ||
    path === "/sitemap.xml" ||
    path.startsWith("/assets/") ||
    path.startsWith("/images/") ||
    path.startsWith("/public/")
  ) {
    return NextResponse.next();
  }

  // Let API routes pass
  if (path.startsWith("/api")) {
    return NextResponse.next();
  }

  const token = await readToken(req);
  const role = token?.role || "user";




  // 🔁 NEW: If logged-in, ANY public route → redirect to role-home
  if (PUBLIC.has(path)) {
    if (token) {
      const home = role === "admin" ? "/admins" : role === "agent" ? "/agents" : "/users/home";
      const url = req.nextUrl.clone();
      url.pathname = home;
      return NextResponse.redirect(url);
    }
    return NextResponse.next();
  }

  // Protected routes: must be logged in
  if (!token) {
    const url = req.nextUrl.clone();
    url.pathname = "/users/sign-in";
    return NextResponse.redirect(url);
  }

  // Check role allowlist
  const allow = ROLE_ROUTES[role] || [];
  if (startsWithAny(path, allow)) {
    return NextResponse.next();
  }

  // Role-denied → not-found (public), but since logged-in, will bounce to role-home by the rule above
  const url = req.nextUrl.clone();
  url.pathname = "/not-found";
  return NextResponse.redirect(url);
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml|api).*)",
  ],
};
