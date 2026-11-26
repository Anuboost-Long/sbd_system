import { forward, readBody } from '@/lib/server-api';

// [Guide §2.3, §4.3] Only these named API routes can be reached through the front end; anything else is 404.
// Why: the page must not become an open proxy to the whole API.
// Standard: OWASP ASVS 5.0 V8.2.1.
const ROUTES: Record<string, string> = {
	login: '/auth/login',
	'mfa-setup': '/auth/mfa/setup',
	'mfa-confirm': '/auth/mfa/confirm',
	mfa: '/auth/mfa',
	logout: '/auth/logout',
	'change-password': '/auth/change-password'
};

export async function POST(request: Request, { params }: { params: Promise<{ action: string }> }) {
	const path = ROUTES[(await params).action];
	if (!path) return new Response(null, { status: 404 });
	return forward('POST', path, await readBody(request));
}

export async function GET(_request: Request, { params }: { params: Promise<{ action: string }> }) {
	if ((await params).action !== 'me') return new Response(null, { status: 404 });
	return forward('GET', '/auth/me');
}
