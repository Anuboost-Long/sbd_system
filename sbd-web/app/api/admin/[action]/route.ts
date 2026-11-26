import { forward, readBody } from '@/lib/server-api';

// [Guide §4.4] Only the six admin actions can be reached; the user ID is checked before it is put in a path.
// Why: no open proxy, and a crafted ID cannot reach another API route.
// Standard: OWASP ASVS 5.0 V8.2.1.
const ACTIONS = new Set(['role', 'disable', 'password-reset', 'mfa-reset', 'search-unlock']);

export async function POST(request: Request, { params }: { params: Promise<{ action: string }> }) {
	const { action } = await params;
	const { userId, ...body } = await readBody(request);

	if (action === 'create') return forward('POST', '/admin/users', body);
	if (!ACTIONS.has(action) || typeof userId !== 'string' || !/^[A-Za-z0-9-]{1,64}$/.test(userId))
		return new Response(null, { status: 404 });
	return forward('POST', `/admin/users/${userId}/${action}`, body);
}
