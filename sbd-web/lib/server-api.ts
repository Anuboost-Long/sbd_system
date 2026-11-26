import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';

const SESSION_COOKIE = 'sbd_session';

type SessionReply = { token?: string; expiresUtc?: string } & Record<string, unknown>;

// [Guide §2.3] The Next.js server is the only caller of the API: it adds the API key and the session token itself.
// Why: the browser never holds the key or the token; the token lives in an HttpOnly cookie that scripts cannot read.
// Standard: OWASP Session Management Cheat Sheet; OWASP ASVS 5.0 V11.5.1.
export async function forward(method: 'GET' | 'POST', path: string, body?: unknown) {
	const token = (await cookies()).get(SESSION_COOKIE)?.value;
	const headers: Record<string, string> = {
		'X-Api-Key': process.env.API_KEY ?? '',
		'Content-Type': 'application/json'
	};
	if (token) headers.Authorization = `Bearer ${token}`;

	const response = await fetch(`${process.env.API_URL}${path}`, {
		method,
		headers,
		body: body === undefined ? undefined : JSON.stringify(body),
		cache: 'no-store'
	});
	const text = await response.text();
	const data: SessionReply | null = text ? JSON.parse(text) : null;

	if (data?.token && data.expiresUtc) {
		(await cookies()).set(SESSION_COOKIE, data.token, {
			httpOnly: true,
			secure: true,
			sameSite: 'strict',
			path: '/',
			expires: new Date(data.expiresUtc)
		});
		delete data.token;
		delete data.expiresUtc;
		data.signedIn = true;
	}
	if (path === '/auth/logout' && response.ok) (await cookies()).delete(SESSION_COOKIE);

	return data === null
		? new NextResponse(null, { status: response.status })
		: NextResponse.json(data, { status: response.status });
}

export async function readBody(request: Request): Promise<Record<string, unknown>> {
	try {
		return await request.json();
	} catch {
		return {};
	}
}
