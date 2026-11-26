export type Reply = { ok: boolean; status: number; data: Record<string, unknown> | null };

export async function call(
	path: string,
	body?: unknown,
	method: 'GET' | 'POST' = 'POST'
): Promise<Reply> {
	const response = await fetch(path, {
		method,
		headers: { 'Content-Type': 'application/json' },
		body: method === 'POST' ? JSON.stringify(body ?? {}) : undefined
	});
	const text = await response.text();
	return { ok: response.ok, status: response.status, data: text ? JSON.parse(text) : null };
}

export function errorText(reply: Reply): string {
	const data = reply.data;
	if (data?.errors)
		return Object.values(data.errors as Record<string, string[]>)
			.flat()
			.join(' ');
	if (data?.error) return String(data.error);
	if (reply.status === 403) return 'You do not have permission to do this.';
	if (reply.status === 429) return 'Too many requests. Try again later.';
	return 'Something went wrong. Try again.';
}
