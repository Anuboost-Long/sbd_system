import { forward } from '@/lib/server-api';

export async function POST(_request: Request, { params }: { params: Promise<{ id: string }> }) {
	const { id } = await params;
	if (!/^\d{1,9}$/.test(id)) return new Response(null, { status: 404 });
	return forward('POST', `/customers/${id}/card/reveal`);
}
