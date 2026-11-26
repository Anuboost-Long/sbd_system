import { forward, readBody } from '@/lib/server-api';

export async function POST(request: Request) {
	return forward('POST', '/customers/search', await readBody(request));
}
