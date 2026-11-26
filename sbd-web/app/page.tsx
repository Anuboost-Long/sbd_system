'use client';

import Admin from '@/components/Admin';
import ChangePassword from '@/components/ChangePassword';
import Search from '@/components/Search';
import SignIn from '@/components/SignIn';
import { Button } from '@/components/ui';
import { call } from '@/lib/client';
import { useCallback, useEffect, useState } from 'react';

type Me = { username: string; role: string; mustChangePassword: boolean; permissions: string[] };

export default function Home() {
	const [me, setMe] = useState<Me | null>(null);
	const [ready, setReady] = useState(false);

	const refresh = useCallback(async () => {
		const reply = await call('/api/auth/me', undefined, 'GET');
		setMe(reply.ok ? (reply.data as unknown as Me) : null);
		setReady(true);
	}, []);

	useEffect(() => {
		void refresh();
	}, [refresh]);

	async function signOut() {
		await call('/api/auth/logout');
		setMe(null);
	}

	if (!ready) return null;

	if (!me)
		return (
			<main className="flex flex-1 items-center justify-center p-6">
				<SignIn onSignedIn={refresh} />
			</main>
		);

	if (me.mustChangePassword)
		return (
			<main className="flex flex-1 items-center justify-center p-6">
				<ChangePassword onChanged={refresh} />
			</main>
		);

	const can = (permission: string) => me.permissions.includes(permission);

	return (
		<main className="mx-auto flex w-full max-w-7xl flex-1 flex-col gap-8 p-6">
			<header className="flex items-center justify-between border-b border-zinc-200 pb-4">
				<div>
					<h1 className="text-lg font-semibold">
						{can('customer.search') ? 'Customer search' : 'User administration'}
					</h1>
					<p className="text-sm text-zinc-600">
						{me.username} · <span className="font-medium text-emerald-800">{me.role}</span>
					</p>
				</div>
				<Button secondary onClick={signOut}>
					Sign out
				</Button>
			</header>
			{can('customer.search') && <Search canReveal={can('customer.card.reveal')} />}
			{can('user.create') && <Admin />}
		</main>
	);
}
