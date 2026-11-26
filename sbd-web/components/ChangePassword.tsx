'use client';

import { call, errorText } from '@/lib/client';
import { useState, type SyntheticEvent } from 'react';

import { Button, Field, Notice } from './ui';

export default function ChangePassword({ onChanged }: Readonly<{ onChanged: () => void }>) {
	const [currentPassword, setCurrentPassword] = useState('');
	const [newPassword, setNewPassword] = useState('');
	const [error, setError] = useState('');

	async function submit(event: SyntheticEvent) {
		event.preventDefault();
		const reply = await call('/api/auth/change-password', { currentPassword, newPassword });
		setCurrentPassword('');
		setNewPassword('');
		if (reply.ok) return onChanged();
		setError(errorText(reply));
	}

	return (
		<form onSubmit={submit} className="flex w-full max-w-sm flex-col gap-4">
			<h1 className="text-xl font-semibold">Change your password</h1>
			<p className="text-sm text-zinc-600">
				A User Admin set a temporary password. Choose a new one to continue (at least 15
				characters).
			</p>
			<Field
				label="Temporary password"
				type="password"
				value={currentPassword}
				onChange={(e) => setCurrentPassword(e.target.value)}
				autoComplete="current-password"
				required
			/>
			<Field
				label="New password"
				type="password"
				value={newPassword}
				onChange={(e) => setNewPassword(e.target.value)}
				autoComplete="new-password"
				required
			/>
			{error && <Notice tone="error">{error}</Notice>}
			<Button type="submit">Change password</Button>
		</form>
	);
}
