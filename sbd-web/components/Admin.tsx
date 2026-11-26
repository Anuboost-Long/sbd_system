'use client';

import { call, errorText } from '@/lib/client';
import { useState, type SyntheticEvent } from 'react';

import { Button, Field, Notice, Select } from './ui';

const ACTIONS = [
	{ value: 'create', label: 'Create user' },
	{ value: 'role', label: 'Change role' },
	{ value: 'disable', label: 'Disable user' },
	{ value: 'password-reset', label: 'Reset password' },
	{ value: 'mfa-reset', label: 'Reset MFA' },
	{ value: 'search-unlock', label: 'Unlock search' }
];
const ROLES = ['Normal', 'Accounting', 'Privileged', 'UserAdmin'];
const NEEDS_APPROVAL = new Set(['create', 'role', 'disable']);
const NEEDS_PASSWORD = new Set(['create', 'password-reset']);
const NEEDS_ROLE = new Set(['create', 'role']);

export default function Admin() {
	const [action, setAction] = useState('create');
	const [form, setForm] = useState({
		userId: '',
		username: '',
		role: 'Normal',
		temporaryPassword: '',
		approvalRef: ''
	});
	const [message, setMessage] = useState<{ tone: 'ok' | 'error'; text: string } | null>(null);
	const set = (field: keyof typeof form) => (e: { target: { value: string } }) =>
		setForm({ ...form, [field]: e.target.value });

	async function submit(event: SyntheticEvent) {
		event.preventDefault();
		const body: Record<string, string> = {};
		if (action === 'create') body.username = form.username;
		else body.userId = form.userId;
		if (NEEDS_ROLE.has(action)) body.role = form.role;
		if (NEEDS_PASSWORD.has(action)) body.temporaryPassword = form.temporaryPassword;
		if (NEEDS_APPROVAL.has(action)) body.approvalRef = form.approvalRef;

		const reply = await call(`/api/admin/${action}`, body);
		setForm({ ...form, temporaryPassword: '' });
		if (!reply.ok) return setMessage({ tone: 'error', text: errorText(reply) });
		if (action === 'create') {
			setForm((current) => ({
				...current,
				userId: String(reply.data?.userId),
				temporaryPassword: ''
			}));
			return setMessage({ tone: 'ok', text: `User created. ID: ${reply.data?.userId}` });
		}
		setMessage({ tone: 'ok', text: 'Done. The change is in the audit log.' });
	}

	return (
		<form onSubmit={submit} className="flex max-w-md flex-col gap-4">
			<Select
				label="Action"
				value={action}
				onChange={(e) => {
					setAction(e.target.value);
					setMessage(null);
				}}
			>
				{ACTIONS.map((item) => (
					<option key={item.value} value={item.value}>
						{item.label}
					</option>
				))}
			</Select>
			{action === 'create' ? (
				<Field label="Username" value={form.username} onChange={set('username')} required />
			) : (
				<Field label="User ID" value={form.userId} onChange={set('userId')} required />
			)}
			{NEEDS_ROLE.has(action) && (
				<Select label="Role" value={form.role} onChange={set('role')}>
					{ROLES.map((role) => (
						<option key={role}>{role}</option>
					))}
				</Select>
			)}
			{NEEDS_PASSWORD.has(action) && (
				<Field
					label="Temporary password"
					type="password"
					value={form.temporaryPassword}
					onChange={set('temporaryPassword')}
					autoComplete="new-password"
					required
				/>
			)}
			{NEEDS_APPROVAL.has(action) && (
				<Field
					label="Manager approval reference"
					value={form.approvalRef}
					onChange={set('approvalRef')}
					required
				/>
			)}
			{message && <Notice tone={message.tone}>{message.text}</Notice>}
			<Button type="submit">Apply</Button>
		</form>
	);
}
