'use client';

import { call, errorText } from '@/lib/client';
import { useState, type SyntheticEvent } from 'react';

import { Button, Field, Notice } from './ui';

type Row = Record<string, unknown>;
type Revealed = { cardNumber: string; cardExpiry: string };

const COLUMNS = [
	'id',
	'firstName',
	'lastName',
	'unit',
	'street',
	'suburb',
	'state',
	'postcode',
	'phone',
	'cardMasked',
	'cardNumber',
	'cardExpiry',
	'medicalStatus'
];

export default function Search({ canReveal }: Readonly<{ canReveal: boolean }>) {
	const [criteria, setCriteria] = useState({ firstName: '', lastName: '', phone: '' });
	const [rows, setRows] = useState<Row[] | null>(null);
	const [revealed, setRevealed] = useState<Record<number, Revealed>>({});
	const [error, setError] = useState('');

	async function search(event: SyntheticEvent) {
		event.preventDefault();
		setError('');
		setRevealed({});
		const body = Object.fromEntries(
			Object.entries(criteria).filter(([, value]) => value.trim() !== '')
		);
		const reply = await call('/api/customers/search', body);
		if (!reply.ok) {
			setRows(null);
			return setError(errorText(reply));
		}
		setRows(reply.data as unknown as Row[]);
	}

	async function reveal(id: number) {
		const reply = await call(`/api/customers/${id}/reveal`);
		if (!reply.ok) return setError(errorText(reply));
		setRevealed((current) => ({ ...current, [id]: reply.data as unknown as Revealed }));
	}

	const shown = rows?.length ? COLUMNS.filter((column) => column in rows[0]) : [];

	return (
		<section className="flex flex-col gap-4">
			<form onSubmit={search} className="grid gap-3 sm:grid-cols-4 sm:items-end">
				<Field
					label="First name"
					value={criteria.firstName}
					onChange={(e) => setCriteria({ ...criteria, firstName: e.target.value })}
				/>
				<Field
					label="Last name"
					value={criteria.lastName}
					onChange={(e) => setCriteria({ ...criteria, lastName: e.target.value })}
				/>
				<Field
					label="Phone (+61…)"
					value={criteria.phone}
					onChange={(e) => setCriteria({ ...criteria, phone: e.target.value })}
				/>
				<Button type="submit">Search</Button>
			</form>
			<p className="text-xs text-zinc-500">
				Name or phone is required. End a name or phone with * after at least 3 characters to match a
				prefix. At most 50 rows.
			</p>
			{error && <Notice tone="error">{error}</Notice>}
			{rows && rows.length === 0 && <p className="text-sm text-zinc-600">No customers found.</p>}
			{rows && rows.length > 0 && (
				<div className="overflow-x-auto rounded-md border border-zinc-200">
					<table className="w-full text-left text-sm">
						<thead className="bg-zinc-50 text-zinc-600">
							<tr>
								{shown.map((column) => (
									<th key={column} className="px-3 py-2 font-medium whitespace-nowrap">
										{column}
									</th>
								))}
								{canReveal && <th className="px-3 py-2" />}
							</tr>
						</thead>
						<tbody className="divide-y divide-zinc-100">
							{rows.map((row) => {
								const id = Number(row.id);
								const full = revealed[id];
								const alreadyShown = 'cardNumber' in row;
								return (
									<tr key={id}>
										{shown.map((column) => (
											<td key={column} className="px-3 py-2 whitespace-nowrap">
												{column === 'cardMasked' && full
													? `${full.cardNumber} · ${full.cardExpiry}`
													: String(row[column] ?? '')}
											</td>
										))}
										{canReveal && (
											<td className="px-3 py-2">
												{alreadyShown ? null : full ? (
													<span className="text-xs text-zinc-600">Revealed and logged</span>
												) : (
													<Button secondary type="button" onClick={() => reveal(id)}>
														Reveal card
													</Button>
												)}
											</td>
										)}
									</tr>
								);
							})}
						</tbody>
					</table>
				</div>
			)}
		</section>
	);
}
