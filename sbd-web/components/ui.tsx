import type { ComponentProps, ReactNode } from 'react';

export function Field({ label, ...input }: Readonly<{ label: string } & ComponentProps<'input'>>) {
	return (
		<label className="flex flex-col gap-1 text-sm">
			<span className="text-zinc-600">{label}</span>
			<input
				{...input}
				className="h-10 rounded-md border border-zinc-300 bg-white px-3 text-zinc-900 outline-none focus-visible:ring-2 focus-visible:ring-emerald-600"
			/>
		</label>
	);
}

export function Select({
	label,
	children,
	...select
}: Readonly<{ label: string; children: ReactNode } & ComponentProps<'select'>>) {
	return (
		<label className="flex flex-col gap-1 text-sm">
			<span className="text-zinc-600">{label}</span>
			<select
				{...select}
				className="h-10 rounded-md border border-zinc-300 bg-white px-3 text-zinc-900 outline-none focus-visible:ring-2 focus-visible:ring-emerald-600"
			>
				{children}
			</select>
		</label>
	);
}

export function Button({
	secondary,
	...button
}: Readonly<{ secondary?: boolean } & ComponentProps<'button'>>) {
	return (
		<button
			{...button}
			className={
				'h-10 rounded-md px-4 text-sm font-medium outline-none focus-visible:ring-2 focus-visible:ring-emerald-600 disabled:opacity-50 ' +
				(secondary
					? 'border border-zinc-300 bg-white text-zinc-800 hover:bg-zinc-50'
					: 'bg-emerald-700 text-white hover:bg-emerald-800')
			}
		/>
	);
}

export function Notice({
	tone,
	children
}: Readonly<{ tone: 'error' | 'ok'; children: ReactNode }>) {
	return (
		<p
			role={tone === 'error' ? 'alert' : 'status'}
			className={
				'rounded-md border px-3 py-2 text-sm ' +
				(tone === 'error'
					? 'border-red-200 bg-red-50 text-red-800'
					: 'border-emerald-200 bg-emerald-50 text-emerald-800')
			}
		>
			{children}
		</p>
	);
}
