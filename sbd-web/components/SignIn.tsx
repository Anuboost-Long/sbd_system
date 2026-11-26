'use client';

import { call, errorText } from '@/lib/client';
import { useState, type SyntheticEvent } from 'react';

import { Button, Field, Notice } from './ui';

type Step = 'password' | 'mfa-setup' | 'mfa';

export default function SignIn({ onSignedIn }: Readonly<{ onSignedIn: () => void }>) {
	const [step, setStep] = useState<Step>('password');
	const [username, setUsername] = useState('');
	const [password, setPassword] = useState('');
	const [code, setCode] = useState('');
	const [ticket, setTicket] = useState('');
	const [manualKey, setManualKey] = useState('');
	const [needsCaptcha, setNeedsCaptcha] = useState(false);
	const [captchaDone, setCaptchaDone] = useState(false);
	const [error, setError] = useState('');

	async function submitPassword() {
		// Demo stand-in for the Cloudflare Turnstile widget: the API still verifies the token on the server.
		const captchaToken = needsCaptcha && captchaDone ? 'demo-turnstile-token' : undefined;
		const reply = await call('/api/auth/login', { username, password, captchaToken });
		if (reply.data?.signedIn) return onSignedIn();
		if (reply.data?.captchaRequired) setNeedsCaptcha(true);
		if (reply.ok && reply.data?.mfaTicket) {
			setTicket(String(reply.data.mfaTicket));
			if (reply.data.mfaSetupRequired) {
				const setup = await call('/api/auth/mfa-setup', { mfaTicket: reply.data.mfaTicket });
				if (!setup.ok) return setError(errorText(setup));
				setManualKey(String(setup.data?.manualKey));
				return setStep('mfa-setup');
			}
			return setStep('mfa');
		}
		setError(errorText(reply));
	}

	async function submitCode() {
		const reply = await call(step === 'mfa-setup' ? '/api/auth/mfa-confirm' : '/api/auth/mfa', {
			mfaTicket: ticket,
			code
		});
		if (reply.data?.signedIn) return onSignedIn();
		setError(errorText(reply));
	}

	async function submit(event: SyntheticEvent) {
		event.preventDefault();
		setError('');
		await (step === 'password' ? submitPassword() : submitCode());
		setPassword('');
		setCode('');
	}

	return (
		<form onSubmit={submit} className="flex w-full max-w-sm flex-col gap-4">
			<h1 className="text-xl font-semibold">Sign in</h1>
			{step === 'password' && (
				<>
					<Field
						label="Username"
						value={username}
						onChange={(e) => setUsername(e.target.value)}
						autoComplete="username"
						required
					/>
					<Field
						label="Password"
						type="password"
						value={password}
						onChange={(e) => setPassword(e.target.value)}
						autoComplete="current-password"
						required
					/>
					{needsCaptcha && (
						<label className="flex items-center gap-2 text-sm">
							<input
								type="checkbox"
								checked={captchaDone}
								onChange={(e) => setCaptchaDone(e.target.checked)}
							/>
							I am not a robot (Turnstile placeholder)
						</label>
					)}
				</>
			)}
			{step === 'mfa-setup' && (
				<>
					<p className="text-sm text-zinc-600">
						Add this key to your authenticator app, then enter the 6-digit code it shows.
					</p>
					<code className="rounded-md bg-zinc-100 px-3 py-2 text-sm tracking-wider">
						{manualKey}
					</code>
				</>
			)}
			{step !== 'password' && (
				<Field
					label="6-digit code"
					inputMode="numeric"
					value={code}
					onChange={(e) => setCode(e.target.value)}
					autoComplete="one-time-code"
					required
				/>
			)}
			{error && <Notice tone="error">{error}</Notice>}
			<Button type="submit">{step === 'password' ? 'Continue' : 'Sign in'}</Button>
		</form>
	);
}
