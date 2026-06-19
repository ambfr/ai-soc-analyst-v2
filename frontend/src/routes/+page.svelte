<script>
	let file = null;
	let loading = false;
	let error = null;
	let result = null;

	function handleFileChange(event) {
		file = event.target.files[0];
		error = null;
	}

	async function handleAnalyze() {
		if (!file) {
			error = 'Please choose a log file first.';
			return;
		}

		loading = true;
		error = null;
		result = null;

		const formData = new FormData();
		formData.append('file', file);

		try {
			const response = await fetch('http://localhost:8080/analyze', {
				method: 'POST',
				body: formData
			});

			if (!response.ok) {
				const errBody = await response.json();
				throw new Error(errBody.error || 'Analysis failed');
			}

			result = await response.json();
		} catch (err) {
			error = err.message;
		} finally {
			loading = false;
		}
	}

	// Maps severity to a Tailwind color class, used in the table below.
	function severityColor(severity) {
		switch (severity) {
			case 'critical':
				return 'bg-red-600 text-white';
			case 'high':
				return 'bg-orange-500 text-white';
			case 'medium':
				return 'bg-yellow-400 text-black';
			case 'low':
				return 'bg-blue-400 text-white';
			default:
				return 'bg-gray-200 text-gray-700';
		}
	}
</script>

<main class="max-w-5xl mx-auto p-8">
	<h1 class="text-3xl font-bold mb-2">Watchtower</h1>
	<p class="text-gray-600 mb-6">Upload a network log file to detect and analyze suspicious activity.</p>

	<div class="flex items-center gap-4 mb-6">
		<input
			type="file"
			accept=".log,.txt"
			on:change={handleFileChange}
			class="border border-gray-300 rounded px-3 py-2"
		/>
		<button
			on:click={handleAnalyze}
			disabled={loading}
			class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 disabled:opacity-50"
		>
			{loading ? 'Analyzing...' : 'Analyze'}
		</button>
	</div>

	{#if error}
		<div class="bg-red-100 text-red-700 px-4 py-3 rounded mb-6">{error}</div>
	{/if}

	{#if result}
		<div class="mb-4 text-sm text-gray-600">
			Analyzed <strong>{result.filename}</strong> — {result.total_ips} unique IPs found
		</div>

		<table class="w-full border-collapse">
			<thead>
				<tr class="text-left border-b border-gray-300">
					<th class="py-2 px-3">IP</th>
					<th class="py-2 px-3">Type</th>
					<th class="py-2 px-3">Count</th>
					<th class="py-2 px-3">Severity</th>
					<th class="py-2 px-3">MITRE Technique</th>
				</tr>
			</thead>
			<tbody>
				{#each result.results as ip}
					<tr class="border-b border-gray-200">
						<td class="py-2 px-3 font-mono">{ip.ip}</td>
						<td class="py-2 px-3">{ip.type}</td>
						<td class="py-2 px-3">{ip.count}</td>
						<td class="py-2 px-3">
							<span class="px-2 py-1 rounded text-xs font-semibold {severityColor(ip.severity)}">
								{ip.severity}
							</span>
						</td>
						<td class="py-2 px-3">
							{#each ip.mitre_techniques || [] as t}
								<div class="text-sm">{t.id} — {t.name}</div>
							{/each}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
</main>