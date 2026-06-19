<script>
	import { onMount, onDestroy } from 'svelte';
	import Chart from 'chart.js/auto';

	let file = null;
	let loading = false;
	let error = null;
	let result = null;
	let expandedIp = null;

	let severityCanvas;
	let trafficCanvas;
	let severityChart = null;
	let trafficChart = null;

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
		expandedIp = null;

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

			// Charts need the canvas elements to exist in the DOM first, and
			// Svelte updates the DOM asynchronously after `result` changes.
			// requestAnimationFrame waits for the next paint, ensuring the
			// {#if result} block has actually rendered before we try to draw.
			requestAnimationFrame(renderCharts);
		} catch (err) {
			error = err.message;
		} finally {
			loading = false;
		}
	}

	function toggleExpand(ip) {
		expandedIp = expandedIp === ip ? null : ip;
	}

	function severityBar(severity) {
		switch (severity) {
			case 'critical': return 'bg-red-500';
			case 'high': return 'bg-orange-500';
			case 'medium': return 'bg-amber-400';
			case 'low': return 'bg-blue-500';
			default: return 'bg-slate-700';
		}
	}

	function severityBadge(severity) {
		switch (severity) {
			case 'critical': return 'bg-red-950 text-red-400 border-red-500 shadow-[2px_2px_0_0_#7F1D1D]';
			case 'high': return 'bg-orange-950 text-orange-400 border-orange-500 shadow-[2px_2px_0_0_#7C2D12]';
			case 'medium': return 'bg-amber-950 text-amber-400 border-amber-500 shadow-[2px_2px_0_0_#78350F]';
			case 'low': return 'bg-blue-950 text-blue-400 border-blue-500 shadow-[2px_2px_0_0_#1E3A8A]';
			default: return 'bg-slate-800 text-slate-500 border-slate-600 shadow-[2px_2px_0_0_#11151D]';
		}
	}

	$: severityCounts = result
		? {
				critical: result.results.filter((r) => r.severity === 'critical').length,
				high: result.results.filter((r) => r.severity === 'high').length,
				medium: result.results.filter((r) => r.severity === 'medium').length,
				low: result.results.filter((r) => r.severity === 'low').length,
				none: result.results.filter((r) => r.severity === 'none').length,
				external: result.results.filter((r) => r.type === 'external').length,
				internal: result.results.filter((r) => r.type === 'internal').length
			}
		: null;

	function destroyCharts() {
		if (severityChart) {
			severityChart.destroy();
			severityChart = null;
		}
		if (trafficChart) {
			trafficChart.destroy();
			trafficChart = null;
		}
	}

	function renderCharts() {
		if (!result || !severityCanvas || !trafficCanvas) return;

		// Destroy any previous chart instances before redrawing — otherwise
		// Chart.js throws "canvas already in use" errors on re-analysis.
		destroyCharts();

		severityChart = new Chart(severityCanvas, {
			type: 'bar',
			data: {
				labels: ['critical', 'high', 'medium', 'low', 'none'],
				datasets: [
					{
						data: [
							severityCounts.critical,
							severityCounts.high,
							severityCounts.medium,
							severityCounts.low,
							severityCounts.none
						],
						backgroundColor: ['#EF4444', '#F97316', '#FBBF24', '#3B82F6', '#475569'],
						borderRadius: 3,
						barThickness: 28
					}
				]
			},
			options: {
				responsive: true,
				maintainAspectRatio: false,
				plugins: { legend: { display: false } },
				scales: {
					x: {
						ticks: { color: '#8B96A8', font: { size: 11, family: 'IBM Plex Mono' } },
						grid: { display: false }
					},
					y: {
						ticks: { color: '#5B6577', stepSize: 1, font: { size: 11 } },
						grid: { color: '#1C2230' },
						beginAtZero: true
					}
				}
			}
		});

		trafficChart = new Chart(trafficCanvas, {
			type: 'doughnut',
			data: {
				labels: ['external', 'internal'],
				datasets: [
					{
						data: [severityCounts.external, severityCounts.internal],
						backgroundColor: ['#3B82F6', '#475569'],
						borderColor: '#0B0E14',
						borderWidth: 3
					}
				]
			},
			options: {
				responsive: true,
				maintainAspectRatio: false,
				cutout: '65%',
				plugins: {
					legend: {
						position: 'bottom',
						labels: { color: '#8B96A8', font: { size: 11 }, boxWidth: 10, padding: 12 }
					}
				}
			}
		});
	}

	onDestroy(() => {
		destroyCharts();
	});
</script>

<div
	class="min-h-screen bg-[#0B0E14] bg-[length:32px_32px] text-slate-200"
	style="background-image: linear-gradient(#161B26 1px, transparent 1px), linear-gradient(90deg, #161B26 1px, transparent 1px);"
>
	<main class="max-w-5xl mx-auto px-8 py-12">
		<div class="flex items-baseline gap-3 mb-2">
			<h1 class="font-mono text-4xl font-semibold text-white tracking-tight">Watchtower</h1>
			<span class="text-xs text-slate-500 uppercase tracking-wider">AI-powered SOC log analysis</span>
		</div>
		<p class="text-sm text-slate-400 mb-10">Upload a network log file to detect and explain suspicious activity.</p>

		<div class="flex items-center gap-4 mb-8">
			<label class="relative cursor-pointer">
				<input
					type="file"
					accept=".log,.txt"
					on:change={handleFileChange}
					class="absolute inset-0 opacity-0 cursor-pointer"
				/>
				<span class="block bg-[#11151D] border-2 border-slate-200 text-slate-200 text-sm px-4 py-2.5 shadow-[3px_3px_0_0_#E8EBF0] active:translate-x-[3px] active:translate-y-[3px] active:shadow-none transition-[transform,box-shadow] duration-75">
					{file ? file.name : 'Choose log file'}
				</span>
			</label>
			<button
				on:click={handleAnalyze}
				disabled={loading}
				class="bg-blue-600 border-2 border-slate-200 text-white text-sm font-medium px-5 py-2.5 shadow-[3px_3px_0_0_#1d4ed8] active:translate-x-[3px] active:translate-y-[3px] active:shadow-none disabled:opacity-40 disabled:cursor-not-allowed disabled:active:translate-x-0 disabled:active:translate-y-0 disabled:active:shadow-[3px_3px_0_0_#1d4ed8] transition-[transform,box-shadow] duration-75"
			>
				{loading ? 'Analyzing…' : 'Analyze'}
			</button>
		</div>

		{#if error}
			<div class="bg-red-950 border border-red-900 text-red-400 text-sm px-4 py-3 rounded-lg mb-8">
				{error}
			</div>
		{/if}

		{#if result}
			<div class="flex items-center justify-between mb-4">
				<div class="text-sm text-slate-500">
					<span class="text-slate-300 font-medium">{result.filename}</span> · {result.total_ips} unique IPs
				</div>
			</div>

			<div class="grid grid-cols-4 gap-2.5 mb-6">
				<div class="bg-[#11151D] border border-[#1C2230] rounded-lg px-3.5 py-2.5">
					<div class="text-[11px] text-slate-500 mb-1">total ips</div>
					<div class="font-mono text-xl text-slate-100">{result.total_ips}</div>
				</div>
				<div class="bg-[#11151D] border border-[#1C2230] rounded-lg px-3.5 py-2.5">
					<div class="text-[11px] text-slate-500 mb-1">critical</div>
					<div class="font-mono text-xl text-red-500">{severityCounts.critical}</div>
				</div>
				<div class="bg-[#11151D] border border-[#1C2230] rounded-lg px-3.5 py-2.5">
					<div class="text-[11px] text-slate-500 mb-1">high</div>
					<div class="font-mono text-xl text-orange-500">{severityCounts.high}</div>
				</div>
				<div class="bg-[#11151D] border border-[#1C2230] rounded-lg px-3.5 py-2.5">
					<div class="text-[11px] text-slate-500 mb-1">external</div>
					<div class="font-mono text-xl text-slate-100">{severityCounts.external}</div>
				</div>
			</div>

			<div class="grid grid-cols-2 gap-2.5 mb-6">
				<div class="bg-[#11151D] border border-[#1C2230] rounded-lg p-4">
					<div class="text-[11px] text-slate-500 mb-3">severity distribution</div>
					<div class="h-44">
						<canvas bind:this={severityCanvas}></canvas>
					</div>
				</div>
				<div class="bg-[#11151D] border border-[#1C2230] rounded-lg p-4">
					<div class="text-[11px] text-slate-500 mb-3">traffic split</div>
					<div class="h-44">
						<canvas bind:this={trafficCanvas}></canvas>
					</div>
				</div>
			</div>

			<div class="flex flex-col gap-px bg-[#1C2230] rounded-lg overflow-hidden border border-[#1C2230]">
				{#each result.results as ip}
					<div>
						<button
							on:click={() => toggleExpand(ip.ip)}
							class="w-full flex items-center gap-3.5 bg-[#11151D] hover:bg-[#141925] px-3.5 py-2.5 text-left transition-colors"
						>
							<span class="w-[3px] self-stretch rounded-full {severityBar(ip.severity)}"></span>
							<span class="flex-1 font-mono text-sm {ip.flags && ip.flags.length ? 'text-slate-100' : 'text-slate-500'}">
								{ip.ip}
							</span>
							<span class="text-xs text-slate-500 w-16">{ip.type}</span>
							<span class="font-mono text-xs text-slate-500 w-10">×{ip.count}</span>
							<span class="text-[11px] font-medium px-2 py-0.5 border {severityBadge(ip.severity)}">
								{ip.severity}
							</span>
							<i
								class="ti ti-chevron-down text-slate-600 text-base transition-transform {expandedIp === ip.ip ? 'rotate-180' : ''}"
							></i>
						</button>

						{#if expandedIp === ip.ip}
							<div class="bg-[#0E1119] px-3.5 py-3 pl-10 border-t border-[#1C2230] text-xs text-slate-400 leading-relaxed">
								{#if ip.mitre_techniques && ip.mitre_techniques.length}
									{#each ip.mitre_techniques as t}
										<div class="mb-2">
											<span class="font-mono text-orange-400">{t.id} — {t.name}</span>
											<span class="text-slate-600"> · {t.tactic}</span>
										</div>
									{/each}
								{/if}

								{#if ip.llm_explanation && ip.llm_explanation.generated}
									<p class="mb-2">{ip.llm_explanation.explanation}</p>
									<p class="text-slate-100">
										<i class="ti ti-arrow-right text-xs mr-1"></i>{ip.llm_explanation.recommended_action}
									</p>
								{:else}
									<p class="text-slate-600">No suspicious activity detected for this IP.</p>
								{/if}

								{#if ip.threat_intel && ip.threat_intel.checked}
									<div class="mt-3 pt-2 border-t border-[#1C2230] flex gap-4 text-slate-600">
										<span>abuse score: <span class="text-slate-400">{ip.threat_intel.abuse_score}/100</span></span>
										{#if ip.threat_intel.country_code}
											<span>country: <span class="text-slate-400">{ip.threat_intel.country_code}</span></span>
										{/if}
										{#if ip.threat_intel.isp}
											<span>isp: <span class="text-slate-400">{ip.threat_intel.isp}</span></span>
										{/if}
									</div>
								{/if}
							</div>
						{/if}
					</div>
				{/each}
			</div>
		{/if}
	</main>
</div>