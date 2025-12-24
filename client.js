// ============================================
// kaerez/speedtest/client.js
// ============================================

/**
 * KSEC SPEED TEST - Frontend Logic
 * Author: Erez Kalman - KSEC
 * Repo: kaerez/speedtest
 * License: PolyForm Noncommercial 1.0.0 (Requires CLA)
 */

const { useState, useEffect, useRef } = React;

// --- UI Component: Circular Gauge ---
const Gauge = ({ value, label, unit, color }) => {
    const r = 70, c = 2 * Math.PI * r, max = 1000;
    const off = c - (Math.min(value, max) / max) * c;
    const colorHex = color === 'cyan' ? '#22d3ee' : '#10b981';

    return (
        <div className="cyber-border p-6 flex flex-col items-center justify-center w-full">
            <div className="relative w-48 h-48">
                <svg className="transform -rotate-90 w-full h-full">
                    <circle cx="96" cy="96" r={r} stroke="#1f2937" strokeWidth="8" fill="transparent" />
                    <circle cx="96" cy="96" r={r} stroke={colorHex} strokeWidth="8" fill="transparent" strokeDasharray={c} strokeDashoffset={off} strokeLinecap="round" className="transition-all duration-300 ease-out" />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-4xl font-bold mono" style={{color: colorHex}}>{value.toFixed(1)}</span>
                    <span className="text-xs text-gray-500 font-bold tracking-widest">{unit}</span>
                </div>
            </div>
            <div className="mt-2 text-gray-400 text-sm tracking-widest uppercase">{label}</div>
        </div>
    );
};

// --- Main Application ---
const App = () => {
    const [status, setStatus] = useState('IDLE');
    const [data, setData] = useState({ ping: 0, jitter: 0, down: 0, up: 0, meta: { ip: '---', isp: 'Initializing...', colo: '---' } });
    const [logs, setLogs] = useState(['> KSEC SPEED TEST OS LOADED', '> WAITING FOR INPUT...']);
    
    const log = (m) => setLogs(p => [...p.slice(-5), `> ${m}`]);

    // Initial Load - Fetch Metadata
    useEffect(() => {
        fetch('/api/meta')
            .then(r => r.json())
            .then(m => { 
                setData(d => ({...d, meta: m})); 
                log(`CONNECTED: ${m.isp} (${m.colo})`); 
            })
            .catch(e => { 
                log('ERROR: META FETCH FAILED'); 
                console.error(e);
            });
        
        setTimeout(() => lucide.createIcons(), 100);
    }, []);

    const runTest = async () => {
        if(status === 'RUNNING') return;
        setStatus('RUNNING');
        setData(d => ({...d, down: 0, up: 0, ping: 0, jitter: 0}));
        log('INITIATING TEST SEQUENCE...');

        try {
            // 1. PING TEST
            log('MEASURING LATENCY...');
            let pings = [];
            // Run 5 pings
            for(let i=0; i<5; i++) {
                const s = performance.now();
                await fetch('/api/ping');
                pings.push(performance.now() - s);
            }
            const minPing = Math.min(...pings);
            const jitter = Math.abs(pings[0] - pings[pings.length-1]);
            setData(d => ({...d, ping: minPing, jitter}));

            // 2. DOWNLOAD TEST
            log('STARTING DOWNLOAD STREAM...');
            const dlStart = performance.now();
            const dlDuration = 10000; // 10 seconds for real test
            let dlBytes = 0;
            
            // Loop until duration met
            while(performance.now() - dlStart < dlDuration) {
                // Request a 10MB chunk
                const res = await fetch(`/api/down?bytes=${10 * 1024 * 1024}`);
                const reader = res.body.getReader();
                
                while(true) {
                    const {done, value} = await reader.read();
                    if(done) break;
                    dlBytes += value.length;
                    
                    // Update Speed UI
                    const elapsed = (performance.now() - dlStart) / 1000; // Seconds
                    if(elapsed > 0) {
                        const bits = dlBytes * 8;
                        const mbps = bits / (elapsed * 1000 * 1000);
                        setData(d => ({...d, down: mbps}));
                    }
                }
            }

            // 3. UPLOAD TEST
            log('STARTING UPLOAD STREAM...');
            const ulStart = performance.now();
            const ulDuration = 10000; // 10 seconds
            let ulBytes = 0;
            // 1MB Chunk to upload repeatedly
            const chunk = new Uint8Array(1024 * 1024); 

            while(performance.now() - ulStart < ulDuration) {
                // Post the chunk to the worker
                await fetch('/api/up', { method: 'POST', body: chunk });
                ulBytes += chunk.length;
                
                // Update Speed UI
                const elapsed = (performance.now() - ulStart) / 1000;
                if(elapsed > 0) {
                    const bits = ulBytes * 8;
                    const mbps = bits / (elapsed * 1000 * 1000);
                    setData(d => ({...d, up: mbps}));
                }
            }

            setStatus('COMPLETE');
            log('TEST SEQUENCE FINISHED');
        } catch (err) {
            log('CRITICAL ERROR - CHECK CONSOLE');
            console.error(err);
            setStatus('IDLE');
        }
    };

    return (
        <div className="flex flex-col items-center justify-center min-h-screen p-4 max-w-5xl mx-auto w-full">
            <header className="w-full border-b border-gray-800 pb-4 mb-8 flex justify-between items-end">
                <div>
                    <h1 className="text-4xl font-bold text-white tracking-tighter">KSEC <span className="text-emerald-500">SPEED TEST</span></h1>
                    <p className="text-xs text-gray-500 tracking-[0.3em] uppercase mt-1">PolyForm Noncommercial License 1.0.0</p>
                </div>
                <div className="text-right hidden sm:block font-mono text-emerald-500 text-sm">
                    <div className="text-gray-600 text-xs uppercase">CONNECTED AS</div>
                    {data.meta.ip}
                </div>
            </header>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 w-full mb-8">
                <Gauge value={data.down} label="Download" unit="Mbps" color="cyan" />
                <Gauge value={data.up} label="Upload" unit="Mbps" color="emerald" />
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 w-full mb-8">
                <div className="cyber-border p-3 bg-black/50">
                    <div className="text-xs text-gray-500 uppercase flex items-center gap-2"><i data-lucide="activity" className="w-3 h-3"></i> Ping</div>
                    <div className="text-xl font-bold mono text-white">{data.ping.toFixed(0)} <span className="text-xs text-gray-600">ms</span></div>
                </div>
                <div className="cyber-border p-3 bg-black/50">
                    <div className="text-xs text-gray-500 uppercase flex items-center gap-2"><i data-lucide="zap" className="w-3 h-3"></i> Jitter</div>
                    <div className="text-xl font-bold mono text-white">{data.jitter.toFixed(0)} <span className="text-xs text-gray-600">ms</span></div>
                </div>
                <div className="cyber-border p-3 bg-black/50 col-span-2">
                    <div className="text-xs text-gray-500 uppercase flex items-center gap-2"><i data-lucide="server" className="w-3 h-3"></i> Server</div>
                    <div className="text-xl font-bold mono text-white truncate">{data.meta.colo || 'EDGE'} <span className="text-xs text-gray-600 mx-2">//</span> {data.meta.isp}</div>
                </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full">
                <button onClick={runTest} disabled={status === 'RUNNING'} className={`md:col-span-1 cyber-border py-4 font-bold tracking-widest uppercase transition-all duration-300 ${status === 'RUNNING' ? 'bg-gray-900 text-gray-600 cursor-not-allowed' : 'bg-emerald-900/20 hover:bg-emerald-900/40 text-emerald-400'}`}>
                    {status === 'RUNNING' ? 'Testing...' : 'Initialize Test'}
                </button>
                <div className="md:col-span-2 cyber-border bg-black/90 p-3 font-mono text-xs flex flex-col justify-end h-32 overflow-hidden">
                    {logs.map((l, i) => <div key={i} className="text-emerald-500/70 mb-1 border-l-2 border-transparent hover:border-emerald-500 pl-2 transition-all">{l}</div>)}
                </div>
            </div>
            <footer className="mt-12 text-center text-xs text-gray-700 uppercase tracking-widest">
                KSEC SPEED TEST // {new Date().getFullYear()} // Author: Erez Kalman
                <br/><span className="text-emerald-900">Valid CLA Required for Use</span>
            </footer>
        </div>
    );
};

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
