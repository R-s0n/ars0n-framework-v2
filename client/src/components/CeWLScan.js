import React, { useState, useEffect } from 'react'

const CeWLScan = ({ activeTarget }) => {
    const [scanStatus, setScanStatus] = useState(null)
    const [scanId, setScanId] = useState(null)
    const [words, setWords] = useState([])
    const [shuffleDNSResults, setShuffleDNSResults] = useState([])
    const [error, setError] = useState(null)
    const [debug, setDebug] = useState([])

    const addDebug = (message) => {
        setDebug(prev => [...prev, `${new Date().toISOString()} - ${message}`])
    }

    useEffect(() => {
        if (scanId) {
            addDebug(`Starting interval with scanId: ${scanId}`)
            const interval = setInterval(async () => {
                try {
                    addDebug('Fetching CeWL scan status...')
                    const response = await fetch(`/api/cewl/${scanId}`)
                    if (!response.ok) throw new Error('Failed to fetch scan status')
                    const data = await response.json()
                    addDebug(`CeWL scan status: ${data.status}`)
                    setScanStatus(data.status)
                    
                    if (data.result) {
                        const wordList = data.result.split('\n').filter(word => word.trim() !== '')
                        addDebug(`Found ${wordList.length} words`)
                        setWords(wordList)
                    }

                    if (data.status === 'success' && activeTarget?.id) {
                        addDebug('CeWL scan successful, fetching ShuffleDNS results...')
                        const shuffleResponse = await fetch(`/api/scope-targets/${activeTarget.id}/shufflednscustom-scans`)
                        if (!shuffleResponse.ok) {
                            addDebug(`Failed to fetch ShuffleDNS results: ${shuffleResponse.status}`)
                            throw new Error('Failed to fetch ShuffleDNS results')
                        }
                        const shuffleData = await shuffleResponse.json()
                        addDebug(`Got ${shuffleData.length} ShuffleDNS scans`)
                        
                        if (shuffleData.length > 0) {
                            const latestScan = shuffleData[0]
                            addDebug(`Latest ShuffleDNS scan status: ${latestScan.status}`)
                            if (latestScan.result) {
                                const subdomains = latestScan.result.split('\n').filter(line => line.trim() !== '')
                                addDebug(`Found ${subdomains.length} subdomains`)
                                setShuffleDNSResults(subdomains)
                            } else {
                                addDebug('No results in latest ShuffleDNS scan')
                            }
                        }
                    }
                } catch (err) {
                    addDebug(`Error: ${err.message}`)
                    setError(err.message)
                }
            }, 2000)
            return () => clearInterval(interval)
        }
    }, [scanId, activeTarget])

    const startScan = async () => {
        if (!activeTarget?.scope_target) {
            setError('No target selected')
            return
        }

        try {
            const domain = activeTarget.scope_target.replace(/^\*\./, '')
            addDebug(`Starting scan for domain: ${domain}`)
            const response = await fetch('/api/cewl/run', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ fqdn: domain })
            })

            if (!response.ok) throw new Error('Failed to start scan')
            const data = await response.json()
            addDebug(`Scan started with ID: ${data.scan_id}`)
            setScanId(data.scan_id)
            setScanStatus('pending')
            setError(null)
        } catch (err) {
            addDebug(`Error starting scan: ${err.message}`)
            setError(err.message)
        }
    }

    return (
        <div>
            <h2>CeWL Scan</h2>
            <button onClick={startScan} disabled={!activeTarget || scanStatus === 'pending'}>
                {scanStatus === 'pending' ? 'Scanning...' : 'Start Scan'}
            </button>
            {error && <div className="error">{error}</div>}
            
            {words.length > 0 && (
                <div>
                    <h3>Words Found ({words.length})</h3>
                    <div className="word-list">
                        {words.map((word, index) => (
                            <div key={index} className="word-item">{word}</div>
                        ))}
                    </div>
                </div>
            )}

            {shuffleDNSResults.length > 0 && (
                <div>
                    <h3>Discovered Subdomains ({shuffleDNSResults.length})</h3>
                    <div className="subdomain-list">
                        {shuffleDNSResults.map((subdomain, index) => (
                            <div key={index} className="subdomain-item">{subdomain}</div>
                        ))}
                    </div>
                </div>
            )}

            <div style={{ marginTop: '20px', padding: '10px', background: '#f5f5f5', borderRadius: '4px' }}>
                <h4>Debug Log</h4>
                <pre style={{ maxHeight: '200px', overflow: 'auto' }}>
                    {debug.map((msg, i) => <div key={i}>{msg}</div>)}
                </pre>
            </div>
        </div>
    )
}

export default CeWLScan 