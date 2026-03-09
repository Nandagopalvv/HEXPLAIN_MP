import React, { useState } from 'react';
import axios from 'axios';
import { Upload, FileCode, MessageSquare, Terminal, Cpu, Shield, X, AlertTriangle, CheckCircle, Download, Bug } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import SyntaxHighlighter from 'react-syntax-highlighter';
import { atomOneDark } from 'react-syntax-highlighter/dist/esm/styles/hljs';
import ReactMarkdown from 'react-markdown';
import './App.css';

const API_BASE = "http://localhost:8000";

function App() {
    const [file, setFile] = useState(null);
    const [uploadedPath, setUploadedPath] = useState(null);
    const [analyzing, setAnalyzing] = useState(false);
    const [functions, setFunctions] = useState({});
    const [selectedFunction, setSelectedFunction] = useState(null);
    const [chatOpen, setChatOpen] = useState(true);

    // Security Analysis State
    const [securityReport, setSecurityReport] = useState(null);
    const [showSecurity, setShowSecurity] = useState(false);
    const [analyzingSecurity, setAnalyzingSecurity] = useState(false);

    // Program Summary State
    const [summaryReport, setSummaryReport] = useState(null);
    const [showSummary, setShowSummary] = useState(false);
    const [analyzingSummary, setAnalyzingSummary] = useState(false);

    // Malware Analysis State
    const [malwareReport, setMalwareReport] = useState(null);
    const [showMalware, setShowMalware] = useState(false);
    const [analyzingMalware, setAnalyzingMalware] = useState(false);

    // Upload Handler
    const handleUpload = async (e) => {
        const uploadedFile = e.target.files[0];
        if (!uploadedFile) return;

        setFile(uploadedFile);
        setAnalyzing(true);
        setSecurityReport(null);
        setSummaryReport(null);

        // 1. Upload
        const formData = new FormData();
        formData.append('file', uploadedFile);

        try {
            const uploadRes = await axios.post(`${API_BASE}/upload`, formData);
            const filePath = uploadRes.data.path;
            setUploadedPath(filePath);

            // 2. Analyze
            const analyzeRes = await axios.post(`${API_BASE}/analyze`, { binary_path: filePath });
            setFunctions(analyzeRes.data.functions);

            // Select first function by default
            const funcNames = Object.keys(analyzeRes.data.functions);
            if (funcNames.length > 0) setSelectedFunction(funcNames[0]);

        } catch (err) {
            console.error("Error:", err);
            const msg = err.response?.data?.detail || err.message || "Analysis failed";
            alert(`Analysis failed: ${msg}`);
        } finally {
            setAnalyzing(false);
        }
    };

    const handleSecurityCheck = async () => {
        if (!uploadedPath) return;
        setAnalyzingSecurity(true);
        setShowSecurity(true);
        try {
            const res = await axios.post(`${API_BASE}/analyze_security`, { binary_path: uploadedPath });
            setSecurityReport(res.data);
        } catch (err) {
            console.error(err);
            alert("Security analysis failed");
            setShowSecurity(false);
        } finally {
            setAnalyzingSecurity(false);
        }
    };

    const handleProgramSummary = async () => {
        if (!uploadedPath) return;
        setAnalyzingSummary(true);
        setShowSummary(true);
        try {
            const res = await axios.post(`${API_BASE}/explain_program`, { binary_path: uploadedPath });
            setSummaryReport(res.data.summary);
        } catch (err) {
            console.error(err);
            alert("Program summary failed");
            setShowSummary(false);
        } finally {
            setAnalyzingSummary(false);
        }
    };

    const handleMalwareScan = async () => {
        if (!uploadedPath) return;
        setAnalyzingMalware(true);
        setShowMalware(true);
        try {
            const res = await axios.post(`${API_BASE}/analyze_malware`, { binary_path: uploadedPath });
            setMalwareReport(res.data);
        } catch (err) {
            console.error(err);
            alert("Malware analysis failed");
            setShowMalware(false);
        } finally {
            setAnalyzingMalware(false);
        }
    };

    return (
        <div className="app-container">
            {/* Sidebar */}
            <aside className="sidebar">
                <div className="logo">
                    <Cpu className="icon-accent" /> Hexplain
                </div>

                <div className="upload-section">
                    <label className="upload-btn">
                        <Upload size={16} /> Load Binary
                        <input type="file" onChange={handleUpload} style={{ display: 'none' }} />
                    </label>
                    {file && (
                        <div className="file-actions">
                            <div className="file-info">{file.name}</div>
                            <button className="security-btn" onClick={handleSecurityCheck}>
                                <Shield size={14} /> Security Check
                            </button>
                            <button className="summary-btn" onClick={handleProgramSummary} style={{ marginTop: '8px' }}>
                                <FileCode size={14} /> Program Summary
                            </button>
                            <button className="malware-btn" onClick={handleMalwareScan} style={{ marginTop: '8px' }}>
                                <Bug size={14} /> Malware Scan
                            </button>
                        </div>
                    )}
                </div>

                <div className="functions-list">
                    <h3>Functions</h3>
                    {analyzing ? (
                        <div className="loading">Analyzing...</div>
                    ) : (
                        <ul>
                            {Object.keys(functions).map(fn => (
                                <li
                                    key={fn}
                                    className={selectedFunction === fn ? 'active' : ''}
                                    onClick={() => setSelectedFunction(fn)}
                                >
                                    <Terminal size={14} /> {fn}
                                </li>
                            ))}
                            {Object.keys(functions).length === 0 && !analyzing && <li className="empty">No functions loaded</li>}
                        </ul>
                    )}
                </div>
            </aside>

            {/* Main Content */}
            <main className="main-content">
                {selectedFunction ? (
                    <div className="code-view">
                        <header>
                            <h2>{selectedFunction}</h2>
                        </header>
                        <div className="editor-container">
                            <SyntaxHighlighter
                                language="c"
                                style={atomOneDark}
                                customStyle={{ background: 'transparent', fontSize: '14px' }}
                                showLineNumbers={true}
                            >
                                {functions[selectedFunction] || "// No code"}
                            </SyntaxHighlighter>
                        </div>
                    </div>
                ) : (
                    <div className="placeholder">
                        <Cpu size={64} opacity={0.2} />
                        <p>Upload a binary to start reverse engineering</p>
                    </div>
                )}
            </main>

            {/* Chat Panel */}
            <ChatPanel open={chatOpen} toggle={() => setChatOpen(!chatOpen)} />

            {/* Security Modal */}
            <AnimatePresence>
                {showSecurity && (
                    <SecurityModal
                        report={securityReport}
                        loading={analyzingSecurity}
                        close={() => setShowSecurity(false)}
                    />
                )}
                {showSummary && (
                    <ProgramSummaryModal
                        summary={summaryReport}
                        loading={analyzingSummary}
                        close={() => setShowSummary(false)}
                    />
                )}
                {showMalware && (
                    <MalwareModal
                        report={malwareReport}
                        loading={analyzingMalware}
                        close={() => setShowMalware(false)}
                    />
                )}
            </AnimatePresence>
        </div>
    );
}

function downloadFile(content, filename) {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function generateSecurityReportText(report) {
    const lines = [];
    const timestamp = new Date().toLocaleString();
    lines.push('═══════════════════════════════════════════════════');
    lines.push('           HEXPLAIN — SECURITY ANALYSIS REPORT');
    lines.push('═══════════════════════════════════════════════════');
    lines.push(`Generated: ${timestamp}`);
    lines.push('');

    // AI Assessment
    if (report.explanation) {
        lines.push('───────────────────────────────────────────────────');
        lines.push('🔍 SECURITY ASSESSMENT (AI-Generated)');
        lines.push('───────────────────────────────────────────────────');
        lines.push(report.explanation);
        lines.push('');
    }

    // Mitigations
    lines.push('───────────────────────────────────────────────────');
    lines.push('🛡️  MITIGATIONS');
    lines.push('───────────────────────────────────────────────────');
    for (const [key, val] of Object.entries(report.mitigations || {})) {
        const status = val === true ? '✅ Enabled' : val === false ? '❌ Disabled' : `⚠️  ${val}`;
        lines.push(`  ${key.padEnd(12)} ${status}`);
    }
    lines.push('');

    // Flaws
    lines.push('───────────────────────────────────────────────────');
    lines.push('⚠️  POTENTIAL FLAWS');
    lines.push('───────────────────────────────────────────────────');
    if (report.flaws && report.flaws.length > 0) {
        report.flaws.forEach(f => lines.push(`  • ${f}`));
    } else {
        lines.push('  ✅ No obvious flaws detected.');
    }
    lines.push('');

    // Vulnerable Call Sites
    if (report.vulnerable_call_sites && report.vulnerable_call_sites.length > 0) {
        lines.push('───────────────────────────────────────────────────');
        lines.push('📍 VULNERABLE CALL SITES');
        lines.push('───────────────────────────────────────────────────');
        report.vulnerable_call_sites.forEach(site => {
            lines.push(`  Function: ${site.function} | Line: ${site.line}`);
            lines.push(`  Danger:   ${site.dangerous_call}()`);
            lines.push(`  Code:     ${site.context}`);
            lines.push('');
        });
    }

    // Fortified Functions
    if (report.fortified_functions && report.fortified_functions.length > 0) {
        lines.push('───────────────────────────────────────────────────');
        lines.push('✅ FORTIFIED FUNCTIONS (FORTIFY_SOURCE)');
        lines.push('───────────────────────────────────────────────────');
        report.fortified_functions.forEach(fn => lines.push(`  • ${fn}`));
        lines.push('');
    }

    // Known CVEs
    if (report.known_cves && report.known_cves.length > 0) {
        lines.push('───────────────────────────────────────────────────');
        lines.push('🗃️  KNOWN CVEs');
        lines.push('───────────────────────────────────────────────────');
        report.known_cves.forEach(cve => {
            lines.push(`  ${cve.cve_id} [${cve.severity}]`);
            lines.push(`  Library: ${cve.library}`);
            lines.push(`  ${cve.description}`);
            lines.push('');
        });
    }

    // Linked Libraries
    if (report.linked_libraries && report.linked_libraries.length > 0) {
        lines.push('───────────────────────────────────────────────────');
        lines.push('📦 LINKED LIBRARIES');
        lines.push('───────────────────────────────────────────────────');
        report.linked_libraries.forEach(lib => lines.push(`  • ${lib}`));
        lines.push('');
    }

    lines.push('═══════════════════════════════════════════════════');
    lines.push('              End of Report — Hexplain');
    lines.push('═══════════════════════════════════════════════════');
    return lines.join('\n');
}

function generateSummaryReportText(summary) {
    const lines = [];
    const timestamp = new Date().toLocaleString();
    lines.push('═══════════════════════════════════════════════════');
    lines.push('          HEXPLAIN — PROGRAM SUMMARY REPORT');
    lines.push('═══════════════════════════════════════════════════');
    lines.push(`Generated: ${timestamp}`);
    lines.push('');
    lines.push(summary);
    lines.push('');
    lines.push('═══════════════════════════════════════════════════');
    lines.push('              End of Report — Hexplain');
    lines.push('═══════════════════════════════════════════════════');
    return lines.join('\n');
}

function SecurityModal({ report, loading, close }) {
    const severityColor = (sev) => {
        const s = (sev || '').toUpperCase();
        if (s === 'CRITICAL') return '#ff4444';
        if (s === 'HIGH') return '#ff8800';
        if (s === 'MEDIUM') return '#ffcc00';
        if (s === 'LOW') return '#44cc44';
        return '#888';
    };

    const handleDownload = () => {
        if (!report) return;
        const text = generateSecurityReportText(report);
        downloadFile(text, `hexplain_security_report_${Date.now()}.txt`);
    };

    return (
        <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            onClick={close}
        >
            <motion.div
                className="modal-content modal-wide"
                initial={{ y: 50, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 50, opacity: 0 }}
                onClick={e => e.stopPropagation()}
            >
                <div className="modal-header">
                    <h3><Shield size={20} /> Security Analysis</h3>
                    <div className="modal-header-actions">
                        {report && !loading && (
                            <button className="download-btn" onClick={handleDownload} title="Download Report">
                                <Download size={16} /> Download
                            </button>
                        )}
                        <button className="close-btn" onClick={close}><X size={18} /></button>
                    </div>
                </div>

                <div className="modal-body">
                    {loading ? (
                        <div className="loading-state">
                            <div className="spinner"></div>
                            <p>Running comprehensive security scan...</p>
                        </div>
                    ) : report ? (
                        <div className="report-container">
                            {/* AI Security Assessment */}
                            {report.explanation && (
                                <div className="section summary">
                                    <h4>🔍 Security Assessment</h4>
                                    <div className="security-summary">
                                        <ReactMarkdown>{report.explanation}</ReactMarkdown>
                                    </div>
                                </div>
                            )}

                            {/* Mitigations Grid */}
                            <div className="section mitigations">
                                <h4>🛡️ Mitigations</h4>
                                <div className="mitigation-grid">
                                    {Object.entries(report.mitigations).map(([key, val]) => (
                                        <div key={key} className={`mitigation-card ${val === true || val === 'Full' ? 'safe' : val === false ? 'danger' : 'warn'}`}>
                                            <div className="status-icon">
                                                {val === true || val === 'Full' ? <CheckCircle size={16} /> : <AlertTriangle size={16} />}
                                            </div>
                                            <div className="mitigation-name">{key}</div>
                                            <div className="mitigation-status">{val === true ? 'Enabled' : val === false ? 'Disabled' : String(val)}</div>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Potential Flaws */}
                            <div className="section flaws">
                                <h4>⚠️ Potential Flaws</h4>
                                {report.flaws.length === 0 ? (
                                    <div className="empty-flaws"><CheckCircle size={14} /> No obvious flaws detected.</div>
                                ) : (
                                    <ul className="flaws-list">
                                        {report.flaws.map((flaw, i) => (
                                            <li key={i}><AlertTriangle size={14} className="icon-danger" /> {flaw}</li>
                                        ))}
                                    </ul>
                                )}
                            </div>

                            {/* Vulnerable Call Sites */}
                            {report.vulnerable_call_sites && report.vulnerable_call_sites.length > 0 && (
                                <div className="section call-sites">
                                    <h4>📍 Vulnerable Call Sites</h4>
                                    <div className="call-sites-list">
                                        {report.vulnerable_call_sites.map((site, i) => (
                                            <div key={i} className="call-site-card">
                                                <div className="call-site-header">
                                                    <span className="call-site-func">{site.function}</span>
                                                    <span className="call-site-line">Line {site.line}</span>
                                                </div>
                                                <div className="call-site-danger">
                                                    <AlertTriangle size={12} /> {site.dangerous_call}()
                                                </div>
                                                <code className="call-site-code">{site.context}</code>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Fortified Functions */}
                            {report.fortified_functions && report.fortified_functions.length > 0 && (
                                <div className="section fortified">
                                    <h4>✅ Fortified Functions (FORTIFY_SOURCE)</h4>
                                    <div className="fortified-list">
                                        {report.fortified_functions.map((fn, i) => (
                                            <span key={i} className="fortified-badge">
                                                <CheckCircle size={12} /> {fn}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Known CVEs */}
                            {report.known_cves && report.known_cves.length > 0 && (
                                <div className="section cves">
                                    <h4>🗃️ Known CVEs</h4>
                                    <div className="cve-list">
                                        {report.known_cves.map((cve, i) => (
                                            <div key={i} className="cve-card">
                                                <div className="cve-header">
                                                    <span className="cve-id">{cve.cve_id}</span>
                                                    <span className="cve-severity" style={{ background: severityColor(cve.severity) }}>
                                                        {cve.severity}
                                                    </span>
                                                </div>
                                                <div className="cve-lib">{cve.library}</div>
                                                <div className="cve-desc">{cve.description}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Linked Libraries */}
                            {report.linked_libraries && report.linked_libraries.length > 0 && (
                                <div className="section libraries">
                                    <h4>📦 Linked Libraries</h4>
                                    <div className="lib-tags">
                                        {report.linked_libraries.map((lib, i) => (
                                            <span key={i} className="lib-tag">{lib}</span>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    ) : (
                        <div className="error-state">No report available.</div>
                    )}
                </div>
            </motion.div>
        </motion.div>
    );
}

function ProgramSummaryModal({ summary, loading, close }) {
    const handleDownload = () => {
        if (!summary) return;
        const text = generateSummaryReportText(summary);
        downloadFile(text, `hexplain_program_summary_${Date.now()}.txt`);
    };

    return (
        <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            onClick={close}
        >
            <motion.div
                className="modal-content"
                initial={{ y: 50, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 50, opacity: 0 }}
                onClick={e => e.stopPropagation()}
            >
                <div className="modal-header">
                    <h3><FileCode size={20} /> Program Summary & Analysis</h3>
                    <div className="modal-header-actions">
                        {summary && !loading && (
                            <button className="download-btn" onClick={handleDownload} title="Download Summary">
                                <Download size={16} /> Download
                            </button>
                        )}
                        <button className="close-btn" onClick={close}><X size={18} /></button>
                    </div>
                </div>

                <div className="modal-body">
                    {loading ? (
                        <div className="loading-state">
                            <div className="spinner"></div>
                            <p>Analyzing program logic... this may take a moment.</p>
                        </div>
                    ) : summary ? (
                        <div className="report-container">
                            <div className="section summary">
                                <div className="security-summary">
                                    <ReactMarkdown>{summary}</ReactMarkdown>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="error-state">Failed to generate summary.</div>
                    )}
                </div>
            </motion.div>
        </motion.div>
    );
}

function MalwareModal({ report, loading, close }) {
    const riskColor = (level) => {
        const l = (level || '').toUpperCase();
        if (l === 'CRITICAL') return '#ff2222';
        if (l === 'HIGH') return '#ff6600';
        if (l === 'MEDIUM') return '#ffaa00';
        if (l === 'LOW') return '#44bb44';
        return '#666';
    };

    const severityBadgeColor = (sev) => {
        const s = (sev || '').toUpperCase();
        if (s === 'CRITICAL') return '#ff2222';
        if (s === 'HIGH') return '#ff6600';
        if (s === 'MEDIUM') return '#ffaa00';
        if (s === 'LOW') return '#44bb44';
        return '#888';
    };

    const handleDownload = () => {
        if (!report) return;
        const lines = [];
        lines.push('═══════════════════════════════════════════════════');
        lines.push('        HEXPLAIN — MALWARE BEHAVIOR REPORT');
        lines.push('═══════════════════════════════════════════════════');
        lines.push(`Generated: ${new Date().toLocaleString()}`);
        lines.push(`Risk Score: ${report.risk_score}/100`);
        lines.push(`Risk Level: ${report.risk_level}`);
        lines.push(`Total Indicators: ${report.total_indicators}`);
        lines.push('');

        if (report.ai_assessment) {
            lines.push('───────────────────────────────────────────────────');
            lines.push('🔬 AI THREAT ASSESSMENT');
            lines.push('───────────────────────────────────────────────────');
            lines.push(report.ai_assessment);
            lines.push('');
        }

        (report.categories || []).forEach(cat => {
            lines.push('───────────────────────────────────────────────────');
            lines.push(`${cat.label} (${cat.count} indicators)`);
            lines.push('───────────────────────────────────────────────────');
            cat.findings.forEach(f => {
                lines.push(`  [${f.severity}] ${f.description}`);
                lines.push(`    Function: ${f.function} | Line: ${f.line}`);
                lines.push(`    Code: ${f.code}`);
                lines.push('');
            });
        });

        lines.push('═══════════════════════════════════════════════════');
        lines.push('              End of Report — Hexplain');
        lines.push('═══════════════════════════════════════════════════');
        downloadFile(lines.join('\n'), `hexplain_malware_report_${Date.now()}.txt`);
    };

    return (
        <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            onClick={close}
        >
            <motion.div
                className="modal-content modal-wide"
                initial={{ y: 50, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 50, opacity: 0 }}
                onClick={e => e.stopPropagation()}
            >
                <div className="modal-header">
                    <h3><Bug size={20} /> Malware Behavior Analysis</h3>
                    <div className="modal-header-actions">
                        {report && !loading && (
                            <button className="download-btn" onClick={handleDownload} title="Download Report">
                                <Download size={16} /> Download
                            </button>
                        )}
                        <button className="close-btn" onClick={close}><X size={18} /></button>
                    </div>
                </div>

                <div className="modal-body">
                    {loading ? (
                        <div className="loading-state">
                            <div className="spinner"></div>
                            <p>Scanning for malware behavioral indicators...</p>
                        </div>
                    ) : report ? (
                        <div className="report-container">
                            {/* Risk Score Overview */}
                            <div className="section malware-overview">
                                <div className="risk-score-card" style={{ borderColor: riskColor(report.risk_level) }}>
                                    <div className="risk-score-number" style={{ color: riskColor(report.risk_level) }}>
                                        {report.risk_score}
                                    </div>
                                    <div className="risk-score-label">Risk Score</div>
                                    <div className="risk-level-badge" style={{ background: riskColor(report.risk_level) }}>
                                        {report.risk_level}
                                    </div>
                                </div>
                                <div className="severity-breakdown">
                                    <div className="severity-item critical">
                                        <span className="severity-count">{report.severity_counts?.CRITICAL || 0}</span>
                                        <span className="severity-label">Critical</span>
                                    </div>
                                    <div className="severity-item high">
                                        <span className="severity-count">{report.severity_counts?.HIGH || 0}</span>
                                        <span className="severity-label">High</span>
                                    </div>
                                    <div className="severity-item medium">
                                        <span className="severity-count">{report.severity_counts?.MEDIUM || 0}</span>
                                        <span className="severity-label">Medium</span>
                                    </div>
                                    <div className="severity-item low">
                                        <span className="severity-count">{report.severity_counts?.LOW || 0}</span>
                                        <span className="severity-label">Low</span>
                                    </div>
                                </div>
                            </div>

                            {/* AI Threat Assessment */}
                            {report.ai_assessment && (
                                <div className="section summary">
                                    <h4>🔬 AI Threat Assessment</h4>
                                    <div className="security-summary">
                                        <ReactMarkdown>{report.ai_assessment}</ReactMarkdown>
                                    </div>
                                </div>
                            )}

                            {/* Categorized Findings */}
                            {(report.categories || []).map((cat, ci) => (
                                <div key={ci} className="section malware-category">
                                    <h4>{cat.label} <span className="cat-count">({cat.count})</span></h4>
                                    <div className="malware-findings-list">
                                        {cat.findings.map((finding, fi) => (
                                            <div key={fi} className="malware-finding-card">
                                                <div className="finding-header">
                                                    <span className="finding-severity" style={{ background: severityBadgeColor(finding.severity) }}>
                                                        {finding.severity}
                                                    </span>
                                                    <span className="finding-desc">{finding.description}</span>
                                                </div>
                                                <div className="finding-location">
                                                    <span className="call-site-func">{finding.function}</span>
                                                    <span className="call-site-line">Line {finding.line}</span>
                                                </div>
                                                <code className="call-site-code">{finding.code}</code>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ))}

                            {report.total_indicators === 0 && (
                                <div className="section">
                                    <div className="empty-flaws">
                                        <CheckCircle size={14} /> No malware behavioral indicators detected.
                                    </div>
                                </div>
                            )}
                        </div>
                    ) : (
                        <div className="error-state">No report available.</div>
                    )}
                </div>
            </motion.div>
        </motion.div>
    );
}

function ChatPanel({ open, toggle }) {
    const [messages, setMessages] = useState([
        { role: 'assistant', content: 'Hello! I am ready to explain your binary code.' }
    ]);
    const [input, setInput] = useState("");
    const [loading, setLoading] = useState(false);

    const sendMessage = async () => {
        if (!input.trim()) return;

        const newMsg = { role: 'user', content: input };
        setMessages(prev => [...prev, newMsg]);
        setInput("");
        setLoading(true);

        try {
            const res = await axios.post(`${API_BASE}/chat`, {
                messages: [...messages, newMsg],
                model: "llama3.2",
                provider: "local"
            });

            setMessages(prev => [...prev, { role: 'assistant', content: res.data.reply }]);
        } catch (err) {
            setMessages(prev => [...prev, { role: 'system', content: "**Error**: Could not connect to AI backend or Local LLM is offline." }]);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className={`chat-panel ${open ? 'open' : 'closed'}`}>
            <div className="chat-header" onClick={toggle}>
                <MessageSquare size={18} /> AI Assistant
            </div>

            <div className="chat-body">
                {messages.map((m, i) => (
                    <div key={i} className={`msg ${m.role}`}>
                        <ReactMarkdown>{m.content}</ReactMarkdown>
                    </div>
                ))}
                {loading && <div className="msg assistant typing">typing...</div>}
            </div>

            <div className="chat-input">
                <input
                    value={input}
                    onChange={e => setInput(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && sendMessage()}
                    placeholder="Ask about this code..."
                />
            </div>
        </div>
    );
}

class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true, error };
    }

    componentDidCatch(error, errorInfo) {
        console.error("ErrorBoundary caught an error", error, errorInfo);
    }

    render() {
        if (this.state.hasError) {
            return (
                <div style={{ padding: '20px', color: 'red' }}>
                    <h1>Something went wrong.</h1>
                    <pre>{this.state.error && this.state.error.toString()}</pre>
                </div>
            );
        }

        return this.props.children;
    }
}

export default function WrappedApp() {
    return (
        <ErrorBoundary>
            <App />
        </ErrorBoundary>
    );
}
