import React, { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import {
    Upload, FileCode, MessageSquare, Terminal, Cpu, Shield, X,
    AlertTriangle, CheckCircle, Download, Bug, ChevronRight,
    ChevronLeft, ChevronDown, Zap, Brain, Hash, Search,
    FolderOpen, RefreshCw, Maximize2, Code2
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import SyntaxHighlighter from 'react-syntax-highlighter';
import { atomOneDark } from 'react-syntax-highlighter/dist/esm/styles/hljs';
import ReactMarkdown from 'react-markdown';
import './App.css';

const API_BASE = "http://localhost:8000";

// ─── Utility ─────────────────────────────────────────────
function downloadFile(content, filename) {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
}

// ─── Main App ─────────────────────────────────────────────
function App() {
    const [file, setFile] = useState(null);
    const [uploadedPath, setUploadedPath] = useState(null);
    const [analyzing, setAnalyzing] = useState(false);
    const [functions, setFunctions] = useState({});
    const [selectedFunction, setSelectedFunction] = useState(null);
    const [funcIndexOpen, setFuncIndexOpen] = useState(true);
    const [funcSearch, setFuncSearch] = useState('');

    // Modals
    const [securityReport, setSecurityReport] = useState(null);
    const [showSecurity, setShowSecurity] = useState(false);
    const [analyzingSecurity, setAnalyzingSecurity] = useState(false);
    const [summaryReport, setSummaryReport] = useState(null);
    const [showSummary, setShowSummary] = useState(false);
    const [analyzingSummary, setAnalyzingSummary] = useState(false);
    const [malwareReport, setMalwareReport] = useState(null);
    const [showMalware, setShowMalware] = useState(false);
    const [analyzingMalware, setAnalyzingMalware] = useState(false);

    const fileInputRef = useRef(null);
    const codeRef = useRef(null);

    const handleUpload = async (e) => {
        const uploadedFile = e.target.files[0];
        if (!uploadedFile) return;
        setFile(uploadedFile);
        setAnalyzing(true);
        setSecurityReport(null); setSummaryReport(null); setMalwareReport(null);
        setFunctions({}); setSelectedFunction(null);

        const formData = new FormData();
        formData.append('file', uploadedFile);
        try {
            const uploadRes = await axios.post(`${API_BASE}/upload`, formData);
            const filePath = uploadRes.data.path;
            setUploadedPath(filePath);
            const analyzeRes = await axios.post(`${API_BASE}/analyze`, { binary_path: filePath });
            const funcs = analyzeRes.data.functions;
            setFunctions(funcs);
            const names = Object.keys(funcs);
            if (names.length > 0) setSelectedFunction(names[0]);
        } catch (err) {
            console.error(err);
            alert(`Analysis failed: ${err.response?.data?.detail || err.message}`);
        } finally {
            setAnalyzing(false);
        }
    };

    const handleSecurityCheck = async () => {
        if (!uploadedPath) return;
        setAnalyzingSecurity(true); setShowSecurity(true);
        try {
            const res = await axios.post(`${API_BASE}/analyze_security`, { binary_path: uploadedPath });
            setSecurityReport(res.data);
        } catch { alert("Security analysis failed"); setShowSecurity(false); }
        finally { setAnalyzingSecurity(false); }
    };

    const handleProgramSummary = async () => {
        if (!uploadedPath) return;
        setAnalyzingSummary(true); setShowSummary(true);
        try {
            const res = await axios.post(`${API_BASE}/explain_program`, { binary_path: uploadedPath });
            setSummaryReport(res.data.summary);
        } catch { alert("Program summary failed"); setShowSummary(false); }
        finally { setAnalyzingSummary(false); }
    };

    const handleMalwareScan = async () => {
        if (!uploadedPath) return;
        setAnalyzingMalware(true); setShowMalware(true);
        try {
            const res = await axios.post(`${API_BASE}/analyze_malware`, { binary_path: uploadedPath });
            setMalwareReport(res.data);
        } catch { alert("Malware analysis failed"); setShowMalware(false); }
        finally { setAnalyzingMalware(false); }
    };

    const filteredFunctions = Object.keys(functions).filter(fn =>
        fn.toLowerCase().includes(funcSearch.toLowerCase())
    );

    return (
        <div className="hx-root">
            {/* ── Top Navbar ── */}
            <header className="hx-navbar">
                <div className="hx-logo">
                    <div className="hx-logo-icon"><Cpu size={20} /></div>
                    <span className="hx-logo-text">Hexplain</span>
                    <span className="hx-logo-badge">RE Platform</span>
                </div>

                <div className="hx-nav-center">
                    {file ? (
                        <div className="hx-binary-pill">
                            <Code2 size={12} />
                            <span>{file.name}</span>
                            {analyzing && <span className="hx-analyzing-badge">Analyzing…</span>}
                        </div>
                    ) : (
                        <span className="hx-nav-hint">Upload a binary to begin</span>
                    )}
                </div>

                <div className="hx-nav-actions">
                    <button className="hx-upload-btn" onClick={() => fileInputRef.current?.click()}>
                        <Upload size={15} />
                        {file ? 'Load New Binary' : 'Upload Binary'}
                    </button>
                    <input ref={fileInputRef} type="file" style={{ display: 'none' }} onChange={handleUpload} />
                </div>
            </header>

            {/* ── Three-panel body ── */}
            <div className="hx-body">

                {/* ── LEFT SIDEBAR ── */}
                <aside className="hx-sidebar">
                    <div className="hx-sidebar-section">
                        <p className="hx-section-label">Analysis Tools</p>

                        <button
                            className={`hx-tool-btn summary ${!uploadedPath ? 'disabled' : ''}`}
                            onClick={handleProgramSummary}
                            disabled={!uploadedPath}
                        >
                            <div className="hx-tool-icon"><FileCode size={22} /></div>
                            <div className="hx-tool-text">
                                <span className="hx-tool-name">Program Summary</span>
                                <span className="hx-tool-desc">High-level narrative report</span>
                            </div>
                            {analyzingSummary && <div className="hx-btn-spinner" />}
                        </button>

                        <button
                            className={`hx-tool-btn malware ${!uploadedPath ? 'disabled' : ''}`}
                            onClick={handleMalwareScan}
                            disabled={!uploadedPath}
                        >
                            <div className="hx-tool-icon"><Bug size={22} /></div>
                            <div className="hx-tool-text">
                                <span className="hx-tool-name">Malware Analysis</span>
                                <span className="hx-tool-desc">Behavioral threat detection</span>
                            </div>
                            {analyzingMalware && <div className="hx-btn-spinner" />}
                        </button>

                        <button
                            className={`hx-tool-btn security ${!uploadedPath ? 'disabled' : ''}`}
                            onClick={handleSecurityCheck}
                            disabled={!uploadedPath}
                        >
                            <div className="hx-tool-icon"><Shield size={22} /></div>
                            <div className="hx-tool-text">
                                <span className="hx-tool-name">Security Check</span>
                                <span className="hx-tool-desc">Mitigations, CVEs & flaws</span>
                            </div>
                            {analyzingSecurity && <div className="hx-btn-spinner" />}
                        </button>
                    </div>

                    <div className="hx-sidebar-section hx-upload-area">
                        <p className="hx-section-label">Project File</p>
                        <div
                            className="hx-dropzone"
                            onClick={() => fileInputRef.current?.click()}
                            onDragOver={e => e.preventDefault()}
                            onDrop={e => {
                                e.preventDefault();
                                const f = e.dataTransfer.files[0];
                                if (f) fileInputRef.current && handleUpload({ target: { files: [f] } });
                            }}
                        >
                            <FolderOpen size={24} className="hx-dropzone-icon" />
                            {file ? (
                                <>
                                    <span className="hx-dropzone-filename">{file.name}</span>
                                    <span className="hx-dropzone-sub">Click to replace</span>
                                </>
                            ) : (
                                <>
                                    <span className="hx-dropzone-title">Drop binary here</span>
                                    <span className="hx-dropzone-sub">or click to browse</span>
                                </>
                            )}
                        </div>
                    </div>

                    <div className="hx-sidebar-footer">
                        <div className="hx-status-dot active" />
                        <span>Backend connected</span>
                    </div>
                </aside>

                {/* ── CENTER: Code Editor ── */}
                <main className="hx-center">
                    {/* Code editor header */}
                    <div className="hx-editor-header">
                        <div className="hx-editor-tabs">
                            {selectedFunction && (
                                <div className="hx-editor-tab active">
                                    <Terminal size={13} />
                                    <span>{selectedFunction}</span>
                                </div>
                            )}
                        </div>
                        <div className="hx-editor-actions">
                            <button
                                className="hx-icon-btn"
                                title="Toggle function index"
                                onClick={() => setFuncIndexOpen(v => !v)}
                            >
                                {funcIndexOpen ? <ChevronLeft size={16} /> : <ChevronRight size={16} />}
                            </button>
                        </div>
                    </div>

                    <div className="hx-editor-body">
                        {/* Function Index Panel */}
                        <AnimatePresence>
                            {funcIndexOpen && (
                                <motion.div
                                    className="hx-func-index"
                                    initial={{ width: 0, opacity: 0 }}
                                    animate={{ width: 200, opacity: 1 }}
                                    exit={{ width: 0, opacity: 0 }}
                                    transition={{ duration: 0.25 }}
                                >
                                    <div className="hx-func-index-header">
                                        <Hash size={13} />
                                        <span>Functions</span>
                                        <span className="hx-func-count">{Object.keys(functions).length}</span>
                                    </div>
                                    <div className="hx-func-search">
                                        <Search size={12} />
                                        <input
                                            type="text"
                                            placeholder="Filter…"
                                            value={funcSearch}
                                            onChange={e => setFuncSearch(e.target.value)}
                                        />
                                    </div>
                                    <ul className="hx-func-list">
                                        {analyzing ? (
                                            <li className="hx-func-loading">
                                                <div className="hx-mini-spinner" />
                                                Decompiling…
                                            </li>
                                        ) : filteredFunctions.length === 0 ? (
                                            <li className="hx-func-empty">
                                                {Object.keys(functions).length === 0
                                                    ? 'No binary loaded'
                                                    : 'No matches'}
                                            </li>
                                        ) : filteredFunctions.map(fn => (
                                            <li
                                                key={fn}
                                                className={`hx-func-item ${selectedFunction === fn ? 'active' : ''}`}
                                                onClick={() => setSelectedFunction(fn)}
                                            >
                                                <Terminal size={11} className="hx-func-icon" />
                                                <span className="hx-func-name">{fn}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </motion.div>
                            )}
                        </AnimatePresence>

                        {/* Code View */}
                        <div className="hx-code-view" ref={codeRef}>
                            {selectedFunction && functions[selectedFunction] ? (
                                <SyntaxHighlighter
                                    language="c"
                                    style={atomOneDark}
                                    showLineNumbers={true}
                                    customStyle={{
                                        margin: 0,
                                        background: 'transparent',
                                        fontSize: '13px',
                                        lineHeight: '1.6',
                                        height: '100%',
                                        padding: '1rem',
                                    }}
                                    lineNumberStyle={{
                                        color: '#3a4a6a',
                                        minWidth: '3em',
                                        paddingRight: '1em',
                                        userSelect: 'none',
                                    }}
                                >
                                    {functions[selectedFunction]}
                                </SyntaxHighlighter>
                            ) : (
                                <div className="hx-code-placeholder">
                                    {analyzing ? (
                                        <>
                                            <div className="hx-large-spinner" />
                                            <p>Decompiling binary with Ghidra…</p>
                                            <span>This may take a moment</span>
                                        </>
                                    ) : (
                                        <>
                                            <Cpu size={64} className="hx-placeholder-icon" />
                                            <p>Upload a binary to start reverse engineering</p>
                                            <span>Supports ELF, PE, Mach-O and more</span>
                                        </>
                                    )}
                                </div>
                            )}
                        </div>
                    </div>
                </main>

                {/* ── RIGHT: AI Assistant ── */}
                <ChatPanel
                    selectedFunction={selectedFunction}
                    currentCode={selectedFunction ? functions[selectedFunction] : null}
                    binaryName={file ? file.name : null}
                    onExplainFunction={() => {/* handled inside */ }}
                />
            </div>

            {/* ── Modals ── */}
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

// ─── AI Chat Panel ────────────────────────────────────────
function ChatPanel({ selectedFunction, currentCode, binaryName }) {
    const [messages, setMessages] = useState([
        {
            role: 'assistant',
            content: "Hello! I'm **Hexplain Assistant**, your AI-powered reverse engineering analyst.\n\nUpload a binary, select a function, and ask me anything:\n- *\"What does this function do?\"*\n- *\"Is there a buffer overflow risk here?\"*\n- *\"Explain the control flow\"*"
        }
    ]);
    const [input, setInput] = useState('');
    const [loading, setLoading] = useState(false);
    const chatBodyRef = useRef(null);

    useEffect(() => {
        if (chatBodyRef.current) {
            chatBodyRef.current.scrollTop = chatBodyRef.current.scrollHeight;
        }
    }, [messages, loading]);

    const sendMessage = async (text) => {
        const content = text || input;
        if (!content.trim()) return;

        const newMsg = { role: 'user', content };
        const historyToSend = [...messages, newMsg];
        setMessages(prev => [...prev, newMsg]);
        setInput('');
        setLoading(true);

        const contextMessages = [];
        if (currentCode && selectedFunction) {
            const code = currentCode.length > 8000
                ? currentCode.slice(0, 8000) + '\n// ... [truncated] ...'
                : currentCode;
            contextMessages.push({
                role: 'system',
                content: (
                    `The user is currently viewing the decompiled function \`${selectedFunction}\` ` +
                    `from binary "${binaryName || 'uploaded binary'}":\n\n` +
                    `\`\`\`c\n${code}\n\`\`\`\n\n` +
                    `When the user says "this function" or "this code", they mean the function above.`
                )
            });
        } else if (binaryName) {
            contextMessages.push({
                role: 'system',
                content: `User has uploaded binary "${binaryName}". No function is currently selected.`
            });
        }

        const cleanHistory = historyToSend.filter(m => m.role === 'user' || m.role === 'assistant');

        try {
            const res = await axios.post(`${API_BASE}/chat`, {
                messages: [...contextMessages, ...cleanHistory],
                model: 'llama3.2',
                provider: 'local'
            });
            setMessages(prev => [...prev, { role: 'assistant', content: res.data.reply }]);
        } catch {
            setMessages(prev => [...prev, {
                role: 'error',
                content: '⚠️ Could not reach AI backend. Is Ollama running?'
            }]);
        } finally {
            setLoading(false);
        }
    };

    const quickActions = [
        { label: 'Explain this function', icon: <Brain size={12} />, msg: 'Explain what this function does in detail.' },
        { label: 'Find vulnerabilities', icon: <AlertTriangle size={12} />, msg: 'Are there any security vulnerabilities or dangerous patterns in this function?' },
        { label: 'Identify purpose', icon: <Zap size={12} />, msg: 'What is the likely purpose of this function? Is it part of malware or benign software?' },
    ];

    return (
        <aside className="hx-chat-panel">
            {/* Chat Header */}
            <div className="hx-chat-header">
                <div className="hx-chat-header-left">
                    <div className="hx-chat-brain-icon"><Brain size={18} /></div>
                    <div>
                        <div className="hx-chat-title">Hexplain Assistant</div>
                        <div className="hx-chat-subtitle">Live AI Reverse Engineering Help</div>
                    </div>
                </div>
                <div className="hx-chat-status">
                    <div className="hx-status-dot active" />
                </div>
            </div>

            {/* Context Badge */}
            {selectedFunction && (
                <div className="hx-chat-context">
                    <Terminal size={11} />
                    <span>Viewing: <code>{selectedFunction}</code></span>
                </div>
            )}

            {/* Message Body */}
            <div className="hx-chat-body" ref={chatBodyRef}>
                {messages.map((m, i) => (
                    <div key={i} className={`hx-msg hx-msg-${m.role}`}>
                        {m.role === 'assistant' && (
                            <div className="hx-msg-avatar ai">
                                <Brain size={12} />
                            </div>
                        )}
                        <div className="hx-msg-bubble">
                            <ReactMarkdown>{m.content}</ReactMarkdown>
                        </div>
                    </div>
                ))}
                {loading && (
                    <div className="hx-msg hx-msg-assistant">
                        <div className="hx-msg-avatar ai"><Brain size={12} /></div>
                        <div className="hx-msg-bubble hx-typing">
                            <span className="dot" /><span className="dot" /><span className="dot" />
                        </div>
                    </div>
                )}
            </div>

            {/* Quick Actions */}
            {selectedFunction && !loading && (
                <div className="hx-quick-actions">
                    {quickActions.map((qa, i) => (
                        <button key={i} className="hx-quick-btn" onClick={() => sendMessage(qa.msg)}>
                            {qa.icon} {qa.label}
                        </button>
                    ))}
                </div>
            )}

            {/* Input */}
            <div className="hx-chat-input-area">
                <div className="hx-chat-input-row">
                    <input
                        className="hx-chat-input"
                        value={input}
                        onChange={e => setInput(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendMessage()}
                        placeholder={
                            selectedFunction
                                ? `Ask about ${selectedFunction}…`
                                : 'Ask about the binary…'
                        }
                        disabled={loading}
                    />
                    <button
                        className="hx-send-btn"
                        onClick={() => sendMessage()}
                        disabled={loading || !input.trim()}
                    >
                        <ChevronRight size={18} />
                    </button>
                </div>
            </div>
        </aside>
    );
}

// ─── Security Modal ───────────────────────────────────────
function SecurityModal({ report, loading, close }) {
    const severityColor = s => {
        const v = (s || '').toUpperCase();
        if (v === 'CRITICAL') return '#ff4444';
        if (v === 'HIGH') return '#ff8800';
        if (v === 'MEDIUM') return '#ffcc00';
        return '#44cc44';
    };
    const handleDownload = () => {
        if (!report) return;
        const lines = [];
        lines.push('HEXPLAIN — SECURITY ANALYSIS REPORT');
        lines.push(new Date().toLocaleString());
        if (report.explanation) lines.push('\nSECURITY ASSESSMENT\n' + report.explanation);
        lines.push('\nMITIGATIONS');
        for (const [k, v] of Object.entries(report.mitigations || {}))
            lines.push(`  ${k}: ${v === true ? 'ENABLED' : v === false ? 'DISABLED' : v}`);
        downloadFile(lines.join('\n'), `hexplain_security_${Date.now()}.txt`);
    };

    return (
        <motion.div className="hx-modal-overlay" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={close}>
            <motion.div className="hx-modal" initial={{ y: 40, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 40, opacity: 0 }} onClick={e => e.stopPropagation()}>
                <div className="hx-modal-header">
                    <div className="hx-modal-title"><Shield size={18} /> Security Analysis</div>
                    <div className="hx-modal-actions">
                        {report && !loading && (
                            <button className="hx-modal-dl-btn" onClick={handleDownload}><Download size={14} /> Download</button>
                        )}
                        <button className="hx-modal-close" onClick={close}><X size={18} /></button>
                    </div>
                </div>
                <div className="hx-modal-body">
                    {loading ? <ModalLoader text="Running comprehensive security scan…" /> : report ? (
                        <div>
                            {report.explanation && (
                                <div className="hx-modal-section">
                                    <h4>🔍 AI Security Assessment</h4>
                                    <div className="hx-ai-text"><ReactMarkdown>{report.explanation}</ReactMarkdown></div>
                                </div>
                            )}
                            <div className="hx-modal-section">
                                <h4>🛡️ Binary Hardening Mitigations</h4>
                                <div className="hx-mit-grid">
                                    {Object.entries(report.mitigations || {}).map(([k, v]) => (
                                        <div key={k} className={`hx-mit-card ${v === true || v === 'Full' ? 'safe' : v === false ? 'danger' : 'warn'}`}>
                                            <div className="hx-mit-icon">
                                                {v === true || v === 'Full' ? <CheckCircle size={16} /> : <AlertTriangle size={16} />}
                                            </div>
                                            <div className="hx-mit-name">{k}</div>
                                            <div className="hx-mit-val">{v === true ? 'Enabled' : v === false ? 'Disabled' : String(v)}</div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                            {report.flaws && (
                                <div className="hx-modal-section">
                                    <h4>⚠️ Potential Flaws</h4>
                                    {report.flaws.length === 0 ? (
                                        <div className="hx-ok-msg"><CheckCircle size={14} /> No obvious flaws detected.</div>
                                    ) : (
                                        <ul className="hx-flaws-list">
                                            {report.flaws.map((f, i) => <li key={i}><AlertTriangle size={13} /> {f}</li>)}
                                        </ul>
                                    )}
                                </div>
                            )}
                            {report.vulnerable_call_sites?.length > 0 && (
                                <div className="hx-modal-section">
                                    <h4>📍 Vulnerable Call Sites</h4>
                                    <div className="hx-call-sites">
                                        {report.vulnerable_call_sites.map((s, i) => (
                                            <div key={i} className="hx-call-card">
                                                <div className="hx-call-top">
                                                    <span className="hx-call-fn">{s.function}</span>
                                                    <span className="hx-call-line">Line {s.line}</span>
                                                </div>
                                                <div className="hx-call-danger"><AlertTriangle size={11} /> {s.dangerous_call}()</div>
                                                <code className="hx-call-code">{s.context}</code>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                            {report.known_cves?.length > 0 && (
                                <div className="hx-modal-section">
                                    <h4>🗃️ Known CVEs</h4>
                                    <div className="hx-cve-list">
                                        {report.known_cves.map((c, i) => (
                                            <div key={i} className="hx-cve-card">
                                                <div className="hx-cve-top">
                                                    <span className="hx-cve-id">{c.cve_id}</span>
                                                    <span className="hx-cve-sev" style={{ background: severityColor(c.severity) }}>{c.severity}</span>
                                                </div>
                                                <div className="hx-cve-lib">{c.library}</div>
                                                <div className="hx-cve-desc">{c.description}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                            {report.linked_libraries?.length > 0 && (
                                <div className="hx-modal-section">
                                    <h4>📦 Linked Libraries</h4>
                                    <div className="hx-tags">
                                        {report.linked_libraries.map((l, i) => <span key={i} className="hx-tag">{l}</span>)}
                                    </div>
                                </div>
                            )}
                        </div>
                    ) : <div className="hx-modal-err">No report available.</div>}
                </div>
            </motion.div>
        </motion.div>
    );
}

// ─── Program Summary Modal ────────────────────────────────
function ProgramSummaryModal({ summary, loading, close }) {
    return (
        <motion.div className="hx-modal-overlay" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={close}>
            <motion.div className="hx-modal" initial={{ y: 40, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 40, opacity: 0 }} onClick={e => e.stopPropagation()}>
                <div className="hx-modal-header">
                    <div className="hx-modal-title"><FileCode size={18} /> Program Summary</div>
                    <div className="hx-modal-actions">
                        {summary && !loading && (
                            <button className="hx-modal-dl-btn" onClick={() => downloadFile(summary, `hexplain_summary_${Date.now()}.txt`)}>
                                <Download size={14} /> Download
                            </button>
                        )}
                        <button className="hx-modal-close" onClick={close}><X size={18} /></button>
                    </div>
                </div>
                <div className="hx-modal-body">
                    {loading ? <ModalLoader text="Synthesizing program behavior into narrative…" /> : summary ? (
                        <div className="hx-narrative"><ReactMarkdown>{summary}</ReactMarkdown></div>
                    ) : <div className="hx-modal-err">Failed to generate summary.</div>}
                </div>
            </motion.div>
        </motion.div>
    );
}

// ─── Malware Modal ────────────────────────────────────────
function MalwareModal({ report, loading, close }) {
    const riskColor = l => {
        const v = (l || '').toUpperCase();
        if (v === 'CRITICAL') return '#ff2222';
        if (v === 'HIGH') return '#ff6600';
        if (v === 'MEDIUM') return '#ffaa00';
        return '#44bb44';
    };
    return (
        <motion.div className="hx-modal-overlay" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={close}>
            <motion.div className="hx-modal" initial={{ y: 40, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 40, opacity: 0 }} onClick={e => e.stopPropagation()}>
                <div className="hx-modal-header">
                    <div className="hx-modal-title"><Bug size={18} /> Malware Behavior Analysis</div>
                    <div className="hx-modal-actions">
                        <button className="hx-modal-close" onClick={close}><X size={18} /></button>
                    </div>
                </div>
                <div className="hx-modal-body">
                    {loading ? <ModalLoader text="Scanning for malware behavioral indicators…" /> : report ? (
                        <div>
                            <div className="hx-risk-overview">
                                <div className="hx-risk-score-card" style={{ borderColor: riskColor(report.risk_level) }}>
                                    <div className="hx-risk-num" style={{ color: riskColor(report.risk_level) }}>{report.risk_score}</div>
                                    <div className="hx-risk-label">Risk Score</div>
                                    <div className="hx-risk-badge" style={{ background: riskColor(report.risk_level) }}>{report.risk_level}</div>
                                </div>
                                <div className="hx-sev-grid">
                                    {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
                                        <div key={s} className={`hx-sev-item hx-sev-${s.toLowerCase()}`}>
                                            <div className="hx-sev-count">{report.severity_counts?.[s] || 0}</div>
                                            <div className="hx-sev-name">{s}</div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                            {report.ai_assessment && (
                                <div className="hx-modal-section">
                                    <h4>🔬 AI Threat Assessment</h4>
                                    <div className="hx-ai-text"><ReactMarkdown>{report.ai_assessment}</ReactMarkdown></div>
                                </div>
                            )}
                            {(report.categories || []).map((cat, ci) => (
                                <div key={ci} className="hx-modal-section">
                                    <h4>{cat.label} <span className="hx-cat-count">({cat.count})</span></h4>
                                    <div className="hx-findings">
                                        {cat.findings.map((f, fi) => (
                                            <div key={fi} className="hx-finding-card">
                                                <div className="hx-finding-top">
                                                    <span className="hx-finding-sev" style={{ background: riskColor(f.severity) }}>{f.severity}</span>
                                                    <span className="hx-finding-desc">{f.description}</span>
                                                </div>
                                                <div className="hx-finding-loc">
                                                    <span className="hx-call-fn">{f.function}</span>
                                                    <span className="hx-call-line">Line {f.line}</span>
                                                </div>
                                                <code className="hx-call-code">{f.code}</code>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ))}
                            {report.total_indicators === 0 && (
                                <div className="hx-ok-msg"><CheckCircle size={14} /> No malware indicators detected.</div>
                            )}
                        </div>
                    ) : <div className="hx-modal-err">No report available.</div>}
                </div>
            </motion.div>
        </motion.div>
    );
}

// ─── Modal Loader ─────────────────────────────────────────
function ModalLoader({ text }) {
    return (
        <div className="hx-modal-loader">
            <div className="hx-large-spinner" />
            <p>{text}</p>
        </div>
    );
}

// ─── Error Boundary ───────────────────────────────────────
class ErrorBoundary extends React.Component {
    state = { hasError: false, error: null };
    static getDerivedStateFromError(error) { return { hasError: true, error }; }
    componentDidCatch(e, info) { console.error(e, info); }
    render() {
        if (this.state.hasError) return (
            <div style={{ padding: 40, color: '#ff4444', fontFamily: 'monospace' }}>
                <h2>Something went wrong.</h2>
                <pre>{this.state.error?.toString()}</pre>
            </div>
        );
        return this.props.children;
    }
}

export default function WrappedApp() {
    return <ErrorBoundary><App /></ErrorBoundary>;
}
