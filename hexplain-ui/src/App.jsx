import React, { useState } from 'react';
import axios from 'axios';
import { Upload, FileCode, MessageSquare, Terminal, Cpu, Shield, X, AlertTriangle, CheckCircle } from 'lucide-react';
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
            </AnimatePresence>
        </div>
    );
}

function SecurityModal({ report, loading, close }) {
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
                    <h3><Shield size={20} /> Security Analysis</h3>
                    <button className="close-btn" onClick={close}><X size={18} /></button>
                </div>

                <div className="modal-body">
                    {loading ? (
                        <div className="loading-state">Scanning binary...</div>
                    ) : report ? (
                        <div className="report-container">
                            {report.explanation && (
                                <div className="section summary">
                                    <h4>Security Assessment</h4>
                                    <div className="security-summary">
                                        <ReactMarkdown>{report.explanation}</ReactMarkdown>
                                    </div>
                                </div>
                            )}

                            <div className="section mitigations">
                                <h4>Mitigations</h4>
                                <div className="mitigation-grid">
                                    {Object.entries(report.mitigations).map(([key, val]) => (
                                        <div key={key} className={`mitigation-card ${val === true ? 'safe' : val === false ? 'danger' : 'warn'}`}>
                                            <div className="status-icon">
                                                {val === true ? <CheckCircle size={16} /> : val === false ? <AlertTriangle size={16} /> : <AlertTriangle size={16} />}
                                            </div>
                                            <div className="mitigation-name">{key}</div>
                                            <div className="mitigation-status">{val === true ? 'Enabled' : val === false ? 'Disabled' : String(val)}</div>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <div className="section flaws">
                                <h4>Potential Flaws</h4>
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
                    <button className="close-btn" onClick={close}><X size={18} /></button>
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
                model: "mistral",
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
