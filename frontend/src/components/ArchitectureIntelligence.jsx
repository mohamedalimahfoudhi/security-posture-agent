import { useState, useCallback, useEffect } from 'react';
import { Upload, FileText, CheckCircle, XCircle, Clock, AlertCircle, Loader2, Trash2 } from 'lucide-react';
import { uploadDocument, extractTechnologies, getDocuments, assessApplicability, deleteDocument } from '../api/client';

export default function ArchitectureIntelligence() {
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [extracting, setExtracting] = useState(false);
  const [documents, setDocuments] = useState([]);
  const [error, setError] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [pollingDocId, setPollingDocId] = useState(null);
  const [vulnerabilityTitle, setVulnerabilityTitle] = useState('Critical PostgreSQL vulnerability allows unauthenticated remote code execution');
  const [assessmentResult, setAssessmentResult] = useState(null);
  const [assessing, setAssessing] = useState(false);
  const [deletingId, setDeletingId] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);

  const loadDocuments = useCallback(async () => {
    try {
      const data = await getDocuments();
      setDocuments(data);
      setError(null);
    } catch (err) {
      console.error('Failed to load documents:', err);
      setError('Failed to load documents');
    }
  }, []);

  // Load documents on mount
  useEffect(() => {
    loadDocuments();
  }, [loadDocuments]);

  // Poll for document status updates
  useEffect(() => {
    if (!pollingDocId) return;

    const pollInterval = setInterval(async () => {
      try {
        const data = await getDocuments();
        const doc = data.find(d => d.id === pollingDocId);
        
        if (doc) {
          setDocuments(data);
          
          // Stop polling if document is completed or failed
          if (doc.extraction_status === 'completed' || doc.extraction_status === 'failed') {
            setPollingDocId(null);
            setExtracting(false);
            setUploading(false);
            setSelectedFile(null);
            
            if (doc.extraction_status === 'failed') {
              setError(doc.error_message || 'Extraction failed');
            }
          }
        }
      } catch (err) {
        console.error('Polling failed:', err);
      }
    }, 2000); // Poll every 2 seconds

    // Timeout after 2 minutes
    const timeout = setTimeout(() => {
      setPollingDocId(null);
      setExtracting(false);
      setUploading(false);
      setError('Extraction timed out. Please try again.');
    }, 120000);

    return () => {
      clearInterval(pollInterval);
      clearTimeout(timeout);
    };
  }, [pollingDocId]);

  const handleDrag = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  }, []);

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFileUpload(e.target.files[0]);
    }
  };

  const handleFileUpload = async (file) => {
    // Validate file type
    const allowedTypes = ['pdf', 'docx', 'xlsx', 'txt'];
    const fileType = file.name.split('.').pop().toLowerCase();
    
    if (!allowedTypes.includes(fileType)) {
      setError(`Unsupported file type: ${fileType}. Allowed: PDF, DOCX, XLSX, TXT`);
      return;
    }

    setSelectedFile(file);
    setUploading(true);
    setError(null);

    try {
      const result = await uploadDocument(file);
      
      // Start polling for extraction status
      setPollingDocId(result.id);
      
      // Trigger extraction (fire and forget, polling will track status)
      extractTechnologies(result.id).catch(err => {
        console.error('Extraction trigger failed:', err);
        // Polling will catch the failure status
      });
      
    } catch (err) {
      console.error('Upload failed:', err);
      setError(err.message || 'Upload failed');
      setUploading(false);
      setExtracting(false);
      setSelectedFile(null);
    }
  };

  const handleExtract = async (documentId) => {
    setExtracting(true);
    setError(null);
    setSuccessMessage(null);
    setPollingDocId(documentId);

    try {
      await extractTechnologies(documentId);
      // Polling will track the status
    } catch (err) {
      console.error('Extraction failed:', err);
      setError(err.message || 'Extraction failed');
      setExtracting(false);
      setPollingDocId(null);
    }
  };

  const handleDelete = async (documentId) => {
    const isConfirmed = window.confirm("Are you sure you want to delete this architecture document? This will remove extracted assets linked to it.");
    if (!isConfirmed) return;

    setDeletingId(documentId);
    setError(null);
    setSuccessMessage(null);

    try {
      await deleteDocument(documentId);
      
      // Remove from local state immediately
      setDocuments(prev => prev.filter(doc => doc.id !== documentId));
      
      // Show success notification
      setSuccessMessage('Document deleted successfully');
      
      // Trigger global refresh for dashboard and dependent components
      window.dispatchEvent(new Event('data:refresh'));
      
      // Clear success message after 3 seconds
      setTimeout(() => {
        setSuccessMessage(null);
      }, 3000);
      
    } catch (err) {
      console.error('Deletion failed:', err);
      setError(err.message || 'Failed to delete document');
    } finally {
      setDeletingId(null);
    }
  };

  const getStatusIcon = (uploadStatus, extractionStatus) => {
    if (uploadStatus === 'failed' || extractionStatus === 'failed') {
      return <XCircle className="w-5 h-5 text-ember-bright" />;
    }
    if (extractionStatus === 'completed') {
      return <CheckCircle className="w-5 h-5 text-sev-low" />;
    }
    if (extractionStatus === 'extracting' || extractionStatus === 'analyzing') {
      return <Loader2 className="w-5 h-5 text-sev-elevated animate-spin" />;
    }
    if (uploadStatus === 'uploaded') {
      return <Clock className="w-5 h-5 text-sev-elevated" />;
    }
    return <AlertCircle className="w-5 h-5 text-mist" />;
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const handleAssessApplicability = async () => {
    try {
      setAssessing(true);
      setError(null);

      const result = await assessApplicability(1, vulnerabilityTitle, []);
      setAssessmentResult(result);
    } catch (err) {
      console.error('Applicability assessment failed:', err);
      setError(err.message || 'Applicability assessment failed');
    } finally {
      setAssessing(false);
    }
  };

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="bg-panel border-b border-hairline p-6">
        <h1 className="text-2xl font-semibold font-display text-ink mb-2">
          Architecture Intelligence
        </h1>
        <p className="text-sm text-mist font-body">
          Upload architecture documents to automatically extract technologies and build your asset inventory
        </p>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-4xl mx-auto space-y-6">
          {/* Upload Area */}
          <div
            className={`
              relative border-2 border-dashed rounded-lg p-12 text-center transition-colors
              ${dragActive ? 'border-ember-bright bg-panel' : 'border-hairline bg-void'}
              ${uploading ? 'opacity-50 pointer-events-none' : ''}
            `}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <input
              type="file"
              id="file-upload"
              className="hidden"
              accept=".pdf,.docx,.xlsx,.txt"
              onChange={handleFileSelect}
              disabled={uploading}
            />
            
            <div className="flex flex-col items-center gap-4">
              <Upload className={`w-12 h-12 ${dragActive ? 'text-ember-bright' : 'text-mist'}`} />
              
              <div>
                <p className="text-base font-medium text-ink mb-2">
                  {uploading ? 'Uploading...' : 'Drag & Drop or Browse Files'}
                </p>
                <p className="text-sm text-mist">
                  Supported: PDF, DOCX, XLSX, TXT
                </p>
              </div>

              {!uploading && (
                <label
                  htmlFor="file-upload"
                  className="px-4 py-2 bg-ember-bright hover:bg-ember-bright/80 text-void rounded-md text-sm font-medium cursor-pointer transition-colors"
                >
                  Browse Files
                </label>
              )}

              {selectedFile && (
                <div className="mt-4 p-3 bg-panel rounded border border-hairline">
                  <div className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-mist" />
                    <span className="text-sm text-ink">{selectedFile.name}</span>
                    <span className="text-xs text-mist">({formatFileSize(selectedFile.size)})</span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Error Message */}
          {error && (
            <div className="bg-void border-l-2 border-ember-bright p-4 rounded">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-5 h-5 text-ember-bright" />
                <p className="text-sm text-ember-bright font-body">{error}</p>
              </div>
            </div>
          )}

          {/* Success Message */}
          {successMessage && (
            <div className="bg-void border-l-2 border-sev-low p-4 rounded">
              <div className="flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-sev-low" />
                <p className="text-sm text-sev-low font-body">{successMessage}</p>
              </div>
            </div>
          )}

          {/* Applicability Assessment */}
          <div className="bg-panel border border-hairline rounded-lg overflow-hidden">
            <div className="p-4 border-b border-hairline">
              <h2 className="text-lg font-semibold font-display text-ink">
                Vulnerability Applicability Assessment
              </h2>
            </div>
            <div className="p-4 space-y-4">
              <label className="block text-sm text-mist font-body">
                Vulnerability description
                <textarea
                  value={vulnerabilityTitle}
                  onChange={(e) => setVulnerabilityTitle(e.target.value)}
                  className="mt-2 w-full rounded border border-hairline bg-void p-3 text-sm text-ink"
                  rows="3"
                />
              </label>

              <button
                onClick={handleAssessApplicability}
                disabled={assessing}
                className="px-4 py-2 bg-ember-bright hover:bg-ember-bright/80 text-void rounded-md text-sm font-medium transition-colors disabled:opacity-50"
              >
                {assessing ? 'Assessing...' : 'Assess applicability'}
              </button>

              {assessmentResult && (
                <div className="rounded border border-hairline bg-void p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-semibold text-ink">Relevance: {assessmentResult.relevance}</p>
                    <span className="text-xs text-mist">Customer {assessmentResult.customer_id}</span>
                  </div>
                  <p className="text-sm text-mist">{assessmentResult.summary}</p>
                  <div className="rounded border border-hairline bg-panel p-3 text-sm text-ink space-y-1">
                    <p><span className="font-medium">Alert:</span> {assessmentResult.alert?.title}</p>
                    <p><span className="font-medium">Stored alert ID:</span> {assessmentResult.alert?.stored_alert_id ?? 'not persisted'}</p>
                    <p><span className="font-medium">Business relevance:</span> {assessmentResult.business_relevance}</p>
                    <p><span className="font-medium">Customer context:</span> {assessmentResult.customer_context}</p>
                    <p><span className="font-medium">Recommended action:</span> {assessmentResult.recommended_action}</p>
                    <p><span className="font-medium">Evidence:</span> {assessmentResult.evidence.top_match} · {assessmentResult.evidence.top_vendor} · confidence {assessmentResult.evidence.confidence}%</p>
                  </div>
                  <div className="space-y-2">
                    {assessmentResult.matches.map((match) => (
                      <div key={match.asset_id} className="rounded border border-hairline bg-panel p-3">
                        <p className="text-sm font-medium text-ink">{match.technology} · {match.vendor}</p>
                        <p className="text-xs text-mist">Confidence: {match.confidence}%</p>
                        <ul className="mt-2 list-disc pl-5 text-xs text-mist">
                          {match.reasons.map((reason) => (
                            <li key={reason}>{reason}</li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Documents List */}
          <div className="bg-panel border border-hairline rounded-lg overflow-hidden">
            <div className="p-4 border-b border-hairline">
              <h2 className="text-lg font-semibold font-display text-ink">
                Uploaded Documents
              </h2>
            </div>

            {documents.length === 0 ? (
              <div className="p-8 text-center">
                <FileText className="w-12 h-12 text-mist mx-auto mb-4" />
                <p className="text-sm text-mist font-body">
                  No documents uploaded yet
                </p>
              </div>
            ) : (
              <div className="divide-y divide-hairline">
                {documents.map((doc) => (
                  <div key={doc.id} className="p-4 hover:bg-void transition-colors">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-4 flex-1">
                        {getStatusIcon(doc.upload_status, doc.extraction_status)}
                        
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <p className="text-sm font-medium text-ink">{doc.filename}</p>
                            <span className="text-xs text-mist">({formatFileSize(doc.file_size)})</span>
                          </div>
                          
                          <div className="flex items-center gap-4 text-xs text-mist">
                            <span>Type: {doc.file_type.toUpperCase()}</span>
                            <span>Uploaded: {new Date(doc.uploaded_at).toLocaleString()}</span>
                            {doc.processed_at && (
                              <span>Processed: {new Date(doc.processed_at).toLocaleString()}</span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <div className="text-right">
                          <p className="text-xs text-mist">Upload</p>
                          <p className={`text-xs font-medium ${
                            doc.upload_status === 'uploaded' ? 'text-sev-elevated' :
                            doc.upload_status === 'failed' ? 'text-ember-bright' :
                            'text-mist'
                          }`}>
                            {doc.upload_status}
                          </p>
                        </div>

                        <div className="text-right">
                          <p className="text-xs text-mist">Extraction</p>
                          <p className={`text-xs font-medium ${
                            doc.extraction_status === 'completed' ? 'text-sev-low' :
                            doc.extraction_status === 'failed' ? 'text-ember-bright' :
                            doc.extraction_status === 'extracting' || doc.extraction_status === 'analyzing' ? 'text-sev-elevated' :
                            'text-mist'
                          }`}>
                            {doc.extraction_status}
                          </p>
                        </div>

                        {doc.upload_status === 'uploaded' && doc.extraction_status !== 'completed' && doc.extraction_status !== 'extracting' && doc.extraction_status !== 'analyzing' && (
                          <button
                            onClick={() => handleExtract(doc.id)}
                            disabled={extracting || deletingId === doc.id}
                            className="px-3 py-1 bg-ember-bright hover:bg-ember-bright/80 text-void rounded text-xs font-medium transition-colors disabled:opacity-50"
                          >
                            {extracting ? 'Extracting...' : 'Extract'}
                          </button>
                        )}
                        
                        {doc.extraction_status !== 'extracting' && doc.extraction_status !== 'analyzing' && doc.upload_status !== 'uploading' && (
                          <button
                            onClick={() => handleDelete(doc.id)}
                            disabled={deletingId === doc.id}
                            className="p-1.5 text-mist hover:text-ember-bright transition-colors rounded hover:bg-void"
                            title="Delete document"
                          >
                            {deletingId === doc.id ? (
                              <Loader2 className="w-4 h-4 animate-spin" />
                            ) : (
                              <Trash2 className="w-4 h-4" />
                            )}
                          </button>
                        )}
                      </div>
                    </div>

                    {doc.error_message && (
                      <div className="mt-3 p-2 bg-void rounded border-l-2 border-ember-bright">
                        <p className="text-xs text-ember-bright font-body">{doc.error_message}</p>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
