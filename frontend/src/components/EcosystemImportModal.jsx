import React, { useState, useEffect } from 'react';
import { Upload, X, Check, Loader2, Server, Globe, FileText, CheckCircle2, Building2, Database } from 'lucide-react';
import { uploadDocument, previewEcosystemImport, confirmEcosystemImport, getDocuments } from '../api/client';
import Panel from './ui/Panel';
import RelationshipTree from './cti/RelationshipTree';

export default function EcosystemImportModal({ isOpen, onClose, customerId, onComplete }) {
  const [step, setStep] = useState('upload'); // upload -> analyzing -> preview
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);
  const [docId, setDocId] = useState(null);
  const [preview, setPreview] = useState(null);
  const [selectedVendors, setSelectedVendors] = useState({});
  const [selectedVendorTech, setSelectedVendorTech] = useState({}); // { vendorIdx: { techIdx: boolean } }
  const [selectedCustomerTech, setSelectedCustomerTech] = useState({});
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!isOpen) {
      setStep('upload');
      setFile(null);
      setError(null);
      setDocId(null);
      setPreview(null);
    }
  }, [isOpen]);

  // Poll for document extraction status
  useEffect(() => {
    if (step !== 'analyzing' || !docId) return;

    const poll = setInterval(async () => {
      try {
        const docs = await getDocuments();
        const doc = docs.find(d => d.id === docId);
        if (doc) {
          if (doc.extraction_status === 'completed') {
            clearInterval(poll);
            loadPreview(docId);
          } else if (doc.extraction_status === 'failed') {
            clearInterval(poll);
            setError(doc.error_message || 'Extraction failed');
            setStep('upload');
          }
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 2000);

    return () => clearInterval(poll);
  }, [step, docId]);

  const loadPreview = async (id) => {
    try {
      const data = await previewEcosystemImport(id);
      setPreview(data);
      
      // Auto-select all by default
      const vSelected = {};
      const vtSelected = {};
      data.vendors.forEach((v, i) => {
        vSelected[i] = true;
        vtSelected[i] = {};
        if (v.technologies) {
          v.technologies.forEach((t, tIdx) => {
            vtSelected[i][tIdx] = true;
          });
        }
      });
      setSelectedVendors(vSelected);
      setSelectedVendorTech(vtSelected);
      
      const cSelected = {};
      data.customer_technologies.forEach((t, i) => cSelected[i] = true);
      setSelectedCustomerTech(cSelected);
      
      setStep('preview');
    } catch (err) {
      setError(err.message || 'Failed to load preview');
      setStep('upload');
    }
  };

  const handleUpload = async (selectedFile) => {
    if (!selectedFile) return;
    setFile(selectedFile);
    setUploading(true);
    setError(null);

    try {
      const res = await uploadDocument(selectedFile);
      setDocId(res.id);
      setStep('analyzing');
    } catch (err) {
      setError(err.message || 'Upload failed');
      setStep('upload');
    } finally {
      setUploading(false);
    }
  };

  const handleConfirm = async () => {
    setSubmitting(true);
    setError(null);

    try {
      const acceptedVendors = [];
      const editedVendors = [];

      preview.vendors.forEach((v, i) => {
        if (selectedVendors[i]) {
          acceptedVendors.push(i);
          // Check if any technologies were deselected
          if (v.technologies) {
            const acceptedTechs = v.technologies.filter((t, tIdx) => selectedVendorTech[i][tIdx]);
            if (acceptedTechs.length !== v.technologies.length) {
              editedVendors.push({
                index: i,
                technologies: acceptedTechs.map(t => typeof t === 'string' ? t : (t.technology || t.name || t))
              });
            }
          }
        }
      });

      const acceptedTech = [];
      preview.customer_technologies.forEach((t, i) => {
        if (selectedCustomerTech[i]) acceptedTech.push(i);
      });

      await confirmEcosystemImport({
        document_id: docId,
        customer_id: customerId,
        accepted_vendors: acceptedVendors,
        edited_vendors: editedVendors.length > 0 ? editedVendors : undefined,
        accepted_customer_technologies: acceptedTech
      });

      onComplete();
    } catch (err) {
      setError(err.message || 'Failed to confirm import');
    } finally {
      setSubmitting(false);
    }
  };

  const toggleVendor = (i, checked) => {
    setSelectedVendors(prev => ({ ...prev, [i]: checked }));
    // Auto toggle its technologies to match vendor selection
    if (preview.vendors[i].technologies) {
      const newTechSelected = { ...selectedVendorTech[i] };
      preview.vendors[i].technologies.forEach((t, tIdx) => {
        newTechSelected[tIdx] = checked;
      });
      setSelectedVendorTech(prev => ({ ...prev, [i]: newTechSelected }));
    }
  };

  const toggleVendorTech = (vIdx, tIdx, checked) => {
    setSelectedVendorTech(prev => ({
      ...prev,
      [vIdx]: { ...prev[vIdx], [tIdx]: checked }
    }));
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-panel border border-hairline rounded-xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl animate-slide-down">
        
        <div className="flex items-center justify-between p-4 border-b border-hairline bg-panel/80">
          <h2 className="text-lg font-display font-semibold text-ink">Import Ecosystem Architecture</h2>
          <button onClick={onClose} className="p-1.5 text-mist hover:text-ink rounded transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex-1 overflow-auto p-6 custom-scrollbar">
          {error && (
            <div className="mb-6 p-3 bg-ember-bright/10 border border-ember-bright/30 rounded text-ember-bright text-sm flex items-center gap-2">
              <X className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}

          {step === 'upload' && (
            <div 
              className="border-2 border-dashed border-hairline rounded-xl p-12 flex flex-col items-center justify-center bg-void hover:border-mist transition-colors cursor-pointer"
              onClick={() => document.getElementById('file-upload').click()}
            >
              <input 
                id="file-upload" 
                type="file" 
                className="hidden" 
                accept=".pdf,.docx,.txt,.md,.csv,.xlsx"
                onChange={(e) => handleUpload(e.target.files[0])}
              />
              <Upload className="w-10 h-10 text-mist mb-4" />
              <p className="text-ink font-medium text-lg mb-1">Upload Architecture Document</p>
              <p className="text-mist text-sm">PDF, DOCX, TXT. We'll automatically extract technologies.</p>
            </div>
          )}

          {step === 'analyzing' && (
            <div className="py-12 flex flex-col items-center justify-center space-y-4">
              <Loader2 className="w-8 h-8 text-viz-blue animate-spin" />
              <p className="text-ink font-medium">Extracting architecture intelligence...</p>
              <p className="text-mist text-xs">Analyzing relationships and correlating technologies.</p>
            </div>
          )}

          {step === 'preview' && preview && (
            <div className="space-y-6">
              <div className="bg-void p-3 border border-hairline rounded flex items-center gap-3">
                <FileText className="w-5 h-5 text-viz-blue" />
                <div>
                  <p className="text-sm font-medium text-ink">{preview.document_name}</p>
                  <p className="text-xs text-mist">Extracted Intelligence Preview</p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Third-Party Vendors */}
                <Panel title={`THIRD-PARTY VENDORS (${preview.vendors.length})`}>
                  <div className="space-y-4">
                    {preview.vendors.map((v, i) => {
                      const vName = v.vendor || v.name || 'Unknown';
                      const isExisting = preview.existing_vendors.some(ev => ev.vendor.toLowerCase() === vName.toLowerCase());
                      return (
                        <div key={i} className="border border-hairline rounded p-3 bg-void">
                          <div className="flex items-start gap-3">
                            <input 
                              type="checkbox" 
                              checked={selectedVendors[i]}
                              onChange={(e) => toggleVendor(i, e.target.checked)}
                              className="mt-1 accent-viz-blue"
                            />
                            <div className="flex-1">
                              <div className="flex items-center gap-2">
                                <Building2 className="w-3.5 h-3.5 text-viz-blue" />
                                <span className="font-bold text-ink text-sm uppercase tracking-wide">{vName}</span>
                                {isExisting && <span className="text-[9px] font-bold bg-viz-blue/10 text-viz-blue px-1.5 py-0.5 rounded border border-viz-blue/30 tracking-widest">EXISTING</span>}
                              </div>
                              {v.technologies && v.technologies.length > 0 && (
                                <div className="mt-3 pl-3 border-l-2 border-hairline space-y-2">
                                  <p className="text-[9px] uppercase text-mist font-bold tracking-widest">Detected Technologies:</p>
                                  {v.technologies.map((t, idx) => (
                                    <label key={idx} className="flex items-center gap-2 text-xs text-ink/90 cursor-pointer">
                                      <input 
                                        type="checkbox"
                                        checked={selectedVendorTech[i][idx] || false}
                                        onChange={(e) => toggleVendorTech(i, idx, e.target.checked)}
                                        className="accent-viz-blue"
                                      />
                                      <Server className="w-3 h-3 text-mist" /> 
                                      {typeof t === 'string' ? t : (t.technology || t.name || t)}
                                    </label>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    {preview.vendors.length === 0 && <p className="text-xs text-mist">No third-party vendors extracted.</p>}
                  </div>
                </Panel>

                {/* Customer Technologies */}
                <Panel title={`CUSTOMER TECHNOLOGIES (${preview.customer_technologies.length})`}>
                  <div className="space-y-2">
                    {preview.customer_technologies.map((t, i) => (
                      <label key={i} className="flex items-center gap-3 p-3 border border-hairline rounded bg-void cursor-pointer hover:border-mist transition-colors">
                        <input 
                          type="checkbox" 
                          checked={selectedCustomerTech[i]}
                          onChange={(e) => setSelectedCustomerTech({...selectedCustomerTech, [i]: e.target.checked})}
                          className="accent-viz-blue"
                        />
                        <div className="flex items-center gap-2 flex-1">
                          <Globe className="w-3.5 h-3.5 text-viz-teal" />
                          <span className="font-medium text-ink text-sm">{typeof t === 'string' ? t : (t.technology || t.name || t)}</span>
                        </div>
                        <span className="text-[10px] text-mist font-mono uppercase tracking-widest">{(typeof t === 'object' && t.category) || 'INFRASTRUCTURE'}</span>
                      </label>
                    ))}
                    {preview.customer_technologies.length === 0 && <p className="text-xs text-mist">No internal technologies extracted.</p>}
                  </div>
                </Panel>
              </div>
            </div>
          )}
        </div>

        {step === 'preview' && (
          <div className="p-4 border-t border-hairline bg-panel flex justify-end gap-3 rounded-b-xl">
            <button 
              onClick={() => setStep('upload')}
              className="px-4 py-2 text-sm text-mist hover:text-ink font-medium"
              disabled={submitting}
            >
              Cancel
            </button>
            <button 
              onClick={handleConfirm}
              disabled={submitting}
              className="px-6 py-2 bg-viz-blue hover:bg-viz-blue/90 text-white font-semibold rounded text-sm transition-colors flex items-center gap-2 disabled:opacity-50"
            >
              {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
              CONFIRM ECOSYSTEM
            </button>
          </div>
        )}

      </div>
    </div>
  );
}
