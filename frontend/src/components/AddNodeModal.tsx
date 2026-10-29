import React, { useState } from 'react';
import {
  X,
  Shield,
  Server,
  Laptop,
  Database,
  KeyRound,
  Crosshair,
  Printer,
  Crown,
  PlusCircle,
  Sparkles,
  ShieldCheck,
  AlertTriangle,
} from 'lucide-react';
import { useGraphStore } from '../store/graphStore';
import { NodeType } from '../../../shared/types';

interface PresetAsset {
  label: string;
  type: NodeType;
  cvss: number;
  vulns: string[];
  isCrown: boolean;
  isDecoy: boolean;
  desc: string;
  icon: string;
}

const PRESET_ASSETS: PresetAsset[] = [
  {
    label: 'Cloud WAF & Reverse Proxy',
    type: 'Server',
    cvss: 2.5,
    vulns: [],
    isCrown: false,
    isDecoy: false,
    desc: 'Hardened web gateway with rate limiting & inspection',
    icon: '🛡️',
  },
  {
    label: 'Zero-Trust Bastion Host (MFA)',
    type: 'Workstation',
    cvss: 4.0,
    vulns: [],
    isCrown: false,
    isDecoy: false,
    desc: 'Jump box requiring MFA for all administrator sessions',
    icon: '🏰',
  },
  {
    label: 'Secure Vault Database (Encrypted)',
    type: 'Database',
    cvss: 9.9,
    vulns: ['CVE-2024-DB-SEC'],
    isCrown: true,
    isDecoy: false,
    desc: 'High-value customer records storage (Crown Jewel)',
    icon: '🗄️',
  },
  {
    label: 'Active Deception Honeypot',
    type: 'Decoy',
    cvss: 10.0,
    vulns: ['CVE-BAIT-TRAP'],
    isCrown: false,
    isDecoy: true,
    desc: 'Bait service that traps lateral intrusion pivots',
    icon: '🍯',
  },
  {
    label: 'Least-Privilege IAM Service Principal',
    type: 'IAM',
    cvss: 8.5,
    vulns: ['CVE-IAM-PERM'],
    isCrown: false,
    isDecoy: false,
    desc: 'Scoped cloud credentials with session policy boundary',
    icon: '🔑',
  },
  {
    label: 'Internal Payments Microservice',
    type: 'Server',
    cvss: 7.8,
    vulns: ['CVE-2023-API-INJ'],
    isCrown: false,
    isDecoy: false,
    desc: 'Internal cluster backend service for billing APIs',
    icon: '⚙️',
  },
];

export const AddNodeModal: React.FC = () => {
  const { isAddNodeModalOpen, setIsAddNodeModalOpen, addWhatIfNode } = useGraphStore();

  const [label, setLabel] = useState('Custom Security Asset');
  const [type, setType] = useState<NodeType>('Server');
  const [cvss, setCvss] = useState<number>(5.0);
  const [isCrown, setIsCrown] = useState(false);
  const [isDecoy, setIsDecoy] = useState(false);
  const [status, setStatus] = useState<'secure' | 'compromised' | 'isolated'>('secure');
  const [cveText, setCveText] = useState('CVE-2024-CUSTOM-01');

  if (!isAddNodeModalOpen) return null;

  const handleDeployCustom = (e: React.FormEvent) => {
    e.preventDefault();
    const vulns = cveText
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    addWhatIfNode({
      label,
      type,
      cvss_score: cvss,
      vulnerabilities: vulns,
      is_crown_jewel: isCrown,
      is_decoy: isDecoy,
      status,
    });
    setIsAddNodeModalOpen(false);
  };

  const handleDeployPreset = (p: PresetAsset) => {
    addWhatIfNode({
      label: p.label,
      type: p.type,
      cvss_score: p.cvss,
      vulnerabilities: p.vulns,
      is_crown_jewel: p.isCrown,
      is_decoy: p.isDecoy,
      status: 'secure',
    });
    setIsAddNodeModalOpen(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-in fade-in duration-150">
      <div className="w-full max-w-2xl rounded-2xl bg-slate-900 border border-slate-700/80 p-5 shadow-2xl flex flex-col max-h-[90vh] overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-xl bg-emerald-500/20 text-emerald-400">
              <PlusCircle className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                Deploy Security Asset to Sandbox
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 font-mono">
                  WHAT-IF MODE
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Design custom security architectures and test breach resistance before production rollout.
              </p>
            </div>
          </div>
          <button
            onClick={() => setIsAddNodeModalOpen(false)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto py-4 space-y-4 pr-1 text-xs">
          {/* Quick Presets */}
          <div>
            <div className="flex items-center gap-1.5 mb-2 font-semibold text-slate-300">
              <Sparkles className="w-3.5 h-3.5 text-amber-400" /> 1-Click Defensive Presets
            </div>
            <div className="grid grid-cols-2 gap-2">
              {PRESET_ASSETS.map((p, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => handleDeployPreset(p)}
                  className="p-3 rounded-xl border border-slate-800 bg-slate-950/80 hover:bg-slate-800/80 hover:border-slate-700 text-left transition flex flex-col justify-between group"
                >
                  <div>
                    <div className="font-bold text-slate-200 text-xs flex items-center gap-1.5 mb-1 group-hover:text-emerald-300 transition">
                      <span>{p.icon}</span> {p.label}
                    </div>
                    <div className="text-[11px] text-slate-400 line-clamp-1 mb-2">{p.desc}</div>
                  </div>
                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                    <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-sky-300">
                      {p.type}
                    </span>
                    <span
                      className={`font-semibold ${
                        p.cvss >= 8
                          ? 'text-red-400'
                          : p.cvss >= 5
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      CVSS {p.cvss}
                    </span>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Custom Asset Builder Form */}
          <form onSubmit={handleDeployCustom} className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3">
            <div className="font-semibold text-slate-200 flex items-center gap-1.5 pb-1 border-b border-slate-800/80">
              <Shield className="w-3.5 h-3.5 text-sky-400" /> Custom Architecture Asset Specification
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] font-medium text-slate-400 block mb-1">Asset Label / Hostname</label>
                <input
                  type="text"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  required
                  placeholder="e.g. Edge-API-Proxy-v1"
                  className="w-full px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono focus:outline-none focus:border-sky-500"
                />
              </div>

              <div>
                <label className="text-[10px] font-medium text-slate-400 block mb-1">Asset Infrastructure Type</label>
                <select
                  value={type}
                  onChange={(e) => {
                    const newType = e.target.value as NodeType;
                    setType(newType);
                    if (newType === 'Decoy') setIsDecoy(true);
                    if (newType === 'Database') setIsCrown(true);
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-sky-500"
                >
                  <option value="Server">Server / Microservice</option>
                  <option value="Workstation">Workstation / Client</option>
                  <option value="Database">Database / Vault</option>
                  <option value="IAM">IAM Role / Service Principal</option>
                  <option value="Decoy">Decoy Honeypot</option>
                  <option value="IoT">IoT Gateway / Appliance</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1">
                  <span>Vulnerability Score (CVSS)</span>
                  <span className="font-mono font-bold text-amber-300">{cvss.toFixed(1)}</span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="10"
                  step="0.5"
                  value={cvss}
                  onChange={(e) => setCvss(parseFloat(e.target.value))}
                  className="w-full accent-amber-500 cursor-pointer"
                />
              </div>

              <div>
                <label className="text-[10px] font-medium text-slate-400 block mb-1">Initial Security State</label>
                <select
                  value={status}
                  onChange={(e) => setStatus(e.target.value as any)}
                  className="w-full px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-sky-500"
                >
                  <option value="secure">Secure (Normal Operating)</option>
                  <option value="compromised">Compromised (Test as Entry Foothold)</option>
                  <option value="isolated">Isolated (Quarantined Host)</option>
                </select>
              </div>
            </div>

            <div>
              <label className="text-[10px] font-medium text-slate-400 block mb-1">CVE Identifiers (Comma-separated)</label>
              <input
                type="text"
                value={cveText}
                onChange={(e) => setCveText(e.target.value)}
                placeholder="CVE-2024-XXXX, CVE-2023-YYYY"
                className="w-full px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono focus:outline-none focus:border-sky-500"
              />
            </div>

            <div className="flex items-center gap-4 pt-1">
              <label className="flex items-center gap-2 cursor-pointer text-slate-300 hover:text-white">
                <input
                  type="checkbox"
                  checked={isCrown}
                  onChange={(e) => setIsCrown(e.target.checked)}
                  className="accent-amber-400 w-4 h-4 rounded"
                />
                <span className="flex items-center gap-1 font-medium">
                  <Crown className="w-3.5 h-3.5 text-amber-400" /> Crown Jewel Target
                </span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer text-slate-300 hover:text-white">
                <input
                  type="checkbox"
                  checked={isDecoy}
                  onChange={(e) => setIsDecoy(e.target.checked)}
                  className="accent-cyan-400 w-4 h-4 rounded"
                />
                <span className="flex items-center gap-1 font-medium">
                  <Crosshair className="w-3.5 h-3.5 text-cyan-400" /> Active Honeypot / Decoy
                </span>
              </label>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setIsAddNodeModalOpen(false)}
                className="px-3 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-slate-200 bg-slate-900 hover:bg-slate-800 transition"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded-lg text-xs font-bold text-white bg-emerald-600 hover:bg-emerald-500 transition shadow flex items-center gap-1.5"
              >
                <PlusCircle className="w-3.5 h-3.5" /> Deploy Custom Asset
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};
