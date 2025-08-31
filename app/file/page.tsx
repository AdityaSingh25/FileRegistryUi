"use client";

import React, { useEffect, useMemo, useState } from "react";
import axios from "axios";
import {
  useAccount,
  usePublicClient,
  useWalletClient,
  useWriteContract,
  useWaitForTransactionReceipt,
  useReadContract,
} from "wagmi";
import { keccak256, stringToBytes, bytesToHex, pad } from "viem";
import { ABI } from "../components/contract";
import useContractAddress from "../hooks/useContractAddress";
import {
  Check,
  Copy,
  Download,
  FileUp,
  Search,
  ShieldCheck,
  TriangleAlert,
  RefreshCw,
} from "lucide-react";

/* ─────────────────────────────────────────────
   EIP-712 Domain & Types (client signing)
   ───────────────────────────────────────────── */
const EIP712_DOMAIN = {
  name: "FileRegistry",
  version: "1",
} as const;

const FILE_PROOF_TYPES = {
  FileProof: [
    { name: "fileId", type: "bytes32" },
    { name: "digest", type: "bytes32" },
    { name: "uri", type: "string" },
    { name: "size", type: "uint256" },
    { name: "privacyMode", type: "uint8" },
    { name: "prevDigest", type: "bytes32" },
    { name: "fileTimestamp", type: "uint64" },
    { name: "nonce", type: "uint256" },
    { name: "deptId", type: "bytes32" },
  ],
} as const;

/* ─────────────────────────────────────────────
   Utils
   ───────────────────────────────────────────── */
export type Hex32 = `0x${string}`;
const ZERO32 = ("0x" + "00".repeat(32)) as Hex32;

function clsx(...xs: Array<string | false | undefined>) {
  return xs.filter(Boolean).join(" ");
}

function shorten(addr?: string | null) {
  return addr ? `${addr.slice(0, 6)}...${addr.slice(-4)}` : "Not connected";
}

/** human-readable bytes */
function prettyBytes(bn?: bigint | number | null) {
  if (bn === undefined || bn === null) return "-";
  const n = typeof bn === "bigint" ? Number(bn) : bn;
  const units = ["B", "KB", "MB", "GB", "TB"] as const;
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(2)} ${units[i]}`;
}

/** Normalize to bytes32 */
function ensureBytes32(input: string): Hex32 {
  if (!input) return ZERO32;

  if (input.startsWith("0x")) {
    let hex = input as `0x${string}`;
    if ((hex.length - 2) % 2 !== 0) hex = `0x0${hex.slice(2)}` as `0x${string}`;
    const byteLen = (hex.length - 2) / 2;
    if (byteLen === 32) return hex as Hex32;
    if (byteLen > 32) return keccak256(hex) as Hex32;
    return pad(hex, { size: 32, dir: "left" }) as Hex32;
  }
  return keccak256(stringToBytes(input)) as Hex32;
}

// WebCrypto SHA-256 (returns bytes32 hex)
async function sha256HexFile(file: File): Promise<Hex32> {
  const buf = await file.arrayBuffer();
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return bytesToHex(new Uint8Array(hash)) as Hex32;
}
async function sha256HexArrayBuffer(buf: ArrayBuffer): Promise<Hex32> {
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return bytesToHex(new Uint8Array(hash)) as Hex32;
}

function Copyable({ text, className }: { text: string; className?: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      type="button"
      className={clsx(
        "inline-flex items-center gap-1 text-xs text-gray-300 hover:text-white transition",
        className
      )}
      onClick={async () => {
        await navigator.clipboard.writeText(text);
        setOk(true);
        setTimeout(() => setOk(false), 1200);
      }}
      title="Copy"
    >
      {ok ? <Check size={14} /> : <Copy size={14} />} {ok ? "Copied" : "Copy"}
    </button>
  );
}

function Badge({
  ok,
  label,
  details,
}: {
  ok: boolean | null;
  label: string;
  details?: string;
}) {
  if (ok === null)
    return (
      <div className="inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs bg-gray-700 text-gray-200">
        <RefreshCw size={14} className="animate-spin" /> {label}
      </div>
    );
  return (
    <div
      className={clsx(
        "inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs",
        ok
          ? "bg-emerald-700/70 text-emerald-100"
          : "bg-rose-700/70 text-rose-100"
      )}
      title={details}
    >
      {ok ? <ShieldCheck size={14} /> : <TriangleAlert size={14} />} {label}
    </div>
  );
}

/* ─────────────────────────────────────────────
   Navbar
   ───────────────────────────────────────────── */
function Navbar({
  tab,
  setTab,
}: {
  tab: "upload" | "retrieve" | "verify";
  setTab: (t: "upload" | "retrieve" | "verify") => void;
}) {
  const { address, chain } = useAccount();

  const NavButton = ({
    id,
    label,
    activeClass,
  }: {
    id: "upload" | "retrieve" | "verify";
    label: string;
    activeClass: string;
  }) => (
    <button
      onClick={() => setTab(id)}
      className={clsx(
        "px-3 py-1.5 rounded-lg text-sm font-medium transition",
        tab === id
          ? activeClass
          : "text-gray-300 hover:text-white hover:bg-gray-800/70"
      )}
      type="button"
    >
      {label}
    </button>
  );

  return (
    <header className="sticky top-0 z-50 border-b border-white/10 bg-gray-950/65 backdrop-blur-xl supports-[backdrop-filter]:bg-gray-950/55">
      <div className="max-w-5xl mx-auto px-4">
        <div className="h-14 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <div className="text-lg font-extrabold tracking-tight text-gray-100">
              File<span className="text-purple-400">Registry</span>
            </div>
            <span className="hidden md:inline text-[11px] text-gray-400">
              IPFS • EIP-712 • On-chain proofs
            </span>
          </div>

          <nav className="hidden sm:flex items-center gap-1">
            <NavButton
              id="upload"
              label="Upload & Register"
              activeClass="bg-purple-600 text-white"
            />
            <NavButton
              id="retrieve"
              label="Retrieve & Download"
              activeClass="bg-sky-600 text-white"
            />
            <NavButton
              id="verify"
              label="Verify"
              activeClass="bg-emerald-600 text-white"
            />
          </nav>

          <div className="flex items-center gap-2">
            <div className="hidden md:flex items-center gap-2 text-[11px] text-gray-400">
              <span>Chain</span>
              <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-200 border border-gray-700">
                {chain?.id ?? "—"}
              </span>
            </div>
            <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-full border border-gray-700 bg-gray-800/80 text-xs text-gray-200">
              <span
                className={clsx(
                  "inline-block w-2 h-2 rounded-full",
                  address ? "bg-emerald-500" : "bg-rose-500"
                )}
              />
              <span className="font-mono">{shorten(address)}</span>
            </div>
          </div>
        </div>

        {/* Mobile nav */}
        <div className="sm:hidden pb-2">
          <div className="flex gap-2 overflow-x-auto">
            <NavButton
              id="upload"
              label="Upload"
              activeClass="bg-purple-600 text-white"
            />
            <NavButton
              id="retrieve"
              label="Retrieve"
              activeClass="bg-sky-600 text-white"
            />
            <NavButton
              id="verify"
              label="Verify"
              activeClass="bg-emerald-600 text-white"
            />
          </div>
        </div>
      </div>
    </header>
  );
}

/* ─────────────────────────────────────────────
   Latest viewer (guarded: avoids revert on empty)
   ───────────────────────────────────────────── */
function Latest({ fileId }: { fileId: Hex32 }) {
  const contractAddress = useContractAddress();

  const {
    data: count,
    isLoading: loadingCount,
    error: countErr,
    refetch: refetchCount,
  } = useReadContract({
    address: contractAddress,
    abi: ABI,
    functionName: "versionsCount",
    args: [fileId],
  });

  const enabled = (typeof count === "bigint" ? count : BigInt(0)) > BigInt(0);

  const { data, error, isLoading, refetch } = useReadContract({
    address: contractAddress,
    abi: ABI,
    functionName: "latest",
    args: [fileId],
    query: { enabled },
  });

  return (
    <div className="mt-6 bg-gray-900 border border-gray-800 rounded-xl p-4 text-xs text-gray-200">
      <div className="flex items-center justify-between mb-2">
        <div className="font-semibold">Latest Version</div>
        <button
          className="text-[11px] px-2 py-1 rounded bg-gray-800 hover:bg-gray-700"
          onClick={() => {
            refetch();
            refetchCount();
          }}
        >
          Refresh
        </button>
      </div>

      {loadingCount && <div>Loading…</div>}
      {countErr && (
        <div className="text-rose-400">
          {String((countErr as any).message || countErr)}
        </div>
      )}
      {!enabled && !loadingCount && <div>No versions yet.</div>}
      {enabled && isLoading && <div>Loading latest…</div>}
      {enabled && error && (
        <div className="text-rose-400">
          {String((error as any).message || error)}
        </div>
      )}

      {enabled && !!data && (
        <div className="grid grid-cols-1 md:grid-cols-2 items-start gap-3 mt-2">
          <div className="min-w-0 md:col-span-2">
            <div className="text-gray-400">digest</div>
            <div className="font-mono break-all">
              {String((data as any).digest)}
            </div>
          </div>

          <div className="min-w-0 md:col-span-2">
            <div className="text-gray-400">prevDigest</div>
            <div className="font-mono break-all">
              {String((data as any).prevDigest)}
            </div>
          </div>

          <div className="min-w-0">
            <div className="text-gray-400">uriHash</div>
            <div className="font-mono break-all">
              {String((data as any).uriHash)}
            </div>
          </div>

          <div className="min-w-0">
            <div className="text-gray-400">size</div>
            <div>
              {String((data as any).size?.toString?.())} (
              {prettyBytes((data as any).size)})
            </div>
          </div>

          <div className="min-w-0">
            <div className="text-gray-400">fileTimestamp</div>
            <div>{String((data as any).fileTimestamp?.toString?.())}</div>
          </div>

          <div className="min-w-0">
            <div className="text-gray-400">privacyMode</div>
            <div>{String((data as any).privacyMode)}</div>
          </div>

          <div className="min-w-0">
            <div className="text-gray-400">signer</div>
            <div className="font-mono break-all">
              {String((data as any).signer)}
            </div>
          </div>

          <div className="min-w-0">
            <div className="text-gray-400">frozen</div>
            <div>{String((data as any).frozen)}</div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ─────────────────────────────────────────────
   Upload & Register
   ───────────────────────────────────────────── */
function UploadPanel() {
  const { address: account, chain } = useAccount();
  const { data: wallet } = useWalletClient();
  const publicClient = usePublicClient();
  const contractAddress = useContractAddress();

  const [file, setFile] = useState<File | null>(null);
  const [fileUrl, setFileUrl] = useState<string>("");
  const [fileIdInput, setFileIdInput] = useState("file-001");
  const [deptInput, setDeptInput] = useState("dept-A");
  const [privacyMode, setPrivacyMode] = useState<number>(0);
  const [prevDigestInput, setPrevDigestInput] = useState("0x0");

  const fileId = useMemo(
    () => ensureBytes32(fileIdInput || "file-001"),
    [fileIdInput]
  );
  const deptId = useMemo(
    () => ensureBytes32(deptInput || "dept-A"),
    [deptInput]
  );
  const prevDigest = useMemo(() => {
    if ((prevDigestInput ?? "").toLowerCase() === "0x0") return ZERO32;
    return ensureBytes32(prevDigestInput || "0x0");
  }, [prevDigestInput]);

  const { writeContract, data: txHash, isPending, error } = useWriteContract();
  const { isLoading: isConfirming, isSuccess: isConfirmed } =
    useWaitForTransactionReceipt({ hash: txHash });

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();

    try {
      if (!file) throw new Error("No file selected");
      if (!account) throw new Error("No account connected");
      if (!wallet) throw new Error("No wallet client available");
      if (!publicClient) throw new Error("No public client available");
      if (!contractAddress)
        throw new Error(
          `No contract mapped for chain ${chain?.id ?? "unknown"}`
        );

      const code = await publicClient.getCode({ address: contractAddress });
      if (!code || code === "0x")
        throw new Error(
          `No contract code at ${contractAddress} on chain ${chain?.id}. Switch to the correct network or update CONTRACTS.`
        );

      if (
        !process.env.NEXT_PUBLIC_PINATA_API_KEY ||
        !process.env.NEXT_PUBLIC_PINATA_SECRET_API_KEY
      ) {
        throw new Error("Pinata API keys are missing");
      }

      // 1) Upload to Pinata
      const fd = new FormData();
      fd.append("file", file);
      const resp = await axios.post(
        "https://api.pinata.cloud/pinning/pinFileToIPFS",
        fd,
        {
          headers: {
            pinata_api_key: String(process.env.NEXT_PUBLIC_PINATA_API_KEY),
            pinata_secret_api_key: String(
              process.env.NEXT_PUBLIC_PINATA_SECRET_API_KEY
            ),
            "Content-Type": "multipart/form-data",
          },
        }
      );
      const url = `https://gateway.pinata.cloud/ipfs/${resp.data.IpfsHash}`;
      setFileUrl(url);

      // 2) File digest & size
      const digest = await sha256HexFile(file);
      const size = BigInt(file.size);

      // 3) Nonce
      const nonce = (await publicClient.readContract({
        address: contractAddress,
        abi: ABI,
        functionName: "nonces",
        args: [account],
      })) as bigint;

      // 4) Timestamp / chain
      const fileTimestamp = BigInt(Math.floor(Date.now() / 1000));
      const chainId = chain?.id ?? (await publicClient.getChainId());

      // 5) EIP-712 sign
      const signature = await wallet.signTypedData({
        account,
        domain: {
          name: EIP712_DOMAIN.name,
          version: EIP712_DOMAIN.version,
          chainId,
          verifyingContract: contractAddress,
        },
        types: FILE_PROOF_TYPES,
        primaryType: "FileProof",
        message: {
          fileId,
          digest,
          uri: url,
          size,
          privacyMode,
          prevDigest,
          fileTimestamp,
          nonce,
          deptId,
        },
      });

      // 6) Send tx
      writeContract({
        address: contractAddress,
        abi: ABI,
        functionName: "register",
        args: [
          fileId,
          digest,
          url,
          size,
          privacyMode,
          prevDigest,
          fileTimestamp,
          deptId,
          signature as `0x${string}`,
        ],
        account,
      });

      // Save URL locally
      try {
        const key = `fileregistry:urls`;
        const existing = JSON.parse(localStorage.getItem(key) || "{}");
        existing[String(fileId)] = url;
        localStorage.setItem(key, JSON.stringify(existing));
      } catch {}
    } catch (err) {
      console.error(err);
      alert((err as Error).message ?? String(err));
    }
  }

  return (
    <div className="bg-gray-900 rounded-xl shadow-lg p-6 w-full border border-gray-800">
      <h3 className="text-xl font-bold mb-4 flex items-center gap-2 text-purple-300">
        <FileUp size={18} /> Upload & Register
      </h3>

      <div className="mb-4 p-3 bg-gray-800 rounded-lg text-sm">
        <div className="text-gray-300">Connection Status:</div>
        <div className="text-xs mt-1">Account: {shorten(account)}</div>
        <div className="text-xs">
          Wallet: {Boolean(wallet) ? "✅" : "❌"} | Public Client:{" "}
          {Boolean(usePublicClient) ? "✅" : "❌"}
        </div>
        <div className="text-xs">
          Contract: <span className="break-all">{contractAddress}</span>
        </div>
        <div className="text-xs">Chain ID: {chain?.id ?? "unknown"}</div>
      </div>

      <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
        <label className="flex flex-col items-center justify-center border-2 border-dashed border-purple-300 rounded-lg p-6 cursor-pointer hover:border-purple-500 transition">
          <span className="text-purple-400 font-medium mb-2">
            Choose a file
          </span>
          <input
            type="file"
            className="hidden"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
          {file && (
            <span className="mt-2 text-sm text-gray-400">{file.name}</span>
          )}
        </label>

        <div className="grid gap-1">
          <label className="text-sm text-gray-300">
            File ID (bytes32 or text)
          </label>
          <input
            className="bg-gray-800 text-gray-100 border border-gray-700 rounded px-3 py-2"
            value={fileIdInput}
            onChange={(e) => setFileIdInput(e.target.value)}
            placeholder="file-001 or 0x..."
            spellCheck={false}
          />
        </div>
        <div className="text-[11px] text-gray-500 flex items-center gap-2">
          Resolved: <span className="break-all">{fileId}</span>{" "}
          <Copyable text={fileId} />
        </div>

        <div className="grid gap-1">
          <label className="text-sm text-gray-300">
            Department (bytes32 or text)
          </label>
          <input
            className="bg-gray-800 text-gray-100 border border-gray-700 rounded px-3 py-2"
            value={deptInput}
            onChange={(e) => setDeptInput(e.target.value)}
            placeholder="dept-A"
            spellCheck={false}
          />
        </div>
        <div className="text-[11px] text-gray-500">Resolved: {deptId}</div>

        <div className="grid gap-1">
          <label className="text-sm text-gray-300">
            Previous Digest (0x0 for first)
          </label>
          <input
            className="bg-gray-800 text-gray-100 border border-gray-700 rounded px-3 py-2"
            value={prevDigestInput}
            onChange={(e) => setPrevDigestInput(e.target.value)}
            placeholder="0x0 or 0x…"
            spellCheck={false}
          />
        </div>
        <div className="text-[11px] text-gray-500">Resolved: {prevDigest}</div>

        <div className="grid gap-1">
          <label className="text-sm text-gray-300">Privacy Mode (0,1,2)</label>
          <input
            type="number"
            min={0}
            max={2}
            className="bg-gray-800 text-gray-100 border border-gray-700 rounded px-3 py-2 w-24"
            value={privacyMode}
            onChange={(e) => setPrivacyMode(parseInt(e.target.value || "0"))}
          />
        </div>

        <button
          type="submit"
          disabled={isPending}
          className="bg-purple-600 text-white py-2 px-4 rounded-lg font-semibold shadow hover:bg-purple-700 transition disabled:opacity-60"
        >
          {isPending ? "Submitting…" : "Upload to IPFS & Register"}
        </button>

        {fileUrl && (
          <div className="text-xs text-gray-300">
            IPFS URL:{" "}
            <a
              href={fileUrl}
              target="_blank"
              className="underline break-all"
              rel="noreferrer"
            >
              {fileUrl}
            </a>
          </div>
        )}

        {txHash && (
          <div className="text-xs text-gray-300 break-all">tx: {txHash}</div>
        )}
        {isConfirming && (
          <div className="text-sm text-amber-400">
            Waiting for confirmation…
          </div>
        )}
        {isConfirmed && (
          <div className="text-sm text-green-400">Confirmed ✅</div>
        )}
        {error && (
          <div className="text-sm text-rose-400">{(error as any).message}</div>
        )}
      </form>

      <Latest fileId={fileId} />
    </div>
  );
}

/* ─────────────────────────────────────────────
   Retrieve (Latest) & Download
   ───────────────────────────────────────────── */
function RetrievePanel() {
  const contractAddress = useContractAddress();
  const [query, setQuery] = useState<string>("file-001");
  const [fileId, setFileId] = useState<Hex32>(ensureBytes32("file-001"));
  const [knownUrl, setKnownUrl] = useState<string>("");

  useEffect(() => {
    try {
      const db = JSON.parse(localStorage.getItem("fileregistry:urls") || "{}");
      const url = db[String(fileId)];
      if (typeof url === "string") setKnownUrl(url);
    } catch {}
  }, [fileId]);

  const { data: count } = useReadContract({
    address: contractAddress,
    abi: ABI,
    functionName: "versionsCount",
    args: [fileId],
  });

  const enabled = (typeof count === "bigint" ? count : BigInt(0)) > BigInt(0);
  const { data, isLoading, error } = useReadContract({
    address: contractAddress,
    abi: ABI,
    functionName: "latest",
    args: [fileId],
    query: { enabled },
  });

  return (
    <div className="bg-gray-900 rounded-xl shadow-lg p-6 w-full border border-gray-800">
      <h3 className="text-xl font-bold mb-4 flex items-center gap-2 text-sky-300">
        <Search size={18} /> Retrieve & Download
      </h3>

      <div className="grid md:grid-cols-[1fr_auto] gap-3 items-end">
        <div className="grid gap-1">
          <label className="text-sm text-gray-300">File ID or Hex</label>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="bg-gray-800 text-gray-100 border border-gray-700 rounded px-3 py-2"
            placeholder="file-001 or 0x…"
            spellCheck={false}
          />
          <div className="text-[11px] text-gray-500 break-all">
            Resolved: {fileId as string}
          </div>
        </div>
        <button
          className="h-10 px-4 rounded bg-gray-800 hover:bg-gray-700 text-gray-100"
          onClick={() => setFileId(ensureBytes32(query))}
        >
          Load Latest
        </button>
      </div>

      <div className="mt-4">
        {isLoading && <div className="text-sm">Loading latest…</div>}
        {error && (
          <div className="text-sm text-rose-400">
            {String((error as any).message || error)}
          </div>
        )}
        {!enabled && (
          <div className="text-sm text-gray-400">
            No versions found for this File ID.
          </div>
        )}

        {enabled && !!data && (
          <div className="rounded-lg border border-gray-800 bg-gray-950 p-4 text-xs text-gray-200">
            <div className="font-semibold mb-2">Latest Metadata</div>

            <div className="grid grid-cols-1 md:grid-cols-2 items-start gap-3">
              <div className="min-w-0 md:col-span-2">
                <div className="text-gray-400">digest</div>
                <div className="font-mono break-all">
                  {String((data as any).digest)}
                </div>
              </div>

              <div className="min-w-0 md:col-span-2">
                <div className="text-gray-400">prevDigest</div>
                <div className="font-mono break-all">
                  {String((data as any).prevDigest)}
                </div>
              </div>

              <div className="min-w-0">
                <div className="text-gray-400">uriHash</div>
                <div className="font-mono break-all">
                  {String((data as any).uriHash)}
                </div>
              </div>

              <div className="min-w-0">
                <div className="text-gray-400">size</div>
                <div>
                  {String((data as any).size?.toString?.())} (
                  {prettyBytes((data as any).size)})
                </div>
              </div>

              <div className="min-w-0">
                <div className="text-gray-400">privacyMode</div>
                <div>{String((data as any).privacyMode)}</div>
              </div>

              <div className="min-w-0">
                <div className="text-gray-400">signer</div>
                <div className="font-mono break-all">
                  {String((data as any).signer)}
                </div>
              </div>
            </div>

            <div className="mt-4 grid md:grid-cols-[1fr_auto] gap-2 items-end">
              <div className="grid gap-1">
                <label className="text-[12px] text-gray-400">
                  Known URL (saved locally after upload or paste manually)
                </label>
                <input
                  value={knownUrl}
                  onChange={(e) => setKnownUrl(e.target.value)}
                  placeholder="https://gateway.pinata.cloud/ipfs/<cid>"
                  className="bg-gray-800 text-gray-100 border border-gray-700 rounded px-3 py-2"
                  spellCheck={false}
                />
              </div>
              <a
                href={knownUrl || "#"}
                download
                target="_blank"
                className={clsx(
                  "h-10 inline-flex items-center justify-center gap-2 px-4 rounded font-medium",
                  knownUrl
                    ? "bg-sky-600 hover:bg-sky-700 text-white"
                    : "bg-gray-700 text-gray-400 cursor-not-allowed"
                )}
                rel="noreferrer"
              >
                <Download size={16} /> Download
              </a>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────
   Verify Panel (Integrity & Binding)
   ───────────────────────────────────────────── */
function VerifyPanel() {
  const contractAddress = useContractAddress();

  const [query, setQuery] = useState<string>("file-001");
  const [fileId, setFileId] = useState<Hex32>(ensureBytes32("file-001"));

  const [source, setSource] = useState<"local" | "remote">("local");
  const [localFile, setLocalFile] = useState<File | null>(null);
  const [remoteUrl, setRemoteUrl] = useState<string>("");

  const [checking, setChecking] = useState(false);
  const [digestOk, setDigestOk] = useState<boolean | null>(null);
  const [sizeOk, setSizeOk] = useState<boolean | null>(null);
  const [uriOk, setUriOk] = useState<boolean | null>(null);
  const [notes, setNotes] = useState<string>("");

  const { data: count } = useReadContract({
    address: contractAddress,
    abi: ABI,
    functionName: "versionsCount",
    args: [fileId],
  });

  const enabled = (typeof count === "bigint" ? count : BigInt(0)) > BigInt(0);
  const { data, error } = useReadContract({
    address: contractAddress,
    abi: ABI,
    functionName: "latest",
    args: [fileId],
    query: { enabled },
  });

  const v: any = data || {};

  useEffect(() => {
    try {
      const db = JSON.parse(localStorage.getItem("fileregistry:urls") || "{}");
      const url = db[String(fileId)];
      if (typeof url === "string") setRemoteUrl(url);
    } catch {}
  }, [fileId]);

  async function runChecks() {
    setChecking(true);
    setDigestOk(null);
    setSizeOk(null);
    setUriOk(null);
    setNotes("");

    try {
      if (!enabled || !data)
        throw new Error("No on-chain version for this File ID");

      let buf: ArrayBuffer;
      let fileSize: bigint;

      if (source === "local") {
        if (!localFile) throw new Error("Select a local file first");
        buf = await localFile.arrayBuffer();
        fileSize = BigInt(localFile.size);
      } else {
        if (!remoteUrl) throw new Error("Provide the file URL");
        const res = await fetch(remoteUrl);
        if (!res.ok)
          throw new Error(`Failed to fetch remote file (${res.status})`);
        const blob = await res.blob();
        buf = await blob.arrayBuffer();
        fileSize = BigInt(blob.size);
      }

      const sizeMatch = fileSize === (v.size as bigint);
      setSizeOk(sizeMatch);

      const digest = await sha256HexArrayBuffer(buf);
      const digestMatch =
        digest.toLowerCase() === String(v.digest).toLowerCase();
      setDigestOk(digestMatch);

      if (source === "remote" && remoteUrl) {
        const uhash = keccak256(stringToBytes(remoteUrl));
        const uriMatch =
          uhash.toLowerCase() === String(v.uriHash).toLowerCase();
        setUriOk(uriMatch);
      } else {
        setUriOk(false);
      }

      const note = [
        `size: ${
          sizeMatch ? "OK" : "MISMATCH"
        } (on-chain ${v.size?.toString?.()})`,
        `digest: ${digestMatch ? "OK" : "MISMATCH"}`,
        `uriHash: ${
          source === "remote"
            ? uriOk
              ? "OK"
              : "MISMATCH"
            : "(skipped – need URL)"
        }`,
      ].join("\n");
      setNotes(note);
    } catch (e: any) {
      setNotes(e?.message || String(e));
    } finally {
      setChecking(false);
    }
  }

  return (
    <div className="bg-gray-900 rounded-xl shadow-lg p-6 w-full border border-gray-800">
      <h3 className="text-xl font-bold mb-4 flex items-center gap-2 text-emerald-300">
        <ShieldCheck size={18} /> Verify Integrity & Binding
      </h3>

      <div className="grid md:grid-cols-[1fr_auto] gap-3 items-end">
        <div className="grid gap-1">
          <label className="text-sm text-gray-300">File ID or Hex</label>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="bg-gray-800 text-gray-100 border border-gray-700 rounded px-3 py-2"
            placeholder="file-001 or 0x…"
            spellCheck={false}
          />
          <div className="text-[11px] text-gray-500 break-all">
            Resolved: {fileId as string}
          </div>
        </div>
        <button
          className="h-10 px-4 rounded bg-gray-800 hover:bg-gray-700 text-gray-100"
          onClick={() => setFileId(ensureBytes32(query))}
        >
          Load On-chain Latest
        </button>
      </div>

      <div className="mt-4 rounded-lg border border-gray-800 bg-gray-950 p-4 text-xs text-gray-200">
        {!enabled && (
          <div className="text-sm text-gray-400">
            No versions found for this File ID.
          </div>
        )}
        {enabled && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="min-w-0">
              <div className="text-gray-400">digest</div>
              <div className="font-mono break-all">{String(v.digest)}</div>
            </div>
            <div className="min-w-0">
              <div className="text-gray-400">uriHash</div>
              <div className="font-mono break-all">{String(v.uriHash)}</div>
            </div>
            <div className="min-w-0">
              <div className="text-gray-400">size</div>
              <div>
                {String(v.size?.toString?.())} ({prettyBytes(v.size)})
              </div>
            </div>
            <div className="min-w-0">
              <div className="text-gray-400">signer</div>
              <div className="font-mono break-all">{String(v.signer)}</div>
            </div>
          </div>
        )}
      </div>

      <div className="mt-4 grid gap-3">
        <div className="flex gap-2 text-sm">
          <button
            className={clsx(
              "px-3 py-1.5 rounded border",
              source === "local"
                ? "bg-gray-800 border-gray-700"
                : "bg-gray-900 border-gray-800"
            )}
            onClick={() => setSource("local")}
            type="button"
          >
            Verify using local file
          </button>
          <button
            className={clsx(
              "px-3 py-1.5 rounded border",
              source === "remote"
                ? "bg-gray-800 border-gray-700"
                : "bg-gray-900 border-gray-800"
            )}
            onClick={() => setSource("remote")}
            type="button"
          >
            Verify using URL
          </button>
        </div>

        {source === "local" ? (
          <label className="flex flex-col items-center justify-center border-2 border-dashed border-emerald-300 rounded-lg p-6 cursor-pointer hover:border-emerald-500 transition">
            <span className="text-emerald-400 font-medium mb-2">
              Choose the original file
            </span>
            <input
              type="file"
              className="hidden"
              onChange={(e) => setLocalFile(e.target.files?.[0] ?? null)}
            />
            {localFile && (
              <span className="mt-2 text-sm text-gray-400">
                {localFile.name}
              </span>
            )}
          </label>
        ) : (
          <div className="grid gap-1">
            <label className="text-[12px] text-gray-400">
              URL used during upload (gateway link)
            </label>
            <input
              value={remoteUrl}
              onChange={(e) => setRemoteUrl(e.target.value)}
              placeholder="https://gateway.pinata.cloud/ipfs/<cid>"
              className="bg-gray-800 text-gray-100 border border-gray-700 rounded px-3 py-2"
              spellCheck={false}
            />
          </div>
        )}

        <div className="flex items-center gap-3">
          <button
            onClick={runChecks}
            disabled={checking}
            className="px-4 py-2 rounded bg-emerald-600 hover:bg-emerald-700 text-white disabled:opacity-60"
          >
            {checking ? "Verifying…" : "Run Verification"}
          </button>
          <Badge ok={sizeOk} label="Size" />
          <Badge ok={digestOk} label="SHA-256 digest" />
          <Badge ok={uriOk} label="URL binding" />
        </div>

        {notes && (
          <pre className="mt-2 text-[11px] bg-gray-950/80 border border-gray-800 rounded p-3 whitespace-pre-wrap">
            {notes}
          </pre>
        )}
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────
   Top-level Page with Navbar + Tabs
   ───────────────────────────────────────────── */
export default function FileRegistryUI() {
  const [tab, setTab] = useState<"upload" | "retrieve" | "verify">("upload");

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-950">
      <Navbar tab={tab} setTab={setTab} />

      <main className="flex flex-col items-center justify-start pt-6 pb-12 px-4">
        <h1 className="text-3xl font-extrabold text-center mb-2 text-gray-100">
          File transfer using{" "}
          <span className="bg-gradient-to-r from-purple-400 via-pink-400 to-blue-400 bg-clip-text text-transparent uppercase tracking-widest drop-shadow">
            BLOCKCHAIN
          </span>
        </h1>
        <p className="text-gray-400 text-sm mb-6 text-center max-w-2xl">
          Upload to IPFS, register on-chain with EIP-712, retrieve metadata, and
          verify integrity.
        </p>

        <div className="w-full max-w-3xl">
          {tab === "upload" && <UploadPanel />}
          {tab === "retrieve" && <RetrievePanel />}
          {tab === "verify" && <VerifyPanel />}
        </div>

        <div className="mt-10 text-[11px] text-gray-500 max-w-3xl">
          <div className="font-semibold text-gray-400 mb-2">Notes</div>
          <ul className="list-disc pl-5 space-y-1">
            <li>
              Retrieval shows the <span className="text-gray-300">latest</span>{" "}
              version using the contract’s
              <code className="mx-1">latest(fileId)</code> and{" "}
              <code className="mx-1">versionsCount(fileId)</code>. If your ABI
              exposes a per-index getter, you can extend this screen to list the
              entire history.
            </li>
            <li>
              Verification compares a local/remote file to on-chain metadata:
              SHA-256 digest, size, and URL binding (by checking{" "}
              <code className="mx-1">keccak256(url)</code> equals the stored{" "}
              <code className="mx-1">uriHash</code>).
            </li>
            <li>
              After upload, the IPFS gateway URL is saved in{" "}
              <code className="mx-1">localStorage</code> for convenience under
              <code className="mx-1">fileregistry:urls</code>. You can paste a
              URL manually if needed.
            </li>
            <li>
              EIP-712 signature is validated by the contract during{" "}
              <code className="mx-1">register</code>. If you also store the
              signature on-chain or emit it in an event, you can add off-chain
              signature re-verification here.
            </li>
          </ul>
        </div>
      </main>
    </div>
  );
}
