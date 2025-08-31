import { localhost, sepolia } from "wagmi/chains";
import { useChainId } from "wagmi";

export const CONTRACTS: Record<number, `0x${string}`> = {
  [sepolia.id]: "0x54bA72fe64FdaCDB886ACB6A10E0472e12Bb0C13", // sepolia
};

export const ABI = [
  {
    type: "constructor",
    inputs: [{ name: "admin", type: "address", internalType: "address" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "AUDITOR_ROLE",
    inputs: [],
    outputs: [{ name: "", type: "bytes32", internalType: "bytes32" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "DEFAULT_ADMIN_ROLE",
    inputs: [],
    outputs: [{ name: "", type: "bytes32", internalType: "bytes32" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "UPLOADER_ROLE",
    inputs: [],
    outputs: [{ name: "", type: "bytes32", internalType: "bytes32" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "eip712Domain",
    inputs: [],
    outputs: [
      { name: "fields", type: "bytes1", internalType: "bytes1" },
      { name: "name", type: "string", internalType: "string" },
      { name: "version", type: "string", internalType: "string" },
      { name: "chainId", type: "uint256", internalType: "uint256" },
      {
        name: "verifyingContract",
        type: "address",
        internalType: "address",
      },
      { name: "salt", type: "bytes32", internalType: "bytes32" },
      {
        name: "extensions",
        type: "uint256[]",
        internalType: "uint256[]",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "freeze",
    inputs: [{ name: "fileId", type: "bytes32", internalType: "bytes32" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "getRoleAdmin",
    inputs: [{ name: "role", type: "bytes32", internalType: "bytes32" }],
    outputs: [{ name: "", type: "bytes32", internalType: "bytes32" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "grantRole",
    inputs: [
      { name: "role", type: "bytes32", internalType: "bytes32" },
      { name: "account", type: "address", internalType: "address" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "hasRole",
    inputs: [
      { name: "role", type: "bytes32", internalType: "bytes32" },
      { name: "account", type: "address", internalType: "address" },
    ],
    outputs: [{ name: "", type: "bool", internalType: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "latest",
    inputs: [{ name: "fileId", type: "bytes32", internalType: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        internalType: "struct FileRegistry.Version",
        components: [
          { name: "digest", type: "bytes32", internalType: "bytes32" },
          {
            name: "prevDigest",
            type: "bytes32",
            internalType: "bytes32",
          },
          { name: "uriHash", type: "bytes32", internalType: "bytes32" },
          { name: "size", type: "uint256", internalType: "uint256" },
          {
            name: "fileTimestamp",
            type: "uint64",
            internalType: "uint64",
          },
          { name: "privacyMode", type: "uint8", internalType: "uint8" },
          { name: "signer", type: "address", internalType: "address" },
          { name: "frozen", type: "bool", internalType: "bool" },
        ],
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "nonces",
    inputs: [{ name: "", type: "address", internalType: "address" }],
    outputs: [{ name: "", type: "uint256", internalType: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "register",
    inputs: [
      { name: "fileId", type: "bytes32", internalType: "bytes32" },
      { name: "digest", type: "bytes32", internalType: "bytes32" },
      { name: "uri", type: "string", internalType: "string" },
      { name: "size", type: "uint256", internalType: "uint256" },
      { name: "privacyMode", type: "uint8", internalType: "uint8" },
      { name: "prevDigest", type: "bytes32", internalType: "bytes32" },
      { name: "fileTimestamp", type: "uint64", internalType: "uint64" },
      { name: "deptId", type: "bytes32", internalType: "bytes32" },
      { name: "sig", type: "bytes", internalType: "bytes" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "renounceRole",
    inputs: [
      { name: "role", type: "bytes32", internalType: "bytes32" },
      {
        name: "callerConfirmation",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "revoke",
    inputs: [{ name: "fileId", type: "bytes32", internalType: "bytes32" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "revokeRole",
    inputs: [
      { name: "role", type: "bytes32", internalType: "bytes32" },
      { name: "account", type: "address", internalType: "address" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "revoked",
    inputs: [{ name: "", type: "bytes32", internalType: "bytes32" }],
    outputs: [{ name: "", type: "bool", internalType: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "supportsInterface",
    inputs: [{ name: "interfaceId", type: "bytes4", internalType: "bytes4" }],
    outputs: [{ name: "", type: "bool", internalType: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "versions",
    inputs: [
      { name: "", type: "bytes32", internalType: "bytes32" },
      { name: "", type: "uint256", internalType: "uint256" },
    ],
    outputs: [
      { name: "digest", type: "bytes32", internalType: "bytes32" },
      { name: "prevDigest", type: "bytes32", internalType: "bytes32" },
      { name: "uriHash", type: "bytes32", internalType: "bytes32" },
      { name: "size", type: "uint256", internalType: "uint256" },
      { name: "fileTimestamp", type: "uint64", internalType: "uint64" },
      { name: "privacyMode", type: "uint8", internalType: "uint8" },
      { name: "signer", type: "address", internalType: "address" },
      { name: "frozen", type: "bool", internalType: "bool" },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "versionsCount",
    inputs: [{ name: "fileId", type: "bytes32", internalType: "bytes32" }],
    outputs: [{ name: "", type: "uint256", internalType: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "EIP712DomainChanged",
    inputs: [],
    anonymous: false,
  },
  {
    type: "event",
    name: "FileFrozen",
    inputs: [
      {
        name: "fileId",
        type: "bytes32",
        indexed: true,
        internalType: "bytes32",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "FileRegistered",
    inputs: [
      {
        name: "fileId",
        type: "bytes32",
        indexed: true,
        internalType: "bytes32",
      },
      {
        name: "vIdx",
        type: "uint256",
        indexed: true,
        internalType: "uint256",
      },
      {
        name: "digest",
        type: "bytes32",
        indexed: false,
        internalType: "bytes32",
      },
      {
        name: "uri",
        type: "string",
        indexed: false,
        internalType: "string",
      },
      {
        name: "privacyMode",
        type: "uint8",
        indexed: false,
        internalType: "uint8",
      },
      {
        name: "signer",
        type: "address",
        indexed: false,
        internalType: "address",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "FileRevoked",
    inputs: [
      {
        name: "fileId",
        type: "bytes32",
        indexed: true,
        internalType: "bytes32",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "RoleAdminChanged",
    inputs: [
      {
        name: "role",
        type: "bytes32",
        indexed: true,
        internalType: "bytes32",
      },
      {
        name: "previousAdminRole",
        type: "bytes32",
        indexed: true,
        internalType: "bytes32",
      },
      {
        name: "newAdminRole",
        type: "bytes32",
        indexed: true,
        internalType: "bytes32",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "RoleGranted",
    inputs: [
      {
        name: "role",
        type: "bytes32",
        indexed: true,
        internalType: "bytes32",
      },
      {
        name: "account",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "sender",
        type: "address",
        indexed: true,
        internalType: "address",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "RoleRevoked",
    inputs: [
      {
        name: "role",
        type: "bytes32",
        indexed: true,
        internalType: "bytes32",
      },
      {
        name: "account",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "sender",
        type: "address",
        indexed: true,
        internalType: "address",
      },
    ],
    anonymous: false,
  },
  { type: "error", name: "AccessControlBadConfirmation", inputs: [] },
  {
    type: "error",
    name: "AccessControlUnauthorizedAccount",
    inputs: [
      { name: "account", type: "address", internalType: "address" },
      { name: "neededRole", type: "bytes32", internalType: "bytes32" },
    ],
  },
  { type: "error", name: "ECDSAInvalidSignature", inputs: [] },
  {
    type: "error",
    name: "ECDSAInvalidSignatureLength",
    inputs: [{ name: "length", type: "uint256", internalType: "uint256" }],
  },
  {
    type: "error",
    name: "ECDSAInvalidSignatureS",
    inputs: [{ name: "s", type: "bytes32", internalType: "bytes32" }],
  },
  { type: "error", name: "InvalidShortString", inputs: [] },
  {
    type: "error",
    name: "StringTooLong",
    inputs: [{ name: "str", type: "string", internalType: "string" }],
  },
];
