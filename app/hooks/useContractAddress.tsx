import { useAccount } from "wagmi";
import { localhost, sepolia } from "wagmi/chains";
import { CONTRACTS, ABI } from "../components/contract";

export default function useContractAddress() {
  const { chain } = useAccount();
  const id = chain?.id ?? sepolia.id; // default to sepolia while devving
  const addr = CONTRACTS[id];
  console.log(addr);
  return addr;
}
