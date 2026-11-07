// A live NEAR Intents quote for what comes after settlement: sending the funds
// to any chain. It's a dry quote from the real 1Click API. Testnet tokens can't
// bridge, so this shows the mainnet route without moving anything.

const ONE_CLICK = 'https://1click.chaindefuser.com/v0/quote';
const NEAR_USDC = 'nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1';

export interface Route {
  id: string;
  name: string;
  asset: string;
  /** A valid address format for the quote. Nothing is sent to it. */
  sampleRecipient: string;
}

export const ROUTES: Route[] = [
  { id: 'sol', name: 'Solana', asset: 'nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near', sampleRecipient: 'So11111111111111111111111111111111111111112' },
  { id: 'base', name: 'Base', asset: 'nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near', sampleRecipient: '0x0000000000000000000000000000000000000001' },
  { id: 'arb', name: 'Arbitrum', asset: 'nep141:arb-0xaf88d065e77c8cc2239327c5edb3a432268e5831.omft.near', sampleRecipient: '0x0000000000000000000000000000000000000001' },
  { id: 'eth', name: 'Ethereum', asset: 'nep141:eth-0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.omft.near', sampleRecipient: '0x0000000000000000000000000000000000000001' },
];

export interface Quote {
  amountOut: string;
  seconds: number;
}

export async function quoteRoute(route: Route, amount: string): Promise<Quote> {
  const response = await fetch(ONE_CLICK, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      dry: true,
      swapType: 'EXACT_INPUT',
      slippageTolerance: 100,
      originAsset: NEAR_USDC,
      depositType: 'ORIGIN_CHAIN',
      destinationAsset: route.asset,
      amount,
      refundTo: 'relay.tg',
      refundType: 'ORIGIN_CHAIN',
      recipient: route.sampleRecipient,
      recipientType: 'DESTINATION_CHAIN',
      deadline: new Date(Date.now() + 3_600_000).toISOString(),
    }),
  });
  if (!response.ok) throw new Error(`quote failed (${response.status})`);
  const { quote } = await response.json();
  return { amountOut: quote.amountOutFormatted, seconds: quote.timeEstimate };
}
