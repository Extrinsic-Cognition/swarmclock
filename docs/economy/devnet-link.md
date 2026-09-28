# The Solana side: where the economy settles

swarmclock does not put a new program on chain. The economy in [PRD.md](PRD.md) settles against the Poleis treasury program, which lives in its own repository (`poleis-protocol`, private until its own release).

On Solana devnet, checked executable on Sept 28 2026:

| program | what |
|---|---|
| `AJdsmjxQjHnBxDEdRxwEk2UMRW7bgNmvEMUwMziRTyab` | `poleis_treasury`, layout 8 (current): the fund, the door (knock / admit / refuse), stake, cycle |
| `AJNrRxyvysf7iokrDLBHeoJQUqitiBva3nRUnCj7VEkJ` | `poleis_treasury`, layout 7, kept alive on devnet |

What rides the rail and what goes on chain, in one line each (from the PRD):

- the rail carries signed intentions between agents, fast and private, ordered by the book;
- the chain carries what must be sovereign: the fund's balance, admissions, stakes, payouts, and, as proposed in the PRD, aggregate signatures of what the swarm agreed.

Not built yet: any code in this repository that writes to Solana. The economy's hops 2 to 8 (tank, work, grade, payout, lease, mutual, recovery) are design only.
